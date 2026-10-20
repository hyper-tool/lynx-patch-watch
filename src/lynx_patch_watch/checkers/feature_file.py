"""feature_file checker: content fingerprints and rule-based file conditions.

Sources of file-level evidence:
1. advisory item fingerprints (parsed from patch diffs at ingest time);
2. rule checks: {path|glob} + contains / not_contains / regex / sha256.

Matching uses whole-line anchoring (matcher.match_content_hunk_anchored) so a
fixed file that legitimately keeps some before lines is not misjudged.
"""

from __future__ import annotations

import fnmatch
import hashlib
import re
from pathlib import Path
from typing import Any

from lynx_patch_watch.checkers.base import CheckContext, Checker, CheckResult
from lynx_patch_watch.matcher import aggregate_content, match_content_hunk_anchored
from lynx_patch_watch.models import ContentFingerprint


class FeatureFileChecker(Checker):
    name = "feature_file"

    def run(self, ctx: CheckContext, item: dict[str, Any], rules: list[Any]) -> list[CheckResult]:
        if ctx.workspace is None:
            return []
        results: list[CheckResult] = []

        # 1) advisory fingerprints
        fingerprints = [
            ContentFingerprint.model_validate(fp)
            for fp in (item.get("fingerprints") or [])
            if isinstance(fp, dict) and fp.get("path") and (fp.get("before") or fp.get("after"))
        ]
        if fingerprints:
            verdicts = [match_content_hunk_anchored(ctx.workspace, fp) for fp in fingerprints]
            agg = aggregate_content(verdicts, fingerprints)
            outcome = {
                "fixed": "fixed",
                "vulnerable": "vulnerable",
                "no_fingerprints": "unknown",
            }.get(agg, "unknown")
            results.append(
                CheckResult(
                    checker=self.name,
                    outcome=outcome,
                    confidence=0.8 if outcome in ("fixed", "vulnerable") else 0.2,
                    evidence={
                        "content": [v.model_dump() for v in verdicts],
                        "aggregate": agg,
                    },
                    detail=f"fingerprint content match: {agg}",
                )
            )

        # 2) rule checks
        for rule in rules or []:
            for check in getattr(rule, "checks", []) or []:
                if not isinstance(check, dict):
                    continue
                if "path" not in check and "glob" not in check:
                    continue
                results.extend(self._run_rule_check(ctx, check, rule))
        return results

    def _run_rule_check(self, ctx: CheckContext, check: dict[str, Any], rule: Any) -> list[CheckResult]:
        assert ctx.workspace is not None
        pattern = check.get("path") or check.get("glob")
        targets: list[Path] = []
        if "*" in pattern or "?" in pattern:
            targets = sorted(ctx.workspace.glob(pattern))
        else:
            candidate = ctx.workspace / pattern
            if candidate.is_file():
                targets = [candidate]
        if not targets:
            return [
                CheckResult(
                    checker=self.name,
                    outcome="unknown",
                    confidence=0.2,
                    evidence={"rule": getattr(rule, "id", "?"), "pattern": pattern, "reason": "no files matched"},
                    detail=f"no file matches {pattern}",
                )
            ]

        conditions: list[tuple[str, Any]] = []
        for key in ("contains", "not_contains", "regex", "sha256"):
            if key in check:
                conditions.append((key, check[key]))
        if not conditions:
            return []

        verdict_on_match = getattr(rule, "verdict_on_match", "fixed") or "fixed"
        per_file: list[dict[str, Any]] = []
        all_match = True
        for path in targets:
            rel = path.relative_to(ctx.workspace).as_posix()
            try:
                if "sha256" in check:
                    digest = hashlib.sha256(path.read_bytes()).hexdigest()
                    ok = digest.lower() == str(check["sha256"]).lower()
                    detail = f"sha256 {digest[:12]}… vs {check['sha256']}"
                else:
                    text = path.read_text(encoding="utf-8", errors="replace")
                    ok = True
                    notes = []
                    for key, expected in conditions:
                        if key == "contains":
                            hit = str(expected) in text
                            notes.append(f"contains {expected!r}: {hit}")
                            ok = ok and hit
                        elif key == "not_contains":
                            hit = str(expected) not in text
                            notes.append(f"not_contains {expected!r}: {hit}")
                            ok = ok and hit
                        elif key == "regex":
                            hit = bool(re.search(str(expected), text))
                            notes.append(f"regex {expected!r}: {hit}")
                            ok = ok and hit
                    detail = "; ".join(notes)
            except OSError as exc:
                ok = False
                detail = f"read error: {exc}"
            per_file.append({"path": rel, "match": ok, "detail": detail})
            all_match = all_match and ok

        outcome = verdict_on_match if all_match else _opposite(verdict_on_match)
        return [
            CheckResult(
                checker=self.name,
                outcome=outcome,
                confidence=0.75 if all_match else 0.5,
                evidence={
                    "rule": getattr(rule, "id", "?"),
                    "pattern": pattern,
                    "files": per_file,
                    "verdict_on_match": verdict_on_match,
                },
                detail=f"rule {getattr(rule, 'id', '?')} file conditions "
                + ("all matched" if all_match else "did not all match"),
            )
        ]


def _opposite(verdict: str) -> str:
    if verdict == "fixed":
        return "vulnerable"
    if verdict == "vulnerable":
        return "fixed"
    return "unknown"
