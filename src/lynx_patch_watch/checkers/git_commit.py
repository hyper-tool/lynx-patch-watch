"""git_commit checker — three modes:

(a) project repo: rules write ``commits: [sha]`` (checked with
    ``git merge-base --is-ancestor``) or ``message_grep`` (``git log --grep -E``);
(b) upstream fix: rules write ``upstream: {sha | patch_url}``; the .patch is
    downloaded (cached under patch_cache_dir), fingerprinted, path-mapped to the
    vendor layout and judged by feature_file semantics;
(c) tag/branch version: only a version source (low confidence) — handled by
    detect/, not here.

Per the plan's risk note, upstream mode only fires when a rule explicitly
names a sha or patch URL; no automatic discovery.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any

from lynx_patch_watch.adapters.magento.paths import map_upstream_path
from lynx_patch_watch.checkers.base import CheckContext, Checker, CheckResult
from lynx_patch_watch.fingerprint import parse_unified_diff, validate_fingerprints
from lynx_patch_watch.http_fetch import fetch_text
from lynx_patch_watch.matcher import aggregate_content, match_content_hunk_anchored
from lynx_patch_watch.models import ContentFingerprint

logger = logging.getLogger(__name__)


class GitCommitChecker(Checker):
    name = "git_commit"

    def run(self, ctx: CheckContext, item: dict[str, Any], rules: list[Any]) -> list[CheckResult]:
        results: list[CheckResult] = []
        for rule in rules or []:
            checks = getattr(rule, "checks", []) or []
            if not isinstance(checks, list):
                continue
            for check in checks:
                if not isinstance(check, dict):
                    continue
                if "commits" in check or "message_grep" in check:
                    result = self._project_repo(ctx, check, rule)
                    if result:
                        results.append(result)
                elif "upstream" in check:
                    result = self._upstream(ctx, check, rule)
                    if result:
                        results.append(result)
        return results

    # ------------------------------------------------------------------

    def _project_repo(self, ctx: CheckContext, check: dict[str, Any], rule: Any) -> CheckResult | None:
        if ctx.git is None or ctx.workspace is None:
            return None
        shas = [str(s) for s in (check.get("commits") or [])]
        grep = check.get("message_grep")
        evidence: dict[str, Any] = {"rule": getattr(rule, "id", "?")}
        if shas:
            found = []
            for sha in shas:
                is_ancestor = ctx.git.is_ancestor(ctx.workspace, sha)
                evidence[f"commit:{sha}"] = is_ancestor
                if is_ancestor:
                    found.append(sha)
            if found:
                return CheckResult(
                    checker=self.name,
                    outcome="fixed",
                    confidence=0.85,
                    evidence=evidence,
                    detail=f"fix commit(s) {', '.join(found)} are ancestors of HEAD",
                )
            return CheckResult(
                checker=self.name,
                outcome="unknown",
                confidence=0.3,
                evidence=evidence,
                detail="none of the fix commits are ancestors of HEAD",
            )
        if grep:
            hits = ctx.git.log_grep(ctx.workspace, str(grep))
            evidence["message_grep"] = str(grep)
            evidence["hits"] = hits
            if hits:
                return CheckResult(
                    checker=self.name,
                    outcome="fixed",
                    confidence=0.7,
                    evidence=evidence,
                    detail=f"commit message match: {grep!r} ({len(hits)} hit(s))",
                )
            return CheckResult(
                checker=self.name,
                outcome="unknown",
                confidence=0.3,
                evidence=evidence,
                detail=f"no commit message matches {grep!r}",
            )
        return None

    def _upstream(self, ctx: CheckContext, check: dict[str, Any], rule: Any) -> CheckResult | None:
        if ctx.workspace is None or not ctx.has_vendor:
            return None
        upstream = check.get("upstream") or {}
        if not isinstance(upstream, dict):
            return None
        patch_text = self._load_patch(ctx, upstream)
        if not patch_text:
            return CheckResult(
                checker=self.name,
                outcome="unknown",
                confidence=0.1,
                evidence={"rule": getattr(rule, "id", "?"), "reason": "patch unavailable"},
                detail="upstream patch could not be fetched",
            )
        fingerprints = validate_fingerprints(parse_unified_diff(patch_text))
        mapped: list[ContentFingerprint] = []
        for fp in fingerprints:
            target = map_upstream_path(fp.path)
            if target is None:
                continue
            mapped.append(
                ContentFingerprint(
                    path=target,
                    before=fp.before,
                    after=fp.after,
                    hunk_id=fp.hunk_id,
                    critical=fp.critical,
                )
            )
        if not mapped:
            return CheckResult(
                checker=self.name,
                outcome="unknown",
                confidence=0.1,
                evidence={"rule": getattr(rule, "id", "?"), "reason": "no mappable paths"},
                detail="upstream patch has no vendor-mappable paths",
            )
        verdicts = [match_content_hunk_anchored(ctx.workspace, fp) for fp in mapped]
        agg = aggregate_content(verdicts, mapped)
        outcome = {"fixed": "fixed", "vulnerable": "vulnerable"}.get(agg, "unknown")
        return CheckResult(
            checker=self.name,
            outcome=outcome,
            confidence=0.7 if outcome != "unknown" else 0.2,
            evidence={
                "rule": getattr(rule, "id", "?"),
                "upstream": {k: v for k, v in upstream.items() if k != "headers"},
                "content": [v.model_dump() for v in verdicts],
                "aggregate": agg,
            },
            detail=f"upstream patch content match: {agg}",
        )

    def _load_patch(self, ctx: CheckContext, upstream: dict[str, Any]) -> str | None:
        patch_url = upstream.get("patch_url")
        sha = upstream.get("sha")
        if patch_url:
            cache_dir = ctx.patch_cache_dir or (Path(".tmp") / "patch-cache")
            try:
                cache_dir.mkdir(parents=True, exist_ok=True)
            except OSError:
                cache_dir = None
            cache_key = hashlib.sha256(str(patch_url).encode()).hexdigest()[:16]
            if cache_dir is not None:
                cached = cache_dir / f"{cache_key}.patch"
                if cached.is_file():
                    return cached.read_text(encoding="utf-8", errors="replace")
            try:
                fetched = fetch_text(str(patch_url), timeout=60.0)
            except Exception as exc:  # noqa: BLE001
                logger.warning("upstream patch fetch failed %s: %s", patch_url, exc)
                return None
            if fetched.status_code >= 400 or not fetched.text.strip():
                return None
            if cache_dir is not None:
                try:
                    (cache_dir / f"{cache_key}.patch").write_text(fetched.text, encoding="utf-8")
                except OSError:
                    pass
            return fetched.text
        if sha and ctx.git is not None and ctx.workspace is not None:
            # Try to materialise the commit as a patch from the project repo.
            try:
                proc = ctx.git._run(
                    ["git", "show", "--format=", str(sha)], cwd=ctx.workspace
                )
                return proc.stdout
            except Exception:  # noqa: BLE001
                return None
        return None
