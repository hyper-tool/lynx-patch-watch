"""hotfix_dir checker: m2-hotfixes / patches dirs / QUALITY_PATCHES.

Scans for hotfix patches:
- ``m2-hotfixes/*.patch``
- ``patches/`` (composer-patches convention)
- ``.magento.env.yaml`` ``QUALITY_PATCHES`` list

Matching by filename and patch content (CVE or patch id) yields ``declared``.
When the "after" side of the patch diff matches the vendor files (whole-line
anchored), the result is upgraded to ``fixed``.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from lynx_patch_watch.checkers.base import CheckContext, Checker, CheckResult
from lynx_patch_watch.fingerprint import parse_unified_diff, validate_fingerprints
from lynx_patch_watch.matcher import aggregate_content, match_content_hunk_anchored
from lynx_patch_watch.models import ContentFingerprint

_PATCH_ID_RE = re.compile(
    r"(APSB\d{2}-\d{2,4}|CVE-\d{4}-\d{4,}|VULN-\d+|ACSD-\d+|MDVA-\d+)",
    re.IGNORECASE,
)
_QPT_RE = re.compile(r"^\s*-\s*[\"']?([A-Za-z0-9_.\-]+)[\"']?\s*$", re.MULTILINE)


class HotfixDirChecker(Checker):
    name = "hotfix_dir"

    HOTFIX_DIRS = ("m2-hotfixes", "patches")
    ENV_FILE = ".magento.env.yaml"

    # Per-workspace cache of patch files, invalidated by directory mtimes.
    _cache: dict[str, tuple[tuple, list[Path]]] = {}

    def run(self, ctx: CheckContext, item: dict[str, Any], rules: list[Any]) -> list[CheckResult]:
        if ctx.workspace is None:
            return []
        targets = self._match_targets(item)
        if not targets:
            return []

        candidates = self._find_patch_files_cached(ctx.workspace)
        matched: list[dict[str, Any]] = []
        for path in candidates:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = path.relative_to(ctx.workspace).as_posix()
            ids = {m.upper() for m in _PATCH_ID_RE.findall(text)}
            name_ids = {m.upper() for m in _PATCH_ID_RE.findall(path.name)}
            hit = bool(targets & (ids | name_ids))
            if not hit and self._qpt_hit(path, text, targets):
                hit = True
            if not hit:
                continue
            entry = {"path": rel, "ids": sorted(ids | name_ids), "verified": False}
            fingerprints = validate_fingerprints(parse_unified_diff(text))
            if fingerprints and ctx.has_vendor:
                verdicts = [
                    match_content_hunk_anchored(ctx.workspace, fp) for fp in fingerprints
                ]
                agg = aggregate_content(verdicts, fingerprints)
                entry["content_aggregate"] = agg
                if agg == "fixed":
                    entry["verified"] = True
            matched.append(entry)

        if not matched:
            return []
        verified = [m for m in matched if m["verified"]]
        if verified:
            return [
                CheckResult(
                    checker=self.name,
                    outcome="fixed",
                    confidence=0.75,
                    evidence={"patches": matched},
                    detail=f"hotfix patch verified against vendor files: {verified[0]['path']}",
                )
            ]
        return [
            CheckResult(
                checker=self.name,
                outcome="declared",
                confidence=0.4,
                evidence={"patches": matched},
                detail=f"hotfix patch declared but not verified: {matched[0]['path']}",
            )
        ]

    # ------------------------------------------------------------------

    @staticmethod
    def _match_targets(item: dict[str, Any]) -> set[str]:
        targets = set()
        cve = (item.get("cve_id") or "").upper()
        advisory = (item.get("advisory_id") or "").upper()
        if cve:
            targets.add(cve)
        if advisory:
            targets.add(advisory)
        return targets

    def _find_patch_files(self, workspace: Path) -> list[Path]:
        out: list[Path] = []
        for dirname in self.HOTFIX_DIRS:
            directory = workspace / dirname
            if not directory.is_dir():
                continue
            for path in sorted(directory.rglob("*")):
                if path.is_file() and path.suffix.lower() in (".patch", ".diff", ".txt"):
                    out.append(path)
        env_file = workspace / self.ENV_FILE
        if env_file.is_file():
            out.append(env_file)
        # Top-level stray patches (m2-hotfixes convention at repo root).
        for path in sorted(workspace.glob("*.patch")):
            out.append(path)
        return out

    def _find_patch_files_cached(self, workspace: Path) -> list[Path]:
        """Same as _find_patch_files, cached per workspace + directory mtimes.

        The signature covers the workspace root (top-level ``*.patch`` and the
        env file) and every directory under the hotfix dirs, since the patch
        list is built with ``rglob`` and a nested add only bumps its own dir.
        """
        key = str(workspace)
        stamps: list[tuple[str, float]] = [(".", _mtime(workspace))]
        for dirname in self.HOTFIX_DIRS:
            directory = workspace / dirname
            if not directory.is_dir():
                stamps.append((dirname, 0.0))
                continue
            for current, _dirs, _files in os.walk(directory):
                stamps.append((current, _mtime(Path(current))))
        stamps.append((self.ENV_FILE, _mtime(workspace / self.ENV_FILE)))
        sig = tuple(stamps)
        cached = self._cache.get(key)
        if cached is not None and cached[0] == sig:
            return cached[1]
        files = self._find_patch_files(workspace)
        self._cache[key] = (sig, files)
        return files

    @staticmethod
    def _qpt_hit(path: Path, text: str, targets: set[str]) -> bool:
        if path.name != HotfixDirChecker.ENV_FILE:
            return False
        for token in _QPT_RE.findall(text):
            if token.upper() in targets:
                return True
        return False


def _mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0
