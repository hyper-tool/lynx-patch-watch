"""composer.json checker: exact pins + patch declarations.

① An **exact** pin to the fixed version or higher counts as evidence; range
   constraints like ^2.4.7 can at best produce unknown.
② Patch declarations are recognised from:
   - extra.patches / patches-file (cweagans/composer-patches),
   - vaimo/composer-patches extra config,
   - a magento/quality-patches dependency,
   and matched against APSB / CVE / VULN- / ACSD- ids in patch names or in the
   referenced patch files. A match yields ``declared`` (not verified).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from lynx_patch_watch.checkers.base import CheckContext, Checker, CheckResult
from lynx_patch_watch.matcher import version_fixed, version_in_range
from lynx_patch_watch.magento_version import parse_magento_version

_PATCH_ID_RE = re.compile(
    r"(APSB\d{2}-\d{2,4}|CVE-\d{4}-\d{4,}|VULN-\d+|ACSD-\d+|MDVA-\d+|MAGENTO-\d+)",
    re.IGNORECASE,
)
_EXACT_PIN_RE = re.compile(r"^\d+\.\d+\.\d+(?:-p\d+)?$")
_PRODUCT_KEYS = (
    "magento/product-community-edition",
    "magento/product-enterprise-edition",
    "magento/magento2-base",
)


class ComposerJsonChecker(Checker):
    name = "composer_json"

    def run(self, ctx: CheckContext, item: dict[str, Any], rules: list[Any]) -> list[CheckResult]:
        results: list[CheckResult] = []
        packages = self._packages(item)
        if ctx.workspace is not None and packages and not ctx.is_manual:
            composer = _read_json(ctx.workspace / "composer.json")
            requires: dict[str, Any] = {}
            for section in ("require", "require-dev"):
                req = composer.get(section)
                if isinstance(req, dict):
                    requires.update(req)
            for pkg in packages:
                name = pkg.get("name") or ""
                fixed = pkg.get("fixed_version")
                raw = requires.get(name)
                if not isinstance(raw, str) or not fixed:
                    continue
                pinned = raw.strip().lstrip("v")
                if _EXACT_PIN_RE.match(pinned):
                    is_fixed = version_fixed(pinned, fixed)
                    in_range = version_in_range(pinned, pkg.get("affected_versions"))
                    # A constraint that does not apply to this pin only counts
                    # when the pin has already moved past the fix.
                    if in_range is False and not is_fixed:
                        continue
                    if in_range is None and not is_fixed:
                        # Range unknown/uncomparable: a pin below the fix is
                        # not proof of exposure (same rule as composer_lock).
                        results.append(
                            CheckResult(
                                checker=self.name,
                                outcome="unknown",
                                confidence=0.2,
                                evidence={
                                    "package": name,
                                    "composer_json_require": raw,
                                    "affected_versions": pkg.get("affected_versions"),
                                    "fixed_version": fixed,
                                    "meets_fixed_version": is_fixed,
                                    "reason": "affected range could not be compared",
                                },
                                detail=f"composer.json pins {name} to exact {pinned}; affected range inconclusive",
                            )
                        )
                        continue
                    results.append(
                        CheckResult(
                            checker=self.name,
                            outcome="fixed" if is_fixed else "vulnerable",
                            confidence=0.6 if is_fixed else 0.7,
                            evidence={
                                "package": name,
                                "composer_json_require": raw,
                                "fixed_version": fixed,
                                "meets_fixed_version": is_fixed,
                            },
                            detail=(
                                f"composer.json pins {name} to exact {pinned}"
                                + (" (meets fix)" if is_fixed else " (below fix)")
                            ),
                        )
                    )
                else:
                    results.append(
                        CheckResult(
                            checker=self.name,
                            outcome="unknown",
                            confidence=0.1,
                            evidence={
                                "package": name,
                                "composer_json_require": raw,
                                "fixed_version": fixed,
                                "reason": "range constraint is not exact evidence",
                            },
                            detail=f"composer.json constraint {raw!r} for {name} is not an exact pin",
                        )
                    )
        if ctx.workspace is not None:
            decl = self._patch_declarations(ctx.workspace, item)
            if decl is not None:
                results.append(decl)
        return results

    # ------------------------------------------------------------------

    def _patch_declarations(self, workspace: Path, item: dict[str, Any]) -> CheckResult | None:
        composer = _read_json(workspace / "composer.json")
        if not composer:
            return None
        cve = (item.get("cve_id") or "").upper()
        advisory = (item.get("advisory_id") or "").upper()
        targets = {t for t in (cve, advisory) if t}

        requires: dict[str, Any] = {}
        for section in ("require", "require-dev"):
            req = composer.get(section)
            if isinstance(req, dict):
                requires.update(req)
        has_qpt = any("quality-patches" in k.lower() for k in requires)
        extra = composer.get("extra") or {}
        patch_entries: list[dict[str, Any]] = []
        patch_files: list[str] = []

        def _collect(node: Any) -> None:
            if isinstance(node, list):
                for entry in node:
                    if isinstance(entry, dict):
                        _collect(entry)
                    elif isinstance(entry, str):
                        patch_entries.append({"label": entry})
            elif isinstance(node, dict):
                for key, value in node.items():
                    patch_entries.append({"label": str(key)})
                    if isinstance(value, str):
                        patch_entries.append({"label": value})
                    elif isinstance(value, (list, dict)):
                        _collect(value)

        if isinstance(extra, dict):
            for key in ("patches", "magento-patches", "composer-patches", "patches-default"):
                node = extra.get(key)
                if node is not None:
                    _collect(node)
            for key in ("patches-file", "patchFile", "patches_file"):
                value = extra.get(key)
                if isinstance(value, str):
                    patch_files.append(value)
            # vaimo/composer-patches: extra.patches-file or patchesFile list
            vaimo = extra.get("patchesFile") or extra.get("patches-file")
            if isinstance(vaimo, list):
                patch_files.extend(str(v) for v in vaimo)

        if not patch_entries and not patch_files and not has_qpt:
            return None

        matched: list[str] = []
        for entry in patch_entries:
            label = entry["label"]
            ids = {m.upper() for m in _PATCH_ID_RE.findall(label)}
            if targets & ids:
                matched.append(label[:200])
        for rel in patch_files:
            path = workspace / rel
            if not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            ids = {m.upper() for m in _PATCH_ID_RE.findall(text)}
            if targets & ids:
                matched.append(f"patch file {rel}")
                break
        if has_qpt and not matched:
            matched.append("magento/quality-patches dependency present (QPT tool)")

        if matched:
            return CheckResult(
                checker=self.name,
                outcome="declared",
                confidence=0.4,
                evidence={"matches": matched},
                detail=f"patch declaration matches {', '.join(sorted(targets))}",
            )
        return CheckResult(
            checker=self.name,
            outcome="unknown",
            confidence=0.1,
            evidence={"reason": "patch tooling present but no matching declaration"},
            detail="patch declarations found but none match this advisory",
        )


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return {}
    return data if isinstance(data, dict) else {}
