"""composer.lock version checker.

Compares each affected package constraint (from the advisory item) against the
installed versions recorded in composer.lock / composer.json, reusing msw's
version_in_range / version_fixed (which understand -pN and -YYYY-mon).
"""

from __future__ import annotations

from typing import Any

from lynx_patch_watch.checkers.base import CheckContext, Checker, CheckResult
from lynx_patch_watch.matcher import newer_release_line, version_fixed, version_in_range
from lynx_patch_watch.models import PackageConstraint


class ComposerLockChecker(Checker):
    name = "composer_lock"

    def run(self, ctx: CheckContext, item: dict[str, Any], rules: list[Any]) -> list[CheckResult]:
        packages = self._packages(item)
        if not packages:
            return []
        installed = ctx.installed or {}
        if not installed:
            return [
                CheckResult(
                    checker=self.name,
                    outcome="unknown",
                    confidence=0.0,
                    evidence={"reason": "no installed packages resolved"},
                    detail="no composer.lock / composer.json packages found",
                )
            ]

        # Manual projects only carry a declared version: same comparison, low
        # confidence (the verdict merger marks these decided_by=declared).
        manual = ctx.is_manual
        conf_scale = 0.5 if manual else 1.0
        note = "declared version (manual project)" if manual else None

        details: list[dict[str, Any]] = []
        any_affected = False
        all_fixed = True
        saw_package = False
        for pkg in packages:
            name = pkg.get("name") or ""
            current = installed.get(name)
            affected = pkg.get("affected_versions")
            fixed = pkg.get("fixed_version")
            detail: dict[str, Any] = {
                "name": name,
                "current": current,
                "affected_versions": affected,
                "fixed_version": fixed,
            }
            if current is None:
                detail["status"] = "package_not_found"
                details.append(detail)
                continue
            saw_package = True
            in_range = version_in_range(current, affected)
            is_fixed = version_fixed(current, fixed)
            detail["in_affected_range"] = in_range
            detail["meets_fixed_version"] = is_fixed
            newer = newer_release_line(current, fixed) if fixed else None
            if newer is True:
                # Newer Magento core than this constraint's fix line → N/A.
                detail["status"] = "not_in_affected_range"
            elif in_range is True and is_fixed is not True:
                detail["status"] = "affected"
                any_affected = True
                all_fixed = False
            elif is_fixed is True:
                detail["status"] = "fixed_by_version"
            elif in_range is False:
                detail["status"] = "not_in_affected_range"
            else:
                detail["status"] = "unknown_version_compare"
                all_fixed = False
            details.append(detail)

        if not saw_package:
            return [
                CheckResult(
                    checker=self.name,
                    outcome="not_applicable",
                    confidence=0.6,
                    evidence={"details": details},
                    detail="none of the affected packages are installed",
                )
            ]
        statuses = [d["status"] for d in details]
        if any(s == "affected" for s in statuses):
            return [
                CheckResult(
                    checker=self.name,
                    outcome="vulnerable",
                    confidence=0.9 * conf_scale,
                    evidence={"details": details},
                    detail=note or "installed version is inside the affected range",
                )
            ]
        if any(s == "fixed_by_version" for s in statuses):
            return [
                CheckResult(
                    checker=self.name,
                    outcome="fixed",
                    confidence=0.9 * conf_scale,
                    evidence={"details": details},
                    detail=note or "installed versions meet the fixed version",
                )
            ]
        if all(s in ("not_in_affected_range", "package_not_found") for s in statuses):
            return [
                CheckResult(
                    checker=self.name,
                    outcome="not_applicable",
                    confidence=0.7 * conf_scale,
                    evidence={"details": details},
                    detail="all affected packages are outside the affected range (newer release line or not installed)",
                )
            ]
        return [
            CheckResult(
                checker=self.name,
                outcome="unknown",
                confidence=0.3 * conf_scale,
                evidence={"details": details},
                detail=note or "version comparison inconclusive",
            )
        ]
