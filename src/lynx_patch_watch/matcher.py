"""Version + content matching primitives.

Ported from msw ``matcher.py``: ``version_in_range``, ``version_fixed``,
``magento_lte/gte`` (re-exported from magento_version), ``match_content_hunk``,
``aggregate_content``, ``evaluate_packages`` and ``match_risk_item``, together
with the model dependencies. msw: src/magento_security_watcher/matcher.py

Note: msw's ``match_content_hunk`` does substring matching, which misjudges
when a fixed snippet still contains the before snippet. lpw keeps the ported
function for behavioural compatibility and adds
``match_content_hunk_anchored`` (whole-line anchored) used by the feature_file
checker.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version
from packaging.specifiers import InvalidSpecifier, SpecifierSet

from lynx_patch_watch.magento_version import (
    magento_gte,
    magento_lte,
    newer_release_line,
    parse_magento_version,
)
from lynx_patch_watch.models import (
    ContentFingerprint,
    FindingEvidence,
    FindingRecord,
    FixMethod,
    HunkVerdict,
    PackageConstraint,
    RemediationOffer,
    RemediationStatus,
    RiskItemAnalysis,
)

__all__ = [
    "version_in_range",
    "version_fixed",
    "match_content_hunk",
    "match_content_hunk_anchored",
    "aggregate_content",
    "evaluate_packages",
    "match_risk_item",
    "magento_gte",
    "magento_lte",
    "newer_release_line",
    "parse_magento_version",
]

_AND_EARLIER_RE = re.compile(
    r"(?P<ver>2\.\d+\.\d+(?:-(?:p\d+|\d{4}-[a-z]{3}))?)\s+and\s+earlier",
    re.I,
)
_BARE_MAGENTO_VER_RE = re.compile(
    r"^2\.\d+\.\d+(?:-(?:p\d+|\d{4}-[a-z]{3}))?$",
    re.I,
)


def _parse_version(value: str) -> Version | None:
    try:
        return Version(value)
    except InvalidVersion:
        base = value.split("-")[0]
        try:
            return Version(base)
        except InvalidVersion:
            return None


def _magento_eq(current: str, target: str) -> bool | None:
    cur = parse_magento_version(current)
    tgt = parse_magento_version(target)
    if cur is None or tgt is None:
        return None
    return cur.core == tgt.core and cur.patch == tgt.patch and cur.rank == tgt.rank


def version_in_range(current: str, affected: str | None) -> bool | None:
    """True if current is in affected range. Supports Magento specs like '<=2.4.8-p5'."""
    if not affected:
        return None
    affected = affected.strip()
    # Natural-language leftover from incomplete ingest.
    m = _AND_EARLIER_RE.search(affected)
    if m and "," not in affected:
        return magento_lte(current, m.group("ver"))

    # Magento-aware simple single-clause specs (no commas).
    if "," not in affected:
        if affected.startswith("<="):
            return magento_lte(current, affected[2:].strip())
        if affected.startswith("=="):
            return _magento_eq(current, affected[2:].strip())
        if affected.startswith("<") and not affected.startswith("<="):
            upper = affected[1:].strip()
            le = magento_lte(current, upper)
            eq_cur = parse_magento_version(current)
            eq_up = parse_magento_version(upper)
            if le is None or eq_cur is None or eq_up is None:
                return None
            return le and not (eq_cur == eq_up)
        if affected.startswith(">="):
            return magento_gte(current, affected[2:].strip())
        # Bare Magento version → that exact release token only.
        if _BARE_MAGENTO_VER_RE.match(affected):
            return _magento_eq(current, affected)

    # Continuous PEP 440 ranges (fixtures): >=2.4.0,<2.4.6 means all cores below 2.4.6.
    try:
        spec = SpecifierSet(affected, prereleases=True)
    except InvalidSpecifier:
        return None
    ver = _parse_version(current)
    if ver is None:
        return None
    try:
        return ver in spec
    except Exception:  # noqa: BLE001
        return None


def version_fixed(current: str, fixed: str | None) -> bool | None:
    if not fixed:
        return None
    # Prefer Magento-aware compare (handles -pN and -YYYY-mon)
    cur = parse_magento_version(current)
    fx = parse_magento_version(fixed)
    if cur is not None and fx is not None:
        # Same release line: patch/hotfix ordering.
        if cur.core == fx.core:
            return cur >= fx
        # Newer Magento line than the listed fix → already past that bulletin line.
        if cur.core > fx.core:
            return True
        return False
    cur_v = _parse_version(current)
    fix_v = _parse_version(fixed)
    if cur_v is None or fix_v is None:
        return None
    return cur_v >= fix_v


def match_content_hunk(workspace: Path, fp: ContentFingerprint) -> HunkVerdict:
    """Substring before/after matching (ported from msw)."""
    file_path = workspace / fp.path
    if not file_path.is_file():
        return HunkVerdict(
            path=fp.path,
            hunk_id=fp.hunk_id,
            result="unknown",
            detail=f"file missing: {fp.path}",
        )
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return HunkVerdict(
            path=fp.path,
            hunk_id=fp.hunk_id,
            result="unknown",
            detail=f"read error: {exc}",
        )

    has_before = bool(fp.before and fp.before in text)
    has_after = bool(fp.after and fp.after in text)

    if has_after and not has_before:
        return HunkVerdict(path=fp.path, hunk_id=fp.hunk_id, result="fixed", detail="after present, before absent")
    if has_after and has_before:
        # unusual; treat as unknown (partial / duplicated)
        return HunkVerdict(
            path=fp.path,
            hunk_id=fp.hunk_id,
            result="unknown",
            detail="both before and after snippets present",
        )
    if has_before and not has_after:
        return HunkVerdict(path=fp.path, hunk_id=fp.hunk_id, result="vulnerable", detail="before present, after absent")
    return HunkVerdict(
        path=fp.path,
        hunk_id=fp.hunk_id,
        result="unknown",
        detail="neither before nor after snippet matched",
    )


def _line_present(text: str, snippet: str) -> bool:
    """Whole-line anchored containment: every snippet line must appear as a
    complete stripped line in the file. Avoids the msw false-positive where a
    fixed snippet still contains the vulnerable snippet as a substring."""
    lines = {ln.strip() for ln in text.splitlines()}
    for snippet_line in snippet.splitlines():
        s = snippet_line.strip()
        if not s:
            continue
        if s not in lines:
            return False
    return True


def match_content_hunk_anchored(workspace: Path, fp: ContentFingerprint) -> HunkVerdict:
    """Whole-line anchored before/after matching (lpw improvement).

    ``vulnerable`` requires the before snippet to be present as complete lines
    AND the after snippet to be absent; ``fixed`` requires the after snippet
    present as complete lines AND the before snippet absent. When both are
    present (fixed file that legitimately keeps some before lines) we look at
    per-line evidence: the fix wins only if the before-only lines are gone.
    """
    file_path = workspace / fp.path
    if not file_path.is_file():
        return HunkVerdict(
            path=fp.path,
            hunk_id=fp.hunk_id,
            result="unknown",
            detail=f"file missing: {fp.path}",
        )
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return HunkVerdict(
            path=fp.path,
            hunk_id=fp.hunk_id,
            result="unknown",
            detail=f"read error: {exc}",
        )

    lines = {ln.strip() for ln in text.splitlines() if ln.strip()}

    before_lines = [ln.strip() for ln in (fp.before or "").splitlines() if ln.strip()]
    after_lines = [ln.strip() for ln in (fp.after or "").splitlines() if ln.strip()]

    before_present = all(ln in lines for ln in before_lines) if before_lines else False
    after_present = all(ln in lines for ln in after_lines) if after_lines else False

    if after_lines and after_present and (not before_lines or not before_present):
        return HunkVerdict(
            path=fp.path, hunk_id=fp.hunk_id, result="fixed", detail="after lines present, before lines absent"
        )
    if before_lines and before_present and (not after_lines or not after_present):
        return HunkVerdict(
            path=fp.path, hunk_id=fp.hunk_id, result="vulnerable", detail="before lines present, after lines absent"
        )
    if before_lines and after_lines and before_present and after_present:
        # Both present as complete lines: compare per-line coverage. The fix is
        # only proven when every before-only line is gone.
        after_set = set(after_lines)
        before_only = [ln for ln in before_lines if ln not in after_set]
        if before_only and all(ln not in lines for ln in before_only):
            return HunkVerdict(
                path=fp.path,
                hunk_id=fp.hunk_id,
                result="fixed",
                detail="before-only lines absent; after lines present",
            )
        return HunkVerdict(
            path=fp.path,
            hunk_id=fp.hunk_id,
            result="unknown",
            detail="both before and after lines present",
        )
    return HunkVerdict(
        path=fp.path,
        hunk_id=fp.hunk_id,
        result="unknown",
        detail="neither before nor after lines matched",
    )


def aggregate_content(verdicts: list[HunkVerdict], fingerprints: list[ContentFingerprint]) -> str:
    """Return fixed | vulnerable | unknown for content layer."""
    if not fingerprints:
        return "no_fingerprints"
    critical_ids = {fp.hunk_id or fp.path for fp in fingerprints if fp.critical}
    by_key = {v.hunk_id or v.path: v for v in verdicts}
    relevant = [by_key.get(k) for k in critical_ids]
    relevant = [v for v in relevant if v is not None]
    if not relevant:
        return "unknown"
    if any(v.result == "vulnerable" for v in relevant):
        return "vulnerable"
    if any(v.result == "unknown" for v in relevant):
        return "unknown"
    if all(v.result == "fixed" for v in relevant):
        return "fixed"
    return "unknown"


def evaluate_packages(
    installed: dict[str, str],
    packages: list[PackageConstraint],
) -> dict[str, Any]:
    """Return version-layer summary."""
    if not packages:
        return {"applicable": None, "fixed_by_version": False, "details": []}

    details: list[dict[str, Any]] = []
    any_applicable = False
    all_fixed = True
    saw_package = False

    for pkg in packages:
        current = installed.get(pkg.name)
        detail: dict[str, Any] = {
            "name": pkg.name,
            "current": current,
            "affected_versions": pkg.affected_versions,
            "fixed_version": pkg.fixed_version,
        }
        if current is None:
            detail["status"] = "package_not_found"
            details.append(detail)
            continue
        saw_package = True
        in_range = version_in_range(current, pkg.affected_versions)
        is_fixed = version_fixed(current, pkg.fixed_version)
        detail["in_affected_range"] = in_range
        detail["meets_fixed_version"] = is_fixed
        newer = (
            newer_release_line(current, pkg.fixed_version)
            if pkg.fixed_version
            else None
        )
        # Newer Magento core than this constraint's fix line → bulletin line N/A.
        if newer is True:
            detail["status"] = "not_in_affected_range"
        elif in_range is True:
            if is_fixed is True:
                detail["status"] = "fixed_by_version"
            else:
                detail["status"] = "affected"
                any_applicable = True
                all_fixed = False
        elif is_fixed is True:
            # e.g. affected <2.4.6 and installed == 2.4.6 (out of range but meets fix)
            detail["status"] = "fixed_by_version"
        elif in_range is False:
            detail["status"] = "not_in_affected_range"
        elif pkg.affected_versions:
            token = None
            am = _AND_EARLIER_RE.search(pkg.affected_versions)
            if am:
                token = am.group("ver")
            else:
                stripped = pkg.affected_versions.strip().lstrip("<>=!~^")
                first = stripped.split(",")[0].strip()
                if parse_magento_version(first):
                    token = first
            if token and newer_release_line(current, token) is True:
                detail["status"] = "not_in_affected_range"
            else:
                detail["status"] = "unknown_version_compare"
                all_fixed = False
        else:
            # Unknown compare must NOT count as confirmed affected (avoids false vulnerable).
            detail["status"] = "unknown_version_compare"
            all_fixed = False
        details.append(detail)

    if not saw_package:
        return {"applicable": False, "fixed_by_version": False, "details": details}

    if any_applicable and all_fixed:
        # shouldn't happen
        pass

    fixed_by_version = saw_package and all(
        d.get("status") in {"fixed_by_version", "not_in_affected_range", "package_not_found"}
        for d in details
        if d.get("current") is not None
    ) and any(d.get("status") == "fixed_by_version" for d in details)

    # Only confirmed "affected" makes the risk applicable/vulnerable.
    applicable = any(d.get("status") == "affected" for d in details)
    if any(d.get("status") == "fixed_by_version" for d in details) and not applicable:
        applicable = True  # was in product line; now fixed
        fixed_by_version = True

    # If all installed packages are not_in_affected_range and none fixed_by_version explicitly
    if not applicable and not any(d.get("status") == "fixed_by_version" for d in details):
        if all(
            d.get("status") in {"not_in_affected_range", "package_not_found"}
            for d in details
        ):
            return {"applicable": False, "fixed_by_version": False, "details": details}

    if any(d.get("status") == "fixed_by_version" for d in details) and not any(
        d.get("status") == "affected" for d in details
    ):
        return {"applicable": True, "fixed_by_version": True, "details": details}

    return {
        "applicable": applicable if applicable else None,
        "fixed_by_version": bool(fixed_by_version),
        "details": details,
    }


def match_risk_item(
    *,
    project_id: str,
    workspace: Path,
    installed: dict[str, str],
    analysis: RiskItemAnalysis,
    risk_id: str,
) -> FindingRecord:
    evidence = FindingEvidence()
    version_info = evaluate_packages(installed, analysis.packages)
    evidence.version = version_info

    content_verdicts = [match_content_hunk(workspace, fp) for fp in analysis.fingerprints]
    evidence.content = content_verdicts
    content_agg = aggregate_content(content_verdicts, analysis.fingerprints)

    status: RemediationStatus
    fix_method: FixMethod = FixMethod.NONE

    applicable = version_info.get("applicable")
    fixed_by_version = bool(version_info.get("fixed_by_version"))

    if applicable is False:
        status = RemediationStatus.NOT_APPLICABLE
        fix_method = FixMethod.NONE
    elif fixed_by_version:
        status = RemediationStatus.FIXED
        fix_method = FixMethod.UPGRADE
        if content_agg == "vulnerable":
            evidence.warnings.append("version says fixed but content still matches before-snippet")
        if content_agg == "fixed":
            fix_method = FixMethod.UPGRADE_AND_PATCH
    else:
        # version still affected or unknown
        offer = analysis.remediation_offer
        if content_agg == "fixed":
            status = RemediationStatus.FIXED
            fix_method = FixMethod.PATCH_CONTENT
        elif content_agg == "vulnerable":
            status = RemediationStatus.VULNERABLE
            fix_method = FixMethod.NONE
        elif content_agg == "no_fingerprints":
            if offer == RemediationOffer.UPGRADE_ONLY or offer == RemediationOffer.UPGRADE_OR_PATCH:
                # affected by version, no patch evidence
                if applicable is True or any(
                    d.get("status") == "affected" for d in version_info.get("details", [])
                ):
                    status = RemediationStatus.VULNERABLE
                elif applicable is None and not analysis.packages:
                    status = RemediationStatus.UNKNOWN
                else:
                    status = RemediationStatus.UNKNOWN
            elif offer == RemediationOffer.PATCH_ONLY:
                status = RemediationStatus.UNKNOWN
                evidence.warnings.append("patch-only risk but no fingerprints available")
            else:
                status = RemediationStatus.UNKNOWN
            fix_method = FixMethod.UNKNOWN if status == RemediationStatus.UNKNOWN else FixMethod.NONE
        else:
            status = RemediationStatus.UNKNOWN
            fix_method = FixMethod.UNKNOWN

    finding = FindingRecord(
        project_id=project_id,
        risk_id=risk_id,
        remediation_status=status,
        fix_method=fix_method,
        evidence=evidence,
        analysis_snapshot=analysis,
    )
    finding.evidence_fingerprint = _evidence_fingerprint(finding)
    return finding


def _evidence_fingerprint(finding: FindingRecord) -> str:
    raw = (
        f"{finding.remediation_status.value}|{finding.fix_method.value}|"
        f"{finding.evidence.model_dump_json()}"
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]
