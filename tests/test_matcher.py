"""Ported from msw tests: test_matcher.py (content-hunk parts) and
test_inventory_version.py (version compare parts). msw origin noted inline."""

from __future__ import annotations

from pathlib import Path

import pytest

from lynx_patch_watch.matcher import (
    aggregate_content,
    match_content_hunk,
    match_content_hunk_anchored,
    match_risk_item,
    version_fixed,
    version_in_range,
)
from lynx_patch_watch.models import (
    ContentFingerprint,
    PackageConstraint,
    RemediationOffer,
    RiskItemAnalysis,
    Severity,
)


# --- ported from msw tests/test_matcher.py ---


def test_content_hunk_fixed(tmp_path: Path):
    rel = Path("vendor/magento/module-customer/Model/AccountManagement.php")
    target = tmp_path / rel
    target.parent.mkdir(parents=True)
    target.write_text(
        "if ($user->isAllowed() && $this->csrfValidator->validate($request)) {\n",
        encoding="utf-8",
    )
    fp = ContentFingerprint(
        path=str(rel),
        before="if ($user->isAllowed()) {",
        after="if ($user->isAllowed() && $this->csrfValidator->validate($request)) {",
    )
    verdict = match_content_hunk(tmp_path, fp)
    assert verdict.result == "fixed"


def test_content_hunk_vulnerable(tmp_path: Path):
    rel = Path("vendor/magento/module-customer/Model/AccountManagement.php")
    target = tmp_path / rel
    target.parent.mkdir(parents=True)
    target.write_text("if ($user->isAllowed()) {\n", encoding="utf-8")
    fp = ContentFingerprint(
        path=str(rel),
        before="if ($user->isAllowed()) {",
        after="if ($user->isAllowed() && $this->csrfValidator->validate($request)) {",
    )
    assert match_content_hunk(tmp_path, fp).result == "vulnerable"


def test_content_hunk_anchored_avoids_substring_false_positive(tmp_path: Path):
    """msw's substring match reports 'unknown' when the fixed line still contains
    the before snippet as a substring; anchored matching correctly says fixed."""
    rel = Path("vendor/magento/module-customer/Model/AccountManagement.php")
    target = tmp_path / rel
    target.parent.mkdir(parents=True)
    # The fix extends the old condition; the old text survives as a substring
    # inside the new line but not as a complete line.
    target.write_text(
        "if ($user->isAllowed() && $this->csrfValidator->validate($request)) {\n"
        "    return true;\n"
        "}\n",
        encoding="utf-8",
    )
    fp = ContentFingerprint(
        path=str(rel),
        before="if ($user->isAllowed()",
        after="if ($user->isAllowed() && $this->csrfValidator->validate($request)) {",
    )
    assert match_content_hunk(tmp_path, fp).result == "unknown"  # msw behaviour
    assert match_content_hunk_anchored(tmp_path, fp).result == "fixed"  # lpw behaviour


def test_aggregate_content():
    fps = [ContentFingerprint(path="a.php", before="x", after="y", hunk_id="a.php#0")]
    verdicts = [match_content_hunk.__wrapped__ if False else None]  # placeholder
    from lynx_patch_watch.models import HunkVerdict

    fixed = [HunkVerdict(path="a.php", hunk_id="a.php#0", result="fixed", detail="")]
    assert aggregate_content(fixed, fps) == "fixed"
    vuln = [HunkVerdict(path="a.php", hunk_id="a.php#0", result="vulnerable", detail="")]
    assert aggregate_content(vuln, fps) == "vulnerable"
    assert aggregate_content([], []) == "no_fingerprints"


# --- ported from msw tests/test_inventory_version.py (version parts) ---


@pytest.mark.parametrize(
    ("current", "affected", "expect"),
    [
        ("2.4.7-p7", "<=2.4.7-p7", True),
        ("2.4.7-p8", "<=2.4.7-p7", False),
        ("2.4.7-p8", "<=2.4.8-p5", False),
        ("2.4.8-p5", "<=2.4.8-p5", True),
        ("2.4.8-p6", "<=2.4.8-p5", False),
        ("2.4.7-p7", "<2.4.7-p8", True),
        ("2.4.7-p8", "<2.4.7-p8", False),
        ("2.4.7-p8", "==2.4.7-p8", True),
        ("2.4.7-p7", "==2.4.7-p8", False),
    ],
)
def test_version_in_range_specs(current: str, affected: str, expect: bool):
    assert version_in_range(current, affected) is expect


@pytest.mark.parametrize(
    ("current", "fixed", "expect"),
    [
        ("2.4.7-p8", "2.4.7-p8", True),
        ("2.4.7-p9", "2.4.7-p8", True),
        ("2.4.7-p7", "2.4.7-p8", False),
        ("2.4.8-p6", "2.4.7-p8", True),  # newer Magento line has moved past 2.4.7 fix
        ("2.4.6-p3", "2.4.7-p8", False),  # older line has not met 2.4.7 fix
        ("2.4.8-p6", "2.4.8-p6", True),
        ("2.4.8-2026-jul", "2.4.8-p6", True),
    ],
)
def test_version_fixed_specs(current: str, fixed: str, expect: bool):
    assert version_fixed(current, fixed) is expect


@pytest.mark.parametrize(
    ("installed_ver", "expect_status"),
    [
        ("2.4.7-p6", "vulnerable"),
        ("2.4.7-p7", "vulnerable"),
        ("2.4.7-p8", "fixed"),
        ("2.4.7-p9", "fixed"),
        ("2.4.8-p5", "vulnerable"),  # hits 2.4.8 line only
        ("2.4.8-p6", "fixed"),
        ("2.4.6-p3", "fixed"),  # meets 2.4.6-p3 fix on its own line
        ("2.4.5-p1", "not_applicable"),  # no matching release line
    ],
)
def test_multi_line_bulletin_match_statuses(tmp_path: Path, installed_ver: str, expect_status: str):
    """Ported from msw test_inventory_version.py::test_multi_line_bulletin_match_statuses."""
    analysis = RiskItemAnalysis(
        title="t",
        severity=Severity.CRITICAL,
        remediation_offer=RemediationOffer.UPGRADE_ONLY,
        packages=[
            PackageConstraint(
                name="magento/product-community-edition",
                affected_versions="<=2.4.8-p5",
                fixed_version="2.4.8-p6",
            ),
            PackageConstraint(
                name="magento/product-community-edition",
                affected_versions="<=2.4.7-p7",
                fixed_version="2.4.7-p8",
            ),
            PackageConstraint(
                name="magento/product-community-edition",
                affected_versions="<=2.4.6-p2",
                fixed_version="2.4.6-p3",
            ),
        ],
    )
    finding = match_risk_item(
        project_id="demo",
        workspace=tmp_path,
        installed={"magento/product-community-edition": installed_ver},
        analysis=analysis,
        risk_id="APSB:CVE",
    )
    assert finding.remediation_status.value == expect_status, finding.evidence.version


def test_match_risk_upgrade_fixed(tmp_path: Path):
    analysis = RiskItemAnalysis(
        title="t",
        severity=Severity.HIGH,
        remediation_offer=RemediationOffer.UPGRADE_OR_PATCH,
        packages=[
            PackageConstraint(
                name="magento/module-customer",
                affected_versions=">=2.4.0,<2.4.6",
                fixed_version="2.4.6",
            )
        ],
    )
    finding = match_risk_item(
        project_id="demo",
        workspace=tmp_path,
        installed={"magento/module-customer": "2.4.6"},
        analysis=analysis,
        risk_id="APSB99-01:CVE-2026-10001",
    )
    assert finding.remediation_status.value == "fixed"
    assert finding.fix_method.value == "upgrade"


def test_match_risk_patch_content(tmp_path: Path):
    rel = Path("vendor/magento/module-customer/Model/AccountManagement.php")
    target = tmp_path / rel
    target.parent.mkdir(parents=True)
    after = "if ($user->isAllowed() && $this->csrfValidator->validate($request)) {"
    target.write_text(after + "\n", encoding="utf-8")
    analysis = RiskItemAnalysis(
        title="t",
        severity=Severity.HIGH,
        remediation_offer=RemediationOffer.UPGRADE_OR_PATCH,
        packages=[
            PackageConstraint(
                name="magento/module-customer",
                affected_versions=">=2.4.0,<2.4.6",
                fixed_version="2.4.6",
            )
        ],
        fingerprints=[
            ContentFingerprint(
                path=str(rel),
                before="if ($user->isAllowed()) {",
                after=after,
            )
        ],
    )
    finding = match_risk_item(
        project_id="demo",
        workspace=tmp_path,
        installed={"magento/module-customer": "2.4.5"},
        analysis=analysis,
        risk_id="r1",
    )
    assert finding.remediation_status.value == "fixed"
    assert finding.fix_method.value == "patch_content"


def test_match_not_applicable(tmp_path: Path):
    analysis = RiskItemAnalysis(
        title="t",
        remediation_offer=RemediationOffer.UPGRADE_ONLY,
        packages=[
            PackageConstraint(
                name="magento/module-customer",
                affected_versions=">=2.4.0,<2.4.6",
                fixed_version="2.4.6",
            )
        ],
    )
    finding = match_risk_item(
        project_id="demo",
        workspace=tmp_path,
        installed={"magento/module-customer": "2.3.0"},
        analysis=analysis,
        risk_id="r2",
    )
    assert finding.remediation_status.value == "not_applicable"
