"""Ported from msw tests/test_adobe_versions.py (bulletin parsing parts) plus
new anchored-matching and hotfix-detection cases."""

from __future__ import annotations

from pathlib import Path

from lynx_patch_watch.adobe_bulletin import (
    attach_bulletin_packages_to_seeds,
    detect_isolated_patch_signals,
    parse_affected_and_solution,
    phrase_to_constraint_bits,
)
from lynx_patch_watch.magento_version import (
    composer_recommendable_versions,
    is_dated_security_label,
    magento_gte,
    parse_magento_version,
)
from lynx_patch_watch.matcher import match_risk_item, version_fixed, version_in_range
from lynx_patch_watch.models import (
    PackageConstraint,
    RemediationOffer,
    RiskItemAnalysis,
    Severity,
)
from lynx_patch_watch.sources_cve import extract_bulletin_cves, extract_vuln_detail_by_cve

FIXTURES = Path(__file__).parent / "fixtures" / "advisories"


def test_magento_version_order():
    assert parse_magento_version("2.4.8-p5") < parse_magento_version("2.4.8-p6")
    assert parse_magento_version("2.4.8-p5") < parse_magento_version("2.4.8-2026-jul")
    assert magento_gte("2.4.8-p6", "2.4.8-p6") is True
    assert magento_gte("2.4.8-p5", "2.4.8-p6") is False
    assert is_dated_security_label("2.4.8-2026-jul")
    assert not is_dated_security_label("2.4.8-p5")
    assert composer_recommendable_versions(["2.4.8-p5", "2.4.8-2026-jul", "2.4.7-p10"]) == [
        "2.4.8-p5",
        "2.4.7-p10",
    ]


def test_release_line_scoped_ranges():
    """Adobe '2.4.8-p5 and earlier' must not flag 2.4.7-p8 as affected."""
    assert version_in_range("2.4.7-p8", "<=2.4.8-p5") is False
    assert version_in_range("2.4.7-p8", "<=2.4.7-p7") is False
    assert version_in_range("2.4.7-p7", "<=2.4.7-p7") is True
    assert version_fixed("2.4.7-p8", "2.4.7-p8") is True
    assert version_fixed("2.4.7-p8", "2.4.8-p6") is False


def test_phrase_and_earlier():
    spec, fixed = phrase_to_constraint_bits("2.4.8-p5 and earlier")
    assert spec == "<=2.4.8-p5"
    assert fixed == "2.4.8-p6"
    assert version_in_range("2.4.8-p5", spec) is True
    assert version_in_range("2.4.8-p6", spec) is False
    assert version_fixed("2.4.8-p6", fixed) is True
    assert version_fixed("2.4.8-p5", fixed) is False


def test_parse_apsb26_73_tables():
    html = (FIXTURES / "apsb26-73-snippet.html").read_text(encoding="utf-8")
    parsed = parse_affected_and_solution(html)
    assert parsed["has_affected_table"]
    assert parsed["packages"]
    names = {p["name"] for p in parsed["packages"]}
    assert "magento/product-community-edition" in names
    assert "magento/product-enterprise-edition" in names
    # and-earlier line becomes <=2.4.8-p5 with fixed 2.4.8-p6
    ce = [
        p
        for p in parsed["packages"]
        if p["name"] == "magento/product-community-edition" and p["affected_versions"] == "<=2.4.8-p5"
    ]
    assert ce and ce[0]["fixed_version"] == "2.4.8-p6"
    # recommended_min = Affected baselines (Composer), not Solution *-2026-jul labels
    assert "2.4.8-p5" in parsed["recommended_min_versions"]
    assert "2.4.9" in parsed["recommended_min_versions"]
    assert "2.4.8-2026-jul" not in parsed["recommended_min_versions"]
    assert "2.4.8-2026-jul" in parsed["solution_version_labels"]


def test_apsb26_146_hotfix_signals():
    """APSB26-146's Solution column offers only 'Hotfix for CVE-2026-75650'."""
    html = (FIXTURES / "apsb26-146-snippet.html").read_text(encoding="utf-8")
    signals = detect_isolated_patch_signals(html)
    assert signals["has_isolated_patch"] is True
    assert "isolated_text" in signals["reasons"]
    cves = extract_bulletin_cves(html)
    assert cves == ["CVE-2026-75650"]
    details = extract_vuln_detail_by_cve(html)
    row = details["CVE-2026-75650"]
    assert row["severity"] == "critical"
    assert row["score"] == 10.0


def test_attach_and_match_fixed_upgrade(tmp_path: Path):
    html = (FIXTURES / "apsb26-73-snippet.html").read_text(encoding="utf-8")
    seeds = attach_bulletin_packages_to_seeds(
        [{"title": "APSB26-73 CVE-2026-48356", "cve_ids": ["CVE-2026-48356"], "severity": "critical"}],
        html,
    )
    assert seeds[0]["packages"]
    assert seeds[0]["upgrade_available"] is True
    from lynx_patch_watch.sources_cve import seed_to_analysis

    analysis = seed_to_analysis(seeds[0], "")
    assert analysis.packages
    assert analysis.remediation_offer.value in {"upgrade_only", "upgrade_or_patch"}

    workspace = tmp_path / "shop"
    workspace.mkdir()
    installed = {"magento/product-community-edition": "2.4.8-p6"}
    finding = match_risk_item(
        project_id="demo",
        workspace=workspace,
        installed=installed,
        analysis=analysis,
        risk_id="APSB26-73:CVE-2026-48356",
    )
    assert finding.remediation_status.value == "fixed"
    assert finding.fix_method.value == "upgrade"


def test_multi_line_bulletin_247_p8_is_fixed(tmp_path: Path):
    """Project on 2.4.7-p8 must be fixed when bulletin lists 2.4.7-p7 and earlier + other lines."""
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
                name="magento/product-enterprise-edition",
                affected_versions="<=2.4.7-p7",
                fixed_version="2.4.7-p8",
            ),
        ],
    )
    finding = match_risk_item(
        project_id="demo",
        workspace=tmp_path,
        installed={"magento/product-community-edition": "2.4.7-p8"},
        analysis=analysis,
        risk_id="APSB:CVE",
    )
    assert finding.remediation_status.value == "fixed", finding.evidence.version
    assert finding.fix_method.value == "upgrade"


def test_attach_and_match_vulnerable(tmp_path: Path):
    html = (FIXTURES / "apsb26-73-snippet.html").read_text(encoding="utf-8")
    seeds = attach_bulletin_packages_to_seeds(
        [{"title": "x", "cve_ids": ["CVE-2026-48356"], "severity": "critical"}],
        html,
    )
    from lynx_patch_watch.sources_cve import seed_to_analysis

    analysis = seed_to_analysis(seeds[0], "")
    finding = match_risk_item(
        project_id="demo",
        workspace=tmp_path,
        installed={"magento/product-community-edition": "2.4.8-p3"},
        analysis=analysis,
        risk_id="APSB26-73:CVE-2026-48356",
    )
    assert finding.remediation_status.value == "vulnerable"
