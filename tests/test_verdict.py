"""Verdict merging tests."""

from __future__ import annotations

from lynx_patch_watch.engine.verdict import (
    advisory_level_status,
    apply_manual_review,
    evidence_hash_of,
    merge_verdict,
)
from lynx_patch_watch.models import CheckResult


def _r(checker: str, outcome: str, confidence: float = 0.8, detail: str = "") -> CheckResult:
    return CheckResult(checker=checker, outcome=outcome, confidence=confidence, evidence={}, detail=detail)


def test_content_vulnerable_with_vendor():
    verdict = merge_verdict(
        [_r("feature_file", "vulnerable")],
        has_vendor=True,
    )
    assert verdict.status == "vulnerable"


def test_content_vulnerable_with_vendor_but_version_fixed_is_conflict():
    verdict = merge_verdict(
        [_r("feature_file", "vulnerable"), _r("composer_lock", "fixed")],
        has_vendor=True,
        version_layer_fixed=True,
    )
    assert verdict.status == "conflict"
    assert verdict.conflict_flag


def test_git_mode_content_vulnerable_does_not_override_lock_fixed():
    """git-mode repo without vendor/: content vulnerable + lock fixed → conflict."""
    verdict = merge_verdict(
        [_r("feature_file", "vulnerable"), _r("composer_lock", "fixed")],
        has_vendor=False,
    )
    assert verdict.status == "conflict"


def test_positive_evidence_fixed():
    verdict = merge_verdict(
        [_r("composer_lock", "fixed")],
        has_vendor=True,
        version_layer_fixed=True,
    )
    assert verdict.status == "fixed"
    assert verdict.decided_by == "scan"


def test_positive_and_vulnerable_conflict():
    verdict = merge_verdict(
        [_r("composer_lock", "fixed"), _r("custom_rule", "vulnerable")],
        has_vendor=True,
    )
    assert verdict.status == "conflict"


def test_declared_only():
    verdict = merge_verdict([_r("composer_json", "declared", 0.4)], has_vendor=False)
    assert verdict.status == "declared"


def test_not_applicable():
    verdict = merge_verdict(
        [_r("composer_lock", "not_applicable", 0.6)],
        has_vendor=True,
        version_layer_applicable=False,
    )
    assert verdict.status == "not_applicable"


def test_unknown_fallback():
    verdict = merge_verdict([_r("composer_lock", "unknown", 0.2)], has_vendor=True)
    assert verdict.status == "unknown"


def test_manual_project_declared_low_confidence():
    verdict = merge_verdict(
        [_r("composer_lock", "fixed", 0.9)],
        has_vendor=False,
        is_manual=True,
    )
    assert verdict.status == "fixed"
    assert verdict.decided_by == "declared"
    assert verdict.confidence <= 0.5


def test_evidence_hash_changes_with_results():
    a = evidence_hash_of([_r("composer_lock", "fixed")])
    b = evidence_hash_of([_r("composer_lock", "fixed")])
    c = evidence_hash_of([_r("composer_lock", "vulnerable")])
    assert a == b
    assert a != c


def test_advisory_level_aggregation():
    assert advisory_level_status(["fixed", "vulnerable"]) == "vulnerable"
    assert advisory_level_status(["fixed", "conflict"]) == "vulnerable"
    assert advisory_level_status(["fixed", "unknown"]) == "unknown"
    assert advisory_level_status(["fixed", "declared"]) == "declared"
    assert advisory_level_status(["fixed", "fixed"]) == "fixed"
    assert advisory_level_status(["not_applicable", "not_applicable"]) == "not_applicable"
    assert advisory_level_status([]) == "unknown"


def test_manual_review_override_and_stale():
    auto = merge_verdict([_r("composer_lock", "vulnerable")], has_vendor=True)
    status, decided_by, stale = apply_manual_review(
        auto, {"status": "confirmed_fixed", "stale": False}
    )
    assert status == "fixed" and decided_by == "manual" and stale is False
    status, decided_by, stale = apply_manual_review(
        auto, {"status": "ignored", "stale": True}
    )
    assert status == "ignored" and decided_by == "manual" and stale is True
    # no review → auto
    status, decided_by, stale = apply_manual_review(auto, None)
    assert status == "vulnerable" and decided_by == "scan"
