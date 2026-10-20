"""Verdict merging: checker results → one conclusion per (project, item).

Per plan:

| 顺序 | 条件 | 结论 |
|---|---|---|
| 1 | 部署树里有 vendor/，且内容证据为 vulnerable | vulnerable；如果版本层显示已修，另加"冲突"标记 |
| 2 | 有正向证据（内容 fixed、hotfix 已验证、lock 版本 ≥ 修复版本、修复 commit 是祖先、自定义规则命中） | fixed |
| 3 | 正向证据与漏洞证据同时存在 | conflict（计为未修，需要复核） |
| 4 | 只有补丁声明 | declared（不计入已验证的修复率） |
| 5 | 所有包都不在受影响范围内 | not_applicable |
| 6 | 其余情况 | unknown |

Supplementary rules:
- git-mode repos without vendor/: content-vulnerable does NOT override
  lock-fixed; it is recorded as conflict only;
- manual projects: declared data only, decided_by=declared, low confidence.

Manual reviews override the automatic conclusion (stale reviews are re-marked
when evidence changes); ignored / false_positive reviews are removed from the
denominator and never count as fixed.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Iterable

from lynx_patch_watch.models import CheckResult

# Outcomes ordered by merge priority.
POSITIVE_OUTCOMES = frozenset({"fixed"})
VULNERABLE_OUTCOMES = frozenset({"vulnerable"})
DECLARED_OUTCOMES = frozenset({"declared"})


@dataclass
class Verdict:
    status: str  # fixed | vulnerable | conflict | declared | not_applicable | unknown
    confidence: float = 0.0
    evidence_hash: str = ""
    reasons: list[str] = field(default_factory=list)
    decided_by: str = "scan"  # scan | manual | declared
    conflict_flag: bool = False


def evidence_hash_of(results: Iterable[CheckResult]) -> str:
    payload = json.dumps(
        [
            {
                "checker": r.checker,
                "outcome": r.outcome,
                "evidence": r.evidence,
            }
            for r in results
        ],
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]


def merge_verdict(
    results: list[CheckResult],
    *,
    has_vendor: bool,
    is_manual: bool = False,
    version_layer_fixed: bool | None = None,
    version_layer_vulnerable: bool | None = None,
    version_layer_applicable: bool | None = None,
) -> Verdict:
    """Merge checker results into one conclusion for (project, item)."""
    results = [r for r in results if r is not None]
    positive = [r for r in results if r.outcome in POSITIVE_OUTCOMES]
    vulnerable = [r for r in results if r.outcome in VULNERABLE_OUTCOMES]
    declared = [r for r in results if r.outcome in DECLARED_OUTCOMES]
    not_applicable = [r for r in results if r.outcome == "not_applicable"]

    reasons: list[str] = []
    for r in positive:
        reasons.append(f"{r.checker}: {r.detail or 'positive evidence'}")
    for r in vulnerable:
        reasons.append(f"{r.checker}: {r.detail or 'vulnerable evidence'}")
    for r in declared:
        reasons.append(f"{r.checker}: {r.detail or 'declared patch'}")

    eh = evidence_hash_of(results)
    confidence = max((r.confidence for r in results), default=0.0)

    if is_manual:
        # Manual projects only have declared data.
        if positive:
            return Verdict("fixed", min(confidence, 0.5), eh, reasons, decided_by="declared")
        if declared:
            return Verdict("declared", min(confidence, 0.4), eh, reasons, decided_by="declared")
        if vulnerable:
            return Verdict("vulnerable", confidence, eh, reasons, decided_by="declared")
        return Verdict("unknown", 0.0, eh, reasons, decided_by="declared")

    # Rule 1: content evidence vulnerable with vendor present.
    content_vulnerable = any(
        r.checker in ("feature_file", "hotfix_dir", "git_commit") and r.outcome == "vulnerable"
        for r in vulnerable
    )
    version_fixed = version_layer_fixed is True
    version_vulnerable = version_layer_vulnerable is True

    if content_vulnerable and has_vendor and not positive:
        conflict = version_fixed
        return Verdict(
            "vulnerable" if not conflict else "conflict",
            confidence,
            eh,
            reasons,
            conflict_flag=conflict,
        )

    # Rule 3: positive + vulnerable evidence (content, rule or version layer).
    if positive and (vulnerable or version_vulnerable):
        return Verdict("conflict", confidence, eh, reasons, conflict_flag=True)

    # Rule 1b: version-layer vulnerable evidence without positive evidence.
    if vulnerable and not positive:
        return Verdict("vulnerable", confidence, eh, reasons)

    # Rule 2: positive evidence.
    if positive:
        return Verdict("fixed", confidence, eh, reasons)

    # Rule 4: declared only.
    if declared:
        return Verdict("declared", min(confidence, 0.5), eh, reasons)

    # Rule 5: not applicable.
    if version_layer_applicable is False and not vulnerable:
        return Verdict("not_applicable", 0.6, eh, reasons + ["version layer: not applicable"])
    if not_applicable and not results_unknown_or_vuln(results):
        return Verdict("not_applicable", 0.6, eh, reasons + ["checkers: not applicable"])

    # Rule 6: unknown.
    return Verdict("unknown", confidence, eh, reasons)


def results_unknown_or_vuln(results: list[CheckResult]) -> bool:
    return any(r.outcome in ("unknown", "vulnerable", "error") for r in results)


def advisory_level_status(item_statuses: Iterable[str]) -> str:
    """Aggregate item-level statuses into one matrix-cell status.

    | 条件 | 结果 |
    | 任一 item vulnerable/conflict | vulnerable |
    | 其次任一 unknown | unknown |
    | 其次任一 declared | declared |
    | 所有适用 item fixed | fixed |
    | 全部 N/A | N/A |
    """
    statuses = [s for s in item_statuses if s]
    if not statuses:
        return "unknown"
    if any(s in ("vulnerable", "conflict") for s in statuses):
        return "vulnerable"
    if any(s == "unknown" for s in statuses):
        return "unknown"
    if any(s == "declared" for s in statuses):
        return "declared"
    if statuses and all(s == "fixed" for s in statuses):
        return "fixed"
    if all(s == "not_applicable" for s in statuses):
        return "not_applicable"
    return "unknown"


def apply_manual_review(
    auto: Verdict,
    review: dict[str, Any] | None,
) -> tuple[str, str, bool]:
    """Apply a manual review override.

    Returns (final_status, decided_by, stale).
    - review statuses: confirmed_fixed | confirmed_vulnerable | ignored | false_positive | pending
    - ignored / false_positive are excluded from denominators by callers.
    - Without a review the automatic decision (and its decided_by) stands.
    """
    if not review:
        return auto.status, auto.decided_by, False
    status = review.get("status") or ""
    stale = bool(review.get("stale"))
    if status == "confirmed_fixed":
        return "fixed", "manual", stale
    if status == "confirmed_vulnerable":
        return "vulnerable", "manual", stale
    if status == "ignored":
        return "ignored", "manual", stale
    if status == "false_positive":
        return "false_positive", "manual", stale
    if status == "pending":
        return auto.status, auto.decided_by, stale
    return auto.status, auto.decided_by, stale
