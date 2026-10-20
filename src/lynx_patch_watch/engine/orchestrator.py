"""Scan orchestration: resolve workspace → detect → check → merge → persist.

Incremental scans: a project is skipped when its commit, the ruleset hash and
the advisory fingerprint are all unchanged since the last successful run
(this fixes msw's "fixed items are never re-checked" gap).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from lynx_patch_watch.adapters.magento.source import ChimeraAdvisorySource
from lynx_patch_watch.checkers import CHECKERS
from lynx_patch_watch.checkers.base import CheckContext
from lynx_patch_watch.detect import detect as detect_type
from lynx_patch_watch.engine.rules import RuleSet
from lynx_patch_watch.git_workspace import GitWorkspace
from lynx_patch_watch.inventory import merge_installed_for_matching
from lynx_patch_watch.models import CheckResult
from lynx_patch_watch.store import Store

logger = logging.getLogger(__name__)


@dataclass
class ItemVerdict:
    item_id: str
    advisory_id: str
    cve_id: str | None
    status: str
    confidence: float
    evidence_hash: str
    decided_by: str
    conflict: bool
    results: list[CheckResult] = field(default_factory=list)
    review_status: str | None = None
    review_stale: bool = False


@dataclass
class ScanOutcome:
    project_id: str
    scan_run_id: int | None
    status: str  # done | skipped | error
    skip_reason: str | None = None
    error: str | None = None
    git_commit: str | None = None
    verdicts: list[ItemVerdict] = field(default_factory=list)


def resolve_workspace(
    project: dict[str, Any],
    *,
    settings: Any,
) -> tuple[Path | None, str | None, str | None]:
    """Return (workspace_path, git_commit, error) for a project."""
    scan_mode = project.get("scan_mode") or "manual"
    if scan_mode == "git":
        git_url = project.get("git_url")
        branch = project.get("branch") or "main"
        if not git_url:
            return None, None, "git project without git_url"
        mirrors_dir = Path(settings.scan.mirrors_dir)
        gw = GitWorkspace(mirrors_dir, timeout=int(settings.scan.fetch_timeout_seconds))
        try:
            path, commit = gw.sync(project["id"], git_url, branch)
        except Exception as exc:  # noqa: BLE001
            return None, None, f"git sync failed: {exc}"
        return path, commit, None
    if scan_mode == "local":
        local_path = project.get("local_path")
        if not local_path:
            return None, None, "local project without local_path"
        path = Path(local_path)
        local_root = settings.scan.local_root
        if local_root:
            root = Path(local_root).resolve()
            try:
                path.resolve().relative_to(root)
            except ValueError:
                return None, None, f"local_path {local_path} is outside scan.local_root"
        if not path.is_dir():
            return None, None, f"local_path does not exist: {local_path}"
        return path, None, None
    return None, None, None  # manual


def scan_project(
    store: Store,
    project: dict[str, Any],
    *,
    ruleset: RuleSet,
    settings: Any,
    full: bool = False,
    job_id: int | None = None,
) -> ScanOutcome:
    """Scan one project and persist check results + findings ledger rows."""
    project_id = project["id"]
    advisory_fp = store.advisory_fingerprint()
    ruleset_hash = ruleset.hash

    workspace, git_commit, ws_error = resolve_workspace(project, settings=settings)
    if ws_error:
        run_id = store.start_scan_run(
            project_id, job_id=job_id, git_commit=None, ruleset_hash=ruleset_hash
        )
        store.finish_scan_run(run_id, "error", error=ws_error)
        return ScanOutcome(project_id, run_id, "error", error=ws_error)

    # Incremental skip.
    if not full and workspace is not None:
        last = store.latest_scan_run(project_id)
        if (
            last
            and last.get("status") == "done"
            and (last.get("git_commit") or "") == (git_commit or "")
            and (last.get("ruleset_hash") or "") == ruleset_hash
            and (last.get("advisory_fingerprint") or "") == advisory_fp
        ):
            return ScanOutcome(
                project_id,
                None,
                "skipped",
                skip_reason="commit, ruleset and advisories unchanged",
                git_commit=git_commit,
            )

    run_id = store.start_scan_run(
        project_id,
        job_id=job_id,
        git_commit=git_commit,
        ruleset_hash=ruleset_hash,
        advisory_fingerprint=advisory_fp,
    )

    try:
        outcome = _run_checks(
            store,
            project,
            workspace=workspace,
            git_commit=git_commit,
            ruleset=ruleset,
            settings=settings,
            scan_run_id=run_id,
        )
        store.finish_scan_run(run_id, "done", git_commit=git_commit)
        outcome.scan_run_id = run_id
        outcome.git_commit = git_commit
        return outcome
    except Exception as exc:  # noqa: BLE001
        logger.exception("scan failed for %s", project_id)
        store.finish_scan_run(run_id, "error", error=str(exc))
        return ScanOutcome(project_id, run_id, "error", error=str(exc), git_commit=git_commit)


def _run_checks(
    store: Store,
    project: dict[str, Any],
    *,
    workspace: Path | None,
    git_commit: str | None,
    ruleset: RuleSet,
    settings: Any,
    scan_run_id: int,
) -> ScanOutcome:
    from lynx_patch_watch.engine.verdict import (
        Verdict,
        advisory_level_status,
        apply_manual_review,
        merge_verdict,
    )

    project_id = project["id"]
    scan_mode = project.get("scan_mode") or "manual"

    # --- detection ---
    detected_type = project.get("detected_type")
    detected_version = None
    detected_edition = None
    if workspace is not None:
        det = detect_type(workspace)
        detected_type = det.type if project.get("type", "auto") == "auto" else project.get("type")
        detected_version = det.version
        detected_edition = det.edition
        store.upsert_project(
            {
                "id": project_id,
                "detected_type": det.type,
                "declared_version": project.get("declared_version") or det.version,
                "declared_edition": project.get("declared_edition") or det.edition,
            }
        )
    else:
        detected_type = project.get("type") if project.get("type") != "auto" else "unknown"
        detected_version = project.get("declared_version")
        detected_edition = project.get("declared_edition")

    # --- inventory ---
    installed: dict[str, str] = {}
    has_vendor = False
    if workspace is not None:
        installed = merge_installed_for_matching(workspace)
        has_vendor = (workspace / "vendor").is_dir()
    else:
        # manual project: declared version acts as the product pin
        declared_version = project.get("declared_version")
        if declared_version:
            installed = {
                "magento/product-community-edition": declared_version,
                "magento/product-enterprise-edition": declared_version,
            }

    ctx = CheckContext(
        project=project,
        item={},
        workspace=workspace,
        installed=installed,
        has_vendor=has_vendor,
        scan_mode=scan_mode,
        git_commit=git_commit,
        git=GitWorkspace(Path(settings.scan.mirrors_dir)) if scan_mode == "git" else None,
        patch_cache_dir=Path(settings.advisory.patch_cache_dir),
        detected_type=detected_type or "unknown",
        detected_version=detected_version,
        detected_edition=detected_edition,
    )

    items = store.list_advisory_items()
    verdicts: list[ItemVerdict] = []
    for item in items:
        item_rules = [
            r for r in ruleset.for_item(item["advisory_id"], item.get("cve_id")) if r.applies(ctx)
        ]
        ctx.item = item
        results: list[CheckResult] = []
        for checker in CHECKERS:
            try:
                results.extend(checker.run(ctx, item, item_rules))
            except Exception as exc:  # noqa: BLE001 — a broken checker must not kill the scan
                logger.exception("checker %s failed on %s", checker.name, item["item_id"])
                results.append(
                    CheckResult(
                        checker=checker.name,
                        outcome="error",
                        confidence=0.0,
                        evidence={"error": str(exc)},
                        detail=f"checker error: {exc}",
                    )
                )
        for r in results:
            store.insert_check_result(
                scan_run_id=scan_run_id,
                project_id=project_id,
                item_id=item["item_id"],
                checker=r.checker,
                outcome=r.outcome,
                confidence=r.confidence,
                evidence=r.evidence,
            )

        # version layer signals for the verdict merger
        lock_results = [r for r in results if r.checker == "composer_lock"]
        version_layer_fixed = any(r.outcome == "fixed" for r in lock_results) or None
        version_layer_vulnerable = any(r.outcome == "vulnerable" for r in lock_results) or None
        version_layer_applicable = (
            False if any(r.outcome == "not_applicable" for r in lock_results) else None
        )

        verdict: Verdict = merge_verdict(
            results,
            has_vendor=has_vendor,
            is_manual=(scan_mode == "manual"),
            version_layer_fixed=version_layer_fixed,
            version_layer_vulnerable=version_layer_vulnerable,
            version_layer_applicable=version_layer_applicable,
        )

        review = store.get_manual_review(project_id, item["item_id"])
        final_status, decided_by, stale = apply_manual_review(verdict, review)
        store.refresh_manual_review_staleness(project_id, item["item_id"], verdict.evidence_hash)

        store.insert_finding(
            scan_run_id=scan_run_id,
            project_id=project_id,
            item_id=item["item_id"],
            status=final_status,
            decided_by=decided_by,
            evidence_hash=verdict.evidence_hash,
            source="scan",
            confidence=verdict.confidence,
        )
        verdicts.append(
            ItemVerdict(
                item_id=item["item_id"],
                advisory_id=item["advisory_id"],
                cve_id=item.get("cve_id"),
                status=final_status,
                confidence=verdict.confidence,
                evidence_hash=verdict.evidence_hash,
                decided_by=decided_by,
                conflict=verdict.conflict_flag,
                results=results,
                review_status=(review or {}).get("status"),
                review_stale=stale,
            )
        )

    return ScanOutcome(project_id, scan_run_id, "done", verdicts=verdicts)


def project_item_statuses(store: Store, project_id: str) -> dict[str, list[str]]:
    """Latest status per advisory for a project: {advisory_id: [item statuses]}.

    Every known advisory item is represented: items without a finding (project
    never scanned, or the item post-dates the last scan) report ``unknown`` so
    that the matrix / API / export still surface them instead of silently
    dropping whole advisories.
    """
    per_item: dict[str, str] = {item["item_id"]: "unknown" for item in store.list_advisory_items()}
    for row in store.list_latest_findings(project_id):
        per_item[row["item_id"]] = row["status"]
    out: dict[str, list[str]] = {}
    for item_id, status in per_item.items():
        item = store.get_advisory_item(item_id)
        advisory = item["advisory_id"] if item else item_id.split(":", 1)[0]
        out.setdefault(advisory, []).append(status)
    return out


def project_advisory_status(store: Store, project_id: str) -> dict[str, str]:
    from lynx_patch_watch.engine.verdict import advisory_level_status

    return {
        advisory: advisory_level_status(statuses)
        for advisory, statuses in project_item_statuses(store, project_id).items()
    }
