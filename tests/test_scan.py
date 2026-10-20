"""Scan orchestration end-to-end tests (local workspace + incremental skip)."""

from __future__ import annotations

from pathlib import Path

from lynx_patch_watch.adapters.magento.source import ChimeraAdvisorySource
from lynx_patch_watch.config import AppSettings
from lynx_patch_watch.engine.ingest import ingest_from_source
from lynx_patch_watch.engine.orchestrator import (
    project_advisory_status,
    scan_project,
)
from lynx_patch_watch.engine.rules import load_ruleset
from lynx_patch_watch.store import Store
from tests.conftest import FIXTURES, make_magento_workspace

REPO_ROOT = Path(__file__).resolve().parent.parent


def _settings(tmp_path: Path) -> AppSettings:
    settings = AppSettings()
    settings.data_dir = str(tmp_path / "data")
    settings.db_path = str(tmp_path / "data" / "lpw.sqlite")
    settings.scan.mirrors_dir = str(tmp_path / "data" / "mirrors")
    settings.scan.local_root = str(tmp_path)
    settings.advisory.patch_cache_dir = str(tmp_path / "data" / "cache" / "patches")
    settings.rules.dir = str(REPO_ROOT / "rules" / "magento")
    return settings


def _ingest(store: Store):
    source = ChimeraAdvisorySource(
        chimera_url="unused", fixture_dir=FIXTURES, detail_fetch_limit=15
    )
    return ingest_from_source(store, source)


def test_scan_local_project_fixed_by_version(store: Store, tmp_path: Path):
    _ingest(store)
    ws = make_magento_workspace(tmp_path / "shop", version="2.4.8-p6")
    store.upsert_project(
        {"id": "shop", "name": "Shop", "type": "magento", "scan_mode": "local", "local_path": str(ws)}
    )
    ruleset = load_ruleset(REPO_ROOT / "rules" / "magento")
    outcome = scan_project(store, store.get_project("shop"), ruleset=ruleset, settings=_settings(tmp_path))
    assert outcome.status == "done"
    statuses = {v.item_id: v.status for v in outcome.verdicts}
    # APSB26-73 affects <=2.4.8-p5 with fix 2.4.8-p6 → project on 2.4.8-p6 is fixed.
    assert statuses["APSB26-73:CVE-2026-48356"] == "fixed"
    # APSB26-146 affects dated "2.4.8-2026-aug and earlier" ranges; a 2.4.8-p6
    # project predates that patch and has no hotfix artifact → vulnerable.
    assert statuses["APSB26-146:CVE-2026-75650"] == "vulnerable"
    # detection recorded
    project = store.get_project("shop")
    assert project["detected_type"] == "magento"
    # ledger + latest findings
    assert len(store.list_latest_findings("shop")) == len(outcome.verdicts)
    advisory = project_advisory_status(store, "shop")
    assert advisory["APSB26-73"] == "fixed"


def test_scan_incremental_skip(store: Store, tmp_path: Path):
    _ingest(store)
    ws = make_magento_workspace(tmp_path / "shop", version="2.4.8-p6")
    store.upsert_project(
        {"id": "shop", "name": "Shop", "type": "magento", "scan_mode": "local", "local_path": str(ws)}
    )
    ruleset = load_ruleset(REPO_ROOT / "rules" / "magento")
    settings = _settings(tmp_path)
    first = scan_project(store, store.get_project("shop"), ruleset=ruleset, settings=settings)
    assert first.status == "done"
    second = scan_project(store, store.get_project("shop"), ruleset=ruleset, settings=settings)
    assert second.status == "skipped"
    assert second.skip_reason
    # --full forces a re-run
    third = scan_project(store, store.get_project("shop"), ruleset=ruleset, settings=settings, full=True)
    assert third.status == "done"


def test_scan_manual_project_declared(store: Store, tmp_path: Path):
    _ingest(store)
    store.upsert_project(
        {
            "id": "manual-1",
            "name": "Manual",
            "type": "magento",
            "scan_mode": "manual",
            "declared_version": "2.4.8-p3",
        }
    )
    ruleset = load_ruleset(REPO_ROOT / "rules" / "magento")
    outcome = scan_project(
        store, store.get_project("manual-1"), ruleset=ruleset, settings=_settings(tmp_path)
    )
    assert outcome.status == "done"
    statuses = {v.item_id: v.status for v in outcome.verdicts}
    assert statuses["APSB26-73:CVE-2026-48356"] == "vulnerable"
    assert statuses["APSB26-73:CVE-2026-48356"] == "vulnerable"
    findings = store.list_latest_findings("manual-1")
    assert all(f["decided_by"] == "declared" for f in findings)


def test_scan_local_path_outside_root_rejected(store: Store, tmp_path: Path):
    _ingest(store)
    outside = tmp_path / "outside"
    make_magento_workspace(outside, version="2.4.8-p6")
    store.upsert_project(
        {
            "id": "shop",
            "name": "Shop",
            "type": "magento",
            "scan_mode": "local",
            "local_path": str(outside),
        }
    )
    settings = _settings(tmp_path)
    settings.scan.local_root = str(tmp_path / "allowed-root")
    ruleset = load_ruleset(REPO_ROOT / "rules" / "magento")
    outcome = scan_project(store, store.get_project("shop"), ruleset=ruleset, settings=settings)
    assert outcome.status == "error"
    assert "local_root" in (outcome.error or "")


def test_scan_hotfix_verified(store: Store, tmp_path: Path):
    """A matching m2-hotfixes patch whose after-side matches vendor → positive
    evidence. The project is still on an affected version line (2.4.7-p7 ≤
    2.4.7-p10), so per the merge rules the result is conflict (needs review),
    not silently fixed."""
    _ingest(store)
    ws = make_magento_workspace(tmp_path / "shop", version="2.4.7-p7")
    target = ws / "vendor/magento/module-customer/Model/AccountManagement.php"
    target.parent.mkdir(parents=True)
    target.write_text(
        "if ($user->isAllowed() && $this->csrfValidator->validate($request)) {\n",
        encoding="utf-8",
    )
    (ws / "m2-hotfixes").mkdir()
    (ws / "m2-hotfixes/CVE-2026-48356-fix.patch").write_text(
        """diff --git a/vendor/magento/module-customer/Model/AccountManagement.php b/vendor/magento/module-customer/Model/AccountManagement.php
index 111..222 100644
--- a/vendor/magento/module-customer/Model/AccountManagement.php
+++ b/vendor/magento/module-customer/Model/AccountManagement.php
@@ -10,7 +10,7 @@ class AccountManagement
     public function doSomething($user, $request)
     {
-    if ($user->isAllowed()) {
+    if ($user->isAllowed() && $this->csrfValidator->validate($request)) {
         return true;
     }
""",
        encoding="utf-8",
    )
    store.upsert_project(
        {"id": "shop", "name": "Shop", "type": "magento", "scan_mode": "local", "local_path": str(ws)}
    )
    ruleset = load_ruleset(REPO_ROOT / "rules" / "magento")
    outcome = scan_project(store, store.get_project("shop"), ruleset=ruleset, settings=_settings(tmp_path))
    statuses = {v.item_id: v.status for v in outcome.verdicts}
    assert statuses["APSB26-73:CVE-2026-48356"] == "conflict"


def test_ruleset_hash_and_loading():
    ruleset = load_ruleset(REPO_ROOT / "rules" / "magento")
    assert ruleset.rules
    assert len(ruleset.hash) == 16
    rule = ruleset.for_item("APSB26-146", "CVE-2026-75650")
    assert rule and rule[0].id == "apsb26-146-hotfix"
    assert ruleset.for_item("APSB26-146", "CVE-9999-9999") == []
