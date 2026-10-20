"""Store schema / ledger / review tests (new for lpw)."""

from __future__ import annotations

from lynx_patch_watch.store import Store, valid_project_id


def test_project_crud_and_validation(store: Store):
    assert valid_project_id("shop-a")
    assert valid_project_id("ab")
    assert not valid_project_id("a")  # too short per ^[a-z0-9][a-z0-9_-]{1,63}$
    assert not valid_project_id("ShopA")  # uppercase
    assert not valid_project_id("-lead")  # leading dash
    assert not valid_project_id("x" * 65)  # too long
    assert not valid_project_id("")

    store.upsert_project({"id": "shop-a", "name": "Shop A", "scan_mode": "local"})
    p = store.get_project("shop-a")
    assert p is not None
    assert p["name"] == "Shop A"
    assert p["scan_mode"] == "local"
    assert p["type"] == "auto"
    assert p["enabled"] is True

    store.upsert_project({"id": "shop-a", "name": "Shop A2"})
    assert store.get_project("shop-a")["name"] == "Shop A2"
    assert store.get_project("shop-a")["scan_mode"] == "local"  # preserved

    store.upsert_project({"id": "shop-b", "name": "B", "enabled": False})
    assert len(store.list_projects()) == 2
    assert len(store.list_projects(include_disabled=False)) == 1

    store.delete_project("shop-b")
    assert store.get_project("shop-b") is None


def test_advisory_and_items(store: Store):
    store.upsert_advisory(
        {
            "id": "APSB26-146",
            "product": "Adobe Commerce",
            "title": "Security update available for Adobe Commerce | APSB26-146",
            "priority": "1",
            "published_at": "2026-09-07T00:00:00+00:00",
            "modified_at": "2026-09-30T15:15:14+00:00",
            "url": "https://www.adobe.com/trust/security/products/commerce/apsb26-146",
            "detail_status": "blocked",
        }
    )
    store.upsert_advisory_item(
        {
            "item_id": "APSB26-146:CVE-2026-75650",
            "advisory_id": "APSB26-146",
            "cve_id": "CVE-2026-75650",
            "severity": "critical",
            "cvss": 10.0,
            "packages": [
                {"name": "magento/product-community-edition", "affected_versions": "<=2.4.9-2026-aug", "fixed_version": None}
            ],
            "fix_kind": "hotfix",
        }
    )
    adv = store.get_advisory("APSB26-146")
    assert adv["detail_status"] == "blocked"
    assert adv["item_count"] == 1
    rows = store.list_advisory_items("APSB26-146")
    assert len(rows) == 1
    assert rows[0]["packages"][0]["name"] == "magento/product-community-edition"
    assert rows[0]["fix_kind"] == "hotfix"
    listed = store.list_advisories()
    assert listed[0]["id"] == "APSB26-146"
    assert listed[0]["item_count"] == 1


def test_findings_ledger_latest_wins(store: Store):
    store.upsert_project({"id": "p1", "name": "P1"})
    store.upsert_advisory({"id": "APSB26-146", "title": "t"})
    store.upsert_advisory_item({"item_id": "APSB26-146:CVE-2026-75650", "advisory_id": "APSB26-146", "cve_id": "CVE-2026-75650"})
    store.insert_finding(scan_run_id=None, project_id="p1", item_id="APSB26-146:CVE-2026-75650", status="unknown", evidence_hash="h1")
    store.insert_finding(scan_run_id=None, project_id="p1", item_id="APSB26-146:CVE-2026-75650", status="fixed", evidence_hash="h2")
    latest = store.list_latest_findings("p1")
    assert len(latest) == 1
    assert latest[0]["status"] == "fixed"
    counts = store.count_latest_by_status("p1")
    assert counts["fixed"] == 1 and counts["unknown"] == 0
    assert store.first_finding_time("p1", "APSB26-146:CVE-2026-75650") is not None
    assert store.fixed_finding_time("p1", "APSB26-146:CVE-2026-75650") is not None


def test_manual_review_upsert_and_staleness(store: Store):
    store.upsert_project({"id": "p1", "name": "P1"})
    item = "APSB26-146:CVE-2026-75650"
    store.upsert_manual_review(project_id="p1", item_id=item, status="ignored", evidence_hash_at_review="h1")
    store.upsert_manual_review(project_id="p1", item_id=item, status="false_positive", evidence_hash_at_review="h1")
    reviews = store.list_manual_reviews("p1")
    assert len(reviews) == 1
    assert reviews[0]["status"] == "false_positive"
    # evidence hash changed → stale
    store.refresh_manual_review_staleness("p1", item, "h2")
    assert store.get_manual_review("p1", item)["stale"] is True
    # unchanged → not stale
    store.upsert_manual_review(project_id="p1", item_id=item, status="ignored", evidence_hash_at_review="h2")
    store.refresh_manual_review_staleness("p1", item, "h2")
    assert store.get_manual_review("p1", item)["stale"] is False


def test_scan_jobs_lifecycle(store: Store):
    store.upsert_project({"id": "p1", "name": "P1"})
    job = store.enqueue_scan_job("p1", trigger="manual")
    assert store.next_queued_job()["id"] == job
    store.mark_job_running(job)
    assert store.next_queued_job() is None
    store.mark_job_done(job, "done")
    jobs = store.list_scan_jobs()
    assert jobs[0]["status"] == "done"
    # stale running detection
    j2 = store.enqueue_scan_job("p1")
    store.mark_job_running(j2)
    assert store.fail_stale_running_jobs() == 1
    assert [j for j in store.list_scan_jobs() if j["id"] == j2][0]["status"] == "failed"


def test_audit_log(store: Store):
    store.audit("tester", "project.create", "p1", {"name": "P1"})
    rows = store.list_audit_log()
    assert rows[0]["action"] == "project.create"
    assert rows[0]["actor"] == "tester"


def test_check_results_insert(store: Store):
    store.upsert_project({"id": "p1", "name": "P1"})
    run = store.start_scan_run("p1", ruleset_hash="abc")
    store.insert_check_result(
        scan_run_id=run,
        project_id="p1",
        item_id="APSB26-146:CVE-2026-75650",
        checker="composer_lock",
        outcome="fixed",
        confidence=0.9,
        evidence={"detail": "2.4.8-p6 >= 2.4.8-p6"},
    )
    store.finish_scan_run(run, "done", git_commit="deadbeef")
    runs = store.list_scan_runs("p1")
    assert runs[0]["status"] == "done"
    assert runs[0]["git_commit"] == "deadbeef"


def test_finding_times_and_open_counts_match_per_item_queries(tmp_path):
    from lynx_patch_watch.store import Store

    store = Store(tmp_path / "t.sqlite")
    store.upsert_project({"id": "p1", "name": "P1", "scan_mode": "manual"})
    r1 = store.start_scan_run("p1")
    store.insert_finding(scan_run_id=r1, project_id="p1", item_id="a", status="vulnerable")
    store.insert_finding(scan_run_id=r1, project_id="p1", item_id="b", status="unknown")
    r2 = store.start_scan_run("p1")
    store.insert_finding(scan_run_id=r2, project_id="p1", item_id="a", status="fixed")
    store.insert_finding(scan_run_id=r2, project_id="p1", item_id="b", status="unknown")
    times = store.finding_times()
    for item in ("a", "b"):
        assert times[("p1", item)] == (
            store.first_finding_time("p1", item),
            store.fixed_finding_time("p1", item),
        )
    assert times[("p1", "b")][1] is None
    assert store.open_counts_by_scan_run([r1, r2]) == {r1: 2, r2: 1}
    assert store.open_counts_by_scan_run([]) == {}
