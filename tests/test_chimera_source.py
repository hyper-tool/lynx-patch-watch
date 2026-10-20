"""Chimera advisory source + ingest tests (fixture-driven)."""

from __future__ import annotations

import json
from pathlib import Path

from lynx_patch_watch.adapters.magento.source import ChimeraAdvisorySource
from lynx_patch_watch.engine.ingest import ingest_from_source, ingest_from_html_file
from lynx_patch_watch.store import Store

FIXTURES = Path(__file__).parent / "fixtures" / "advisories"


def _source() -> ChimeraAdvisorySource:
    return ChimeraAdvisorySource(
        chimera_url="unused",
        fixture_dir=FIXTURES,
        detail_fetch_limit=15,
    )


def test_chimera_fixture_lists_seven_commerce_bulletins():
    bulletins = _source().list_bulletins()
    ids = [b.advisory_id for b in bulletins]
    assert len(ids) == 7
    assert set(ids) == {
        "APSB26-05",
        "APSB26-49",
        "APSB26-73",
        "APSB26-92",
        "APSB26-138",
        "APSB26-146",
        "APSB26-153",
    }


def test_chimera_card_fields():
    source = _source()
    bulletins = {b.advisory_id: b for b in source.list_bulletins()}
    b = bulletins["APSB26-146"]
    assert b.priority == "1"
    assert b.published_at == "2026-09-07T00:00:00.000Z"
    assert b.modified_at  # non-empty; re-fetch triggers on change
    assert b.cves == ["CVE-2026-75650"]
    assert b.url.endswith("/commerce/apsb26-146")
    # non-commerce cards are filtered out
    assert not any("substance" in (bb.url or "").lower() for bb in bulletins.values())


def test_ingest_from_fixture_dir(store: Store):
    source = _source()
    report = ingest_from_source(store, source)
    assert report.advisories == 7
    # Two saved detail pages exist in the fixture dir (APSB26-146 + APSB26-73).
    assert report.details_ok == 2
    assert report.details_missing == 5
    adv = store.get_advisory("APSB26-146")
    assert adv["detail_status"] == "ok"
    item = store.get_advisory_item("APSB26-146:CVE-2026-75650")
    assert item is not None
    assert item["fix_kind"] == "hotfix"
    assert item["severity"] == "critical"
    assert item["cvss"] == 10.0
    assert item["packages"], "hotfix bulletin still records affected package ranges"
    # APSB26-73 detail page carries version constraints
    other = store.get_advisory_item("APSB26-73:CVE-2026-48356")
    assert other is not None
    assert other["packages"], "APSB26-73 detail page provides package constraints"
    assert any(p.get("fixed_version") for p in other["packages"])
    # card-only advisories keep their CVE list but no package data
    card_only = store.get_advisory_item("APSB26-05:CVE-2026-21361")
    assert card_only is not None
    assert card_only["packages"] == []


def test_ingest_modified_at_triggers_refetch(store: Store, tmp_path: Path):
    fixture = tmp_path / "fixtures"
    fixture.mkdir()
    for path in FIXTURES.iterdir():
        (fixture / path.name).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    source = ChimeraAdvisorySource(chimera_url="unused", fixture_dir=fixture, detail_fetch_limit=15)
    first = ingest_from_source(store, source)
    assert first.refetched == 0

    # Bump modifiedDate on the APSB26-146 card in the copied collection.
    collection = fixture / "chimera_collection_snippet.json"
    data = json.loads(collection.read_text(encoding="utf-8"))
    for card in data["cards"]:
        if (card.get("contentArea") or {}).get("title") == "APSB26-146":
            card["modifiedDate"] = "2026-10-01T00:00:00.000Z"
    collection.write_text(json.dumps(data), encoding="utf-8")

    report = ingest_from_source(store, source)
    assert report.refetched == 1
    assert store.get_advisory("APSB26-146")["modified_at"] == "2026-10-01T00:00:00.000Z"


def test_ingest_from_html_file(store: Store):
    report = ingest_from_html_file(store, FIXTURES / "apsb26-146-snippet.html")
    assert report.advisories == 1
    assert report.items >= 1
    item = store.get_advisory_item("APSB26-146:CVE-2026-75650")
    assert item is not None
    assert item["fix_kind"] == "hotfix"


def test_apsb_id_regex_supports_three_digits():
    from lynx_patch_watch.adapters.magento.source import APSB_ID_RE

    assert APSB_ID_RE.match("APSB26-146")
    assert APSB_ID_RE.match("APSB26-05")
    assert APSB_ID_RE.match("APSB26-1535")
    assert not APSB_ID_RE.match("APSB26-1")  # too short
    from lynx_patch_watch.sources_cve import extract_apsb_ids

    assert extract_apsb_ids("see APSB26-146 and apsb26-05") == ["APSB26-146", "APSB26-05"]
