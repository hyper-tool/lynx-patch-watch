"""Advisory ingest: chimera → store, fixture dir, --from-html, import-msw.

Key behaviours per the plan:
- advisory id regex supports 3-digit numbers (APSB26-146);
- detail pages blocked by Akamai → detail_status=blocked; advisory items are
  still created from the JSON card's CVE list (empty package data → the
  verdict engine reports unknown until manual completion);
- ``modified_at`` changes trigger a detail re-fetch;
- import-msw imports advisories + risk items only (never msw findings, so the
  lpw ledger keeps honest first-seen times).
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from lynx_patch_watch.adapters.magento.source import (
    ChimeraAdvisorySource,
    ChimeraBulletin,
    DetailParse,
)
from lynx_patch_watch.store import Store

logger = logging.getLogger(__name__)

APSB_ID_RE = re.compile(r"^APSB\d{2}-\d{2,4}$", re.IGNORECASE)


@dataclass
class IngestReport:
    advisories: int = 0
    items: int = 0
    details_ok: int = 0
    details_blocked: int = 0
    details_missing: int = 0
    refetched: int = 0
    warnings: list[str] = field(default_factory=list)


def ingest_from_source(
    store: Store,
    source: ChimeraAdvisorySource,
    *,
    refetch_unchanged: bool = False,
) -> IngestReport:
    """Fetch bulletins from the source and write advisories + items."""
    report = IngestReport()
    bulletins = source.list_bulletins()
    for bulletin in bulletins:
        existing = store.get_advisory(bulletin.advisory_id)
        need_detail = refetch_unchanged or existing is None
        if existing is not None and not refetch_unchanged:
            if (existing.get("modified_at") or "") != (bulletin.modified_at or ""):
                need_detail = True
                report.refetched += 1
        html: str | None = None
        status = "missing"
        detail: DetailParse | None = None
        if need_detail and source.detail_fetch_limit > 0:
            html, status = source.fetch_detail_html(bulletin)
        else:
            status = existing.get("detail_status") if existing else "missing"
            if status == "ok" and existing is not None:
                # keep previously parsed items; only refresh card metadata
                status = "ok"

        if html:
            detail = source.parse_detail(bulletin, html)
        elif existing is not None and status == "ok":
            # Reuse stored items when we did not re-fetch the detail page.
            _refresh_advisory_meta(store, bulletin, status)
            report.advisories += 1
            continue

        _write_bulletin(store, source, bulletin, status, detail, report)
        report.advisories += 1
        if status == "ok":
            report.details_ok += 1
        elif status == "blocked":
            report.details_blocked += 1
        else:
            report.details_missing += 1
    return report


def _refresh_advisory_meta(store: Store, bulletin: ChimeraBulletin, status: str) -> None:
    store.upsert_advisory(
        {
            "id": bulletin.advisory_id,
            "product": "Adobe Commerce",
            "title": bulletin.title,
            "priority": bulletin.priority,
            "published_at": bulletin.published_at,
            "modified_at": bulletin.modified_at,
            "url": bulletin.url,
            "raw_json": {"card": bulletin.raw_card},
            "detail_status": status,
        }
    )


def _write_bulletin(
    store: Store,
    source: ChimeraAdvisorySource,
    bulletin: ChimeraBulletin,
    status: str,
    detail: DetailParse | None,
    report: IngestReport,
) -> None:
    store.upsert_advisory(
        {
            "id": bulletin.advisory_id,
            "product": "Adobe Commerce",
            "title": bulletin.title,
            "priority": bulletin.priority,
            "published_at": bulletin.published_at,
            "modified_at": bulletin.modified_at,
            "url": bulletin.url,
            "raw_json": {"card": bulletin.raw_card},
            "detail_status": status,
        }
    )
    cves = list(bulletin.cves)
    if detail is not None and detail.ok:
        for cve in detail.cve_details:
            if cve not in cves:
                cves.append(cve)
    if not cves:
        report.warnings.append(
            f"{bulletin.advisory_id}: no CVEs on card and no detail page; no items created"
        )
        return
    for cve in sorted(cves):
        seed = source.build_seed(bulletin, cve, detail)
        fix_kind = source.item_fix_kind(seed, detail, cve)
        from lynx_patch_watch.sources_cve import seed_to_analysis

        analysis = seed_to_analysis(seed, "")
        item_id = f"{bulletin.advisory_id}:{cve}"
        store.upsert_advisory_item(
            {
                "item_id": item_id,
                "advisory_id": bulletin.advisory_id,
                "cve_id": cve,
                "severity": analysis.severity.value,
                "cvss": analysis.score,
                "packages": [p.model_dump() for p in analysis.packages],
                "fix_kind": fix_kind,
                "fingerprints": [f.model_dump() for f in analysis.fingerprints],
                "title": analysis.title,
            }
        )
        report.items += 1


def ingest_from_html_file(store: Store, html_path: Path) -> IngestReport:
    """Ingest a single browser-saved bulletin detail page (--from-html)."""
    report = IngestReport()
    html = html_path.read_text(encoding="utf-8", errors="replace")
    bulletin = _bulletin_from_html(html)
    if bulletin is None:
        raise RuntimeError(
            f"No APSB bulletin id found in {html_path}; expected e.g. APSB26-146 in the page."
        )
    source = ChimeraAdvisorySource(chimera_url="unused")
    detail = source.parse_detail(bulletin, html)
    _write_bulletin(store, source, bulletin, "ok", detail, report)
    report.advisories += 1
    report.details_ok += 1
    return report


def _bulletin_from_html(html: str) -> ChimeraBulletin | None:
    from lynx_patch_watch.sources_cve import extract_apsb_ids

    ids = extract_apsb_ids(html)
    if not ids:
        return None
    advisory_id = ids[0].upper()
    title_m = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    title = re.sub(r"\s+", " ", title_m.group(1)).strip() if title_m else advisory_id
    cves = re.findall(r"CVE-\d{4}-\d{4,}", html, re.IGNORECASE)
    return ChimeraBulletin(
        advisory_id=advisory_id,
        title=title or advisory_id,
        url=None,
        priority=None,
        published_at=None,
        modified_at=None,
        cves=sorted({c.upper() for c in cves}),
        raw_card={},
    )


# ---------------------------------------------------------------------------
# import-msw
# ---------------------------------------------------------------------------


def import_msw(store: Store, msw_db_path: Path) -> dict[str, int]:
    """Import advisories + risk items from an msw SQLite database.

    msw findings are deliberately NOT imported: their first-seen timestamps
    would pollute the lpw ledger.
    """
    src = sqlite3.connect(f"file:{msw_db_path}?mode=ro", uri=True)
    src.row_factory = sqlite3.Row
    counts = {"advisories": 0, "items": 0}
    try:
        bulletins = src.execute("SELECT * FROM bulletins").fetchall()
        for row in bulletins:
            b = dict(row)
            advisory_id = b["external_id"]
            if not APSB_ID_RE.match(advisory_id):
                logger.warning("skipping non-APSB msw bulletin %s", advisory_id)
                continue
            store.upsert_advisory(
                {
                    "id": advisory_id,
                    "product": "Adobe Commerce",
                    "title": b.get("title") or advisory_id,
                    "priority": None,
                    "published_at": b.get("published_at"),
                    "modified_at": None,
                    "url": b.get("url"),
                    "raw_json": {"raw_text": (b.get("raw_text") or "")[:50000]},
                    "detail_status": "ok",
                }
            )
            counts["advisories"] += 1
            items = src.execute(
                "SELECT * FROM risk_items WHERE bulletin_external_id=?", (advisory_id,)
            ).fetchall()
            for item in items:
                if _import_msw_risk_item(store, advisory_id, dict(item)):
                    counts["items"] += 1
    finally:
        src.close()
    return counts


def _import_msw_risk_item(store: Store, advisory_id: str, row: dict[str, Any]) -> bool:
    try:
        analysis = json.loads(row.get("analysis_json") or "{}")
    except json.JSONDecodeError:
        return False
    cves = [str(c).upper() for c in analysis.get("cve_ids") or []]
    cve = cves[0] if cves else None
    if not cve:
        # Fall back to the risk id slug when no CVE is present.
        slug = re.sub(r"[^a-z0-9]+", "-", (row.get("risk_id") or "").lower()).strip("-")
        cve = slug or "unknown"
    item_id = f"{advisory_id}:{cve}"
    packages = analysis.get("packages") or []
    opts = analysis.get("remediation_options") or {}
    has_patch = bool(opts.get("has_isolated_patch"))
    has_upgrade = bool(opts.get("upgrade_available")) or bool(packages)
    if has_patch and has_upgrade:
        fix_kind = "both"
    elif has_patch:
        fix_kind = "hotfix"
    elif has_upgrade:
        fix_kind = "upgrade"
    else:
        fix_kind = None
    store.upsert_advisory_item(
        {
            "item_id": item_id,
            "advisory_id": advisory_id,
            "cve_id": cve,
            "severity": analysis.get("severity") or "unknown",
            "cvss": analysis.get("score"),
            "packages": packages,
            "fix_kind": fix_kind,
            "fingerprints": analysis.get("fingerprints") or [],
            "title": analysis.get("title") or item_id,
        }
    )
    return True
