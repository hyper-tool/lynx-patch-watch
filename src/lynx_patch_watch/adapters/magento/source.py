"""Adobe Commerce bulletin source (chimera CaaS collection + detail pages).

The bulletins listing page loads its cards from Adobe's chimera collection API:

    https://www.adobe.com/chimera-api/collection?originSelection=hawks
        &contentTypeTags=caas:content-type/documentation
        &collectionTags=caas:trust-center/security-bulletin
        &...&size=250

Each card carries contentArea.{title,url,description,detailText},
search.search (CVE list), cardDate (published) and modifiedDate.

Detail pages live at
https://www.adobe.com/trust/security/products/commerce/<apsb-id>.html and are
parsed with the ported adobe_bulletin helpers. Adobe's Akamai often blocks CLI
fetches of detail pages (403); the caller then records detail_status=blocked
and only the JSON card is used to build advisory items.

Offline alternatives: advisory.fixture_dir (collection.json + saved detail
pages) and `lpw ingest --from-html FILE`.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from lynx_patch_watch.adobe_bulletin import (
    attach_bulletin_packages_to_seeds,
    attach_patch_signals_to_seeds,
    detect_isolated_patch_signals,
    extract_release_note_urls,
    map_product_to_packages,
    merge_patch_signals,
    parse_affected_and_solution,
    phrase_to_constraint_bits,
    _split_version_phrases,
)
from lynx_patch_watch.browser_identity import BROWSER_USER_AGENT
from lynx_patch_watch.http_fetch import fetch_text
from lynx_patch_watch.models import RemediationOffer
from lynx_patch_watch.sources_cve import (
    extract_bulletin_cves,
    extract_vuln_detail_by_cve,
    options_from_offer,
    seed_to_analysis,
)

logger = logging.getLogger(__name__)

APSB_ID_RE = re.compile(r"^APSB\d{2}-\d{2,4}$", re.IGNORECASE)
_HOTFIX_FOR_CVE_RE = re.compile(r"hotfix\s+for\s+(cve-\d{4}-\d{4,})", re.IGNORECASE)


@dataclass
class ChimeraBulletin:
    """One Commerce bulletin card from the chimera collection."""

    advisory_id: str
    title: str
    url: str | None
    priority: str | None
    published_at: str | None
    modified_at: str | None
    cves: list[str] = field(default_factory=list)
    raw_card: dict[str, Any] = field(default_factory=dict)


@dataclass
class DetailParse:
    """Parsed detail page for one bulletin."""

    ok: bool
    blocked: bool = False
    packages: list[dict[str, Any]] = field(default_factory=list)
    cve_details: dict[str, dict[str, Any]] = field(default_factory=dict)
    hotfix_cves: list[str] = field(default_factory=list)
    has_isolated_patch: bool = False
    recommended_min_versions: list[str] = field(default_factory=list)
    solution_labels: list[str] = field(default_factory=list)


class ChimeraAdvisorySource:
    """Fetch Commerce bulletins from the chimera collection + detail pages."""

    def __init__(
        self,
        *,
        chimera_url: str,
        commerce_mnemonic: str = "caas:mnemonics/adobe-commerce",
        detail_url_template: str = "https://www.adobe.com/trust/security/products/commerce/{aid_lower}",
        user_agent: str = BROWSER_USER_AGENT,
        request_timeout_seconds: float = 45.0,
        detail_fetch_limit: int = 15,
        follow_release_notes: bool = True,
        kb_fetch_limit_per_bulletin: int = 2,
        fixture_dir: Path | None = None,
        local_index_html: Path | None = None,
    ) -> None:
        self.chimera_url = chimera_url
        self.commerce_mnemonic = commerce_mnemonic
        self.detail_url_template = detail_url_template
        self.user_agent = user_agent
        self.request_timeout_seconds = request_timeout_seconds
        self.detail_fetch_limit = detail_fetch_limit
        self.follow_release_notes = follow_release_notes
        self.kb_fetch_limit_per_bulletin = kb_fetch_limit_per_bulletin
        self.fixture_dir = Path(fixture_dir) if fixture_dir else None
        self.local_index_html = Path(local_index_html) if local_index_html else None

    # ------------------------------------------------------------------
    # listing
    # ------------------------------------------------------------------

    def list_bulletins(self) -> list[ChimeraBulletin]:
        """Return Commerce bulletin cards (fixture dir or live chimera API)."""
        cards = self._load_cards()
        bulletins: list[ChimeraBulletin] = []
        for card in cards:
            bulletin = self._card_to_bulletin(card)
            if bulletin is not None:
                bulletins.append(bulletin)
        bulletins.sort(key=lambda b: b.advisory_id, reverse=True)
        return bulletins

    def _load_cards(self) -> list[dict[str, Any]]:
        if self.fixture_dir is not None:
            return self._load_fixture_cards()
        fetched = fetch_text(
            self.chimera_url,
            user_agent=self.user_agent,
            timeout=self.request_timeout_seconds,
        )
        if fetched.status_code >= 400:
            raise RuntimeError(
                f"chimera collection returned HTTP {fetched.status_code}: {self.chimera_url}"
            )
        try:
            data = json.loads(fetched.text)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"chimera collection is not valid JSON: {exc}") from exc
        cards = data.get("cards") if isinstance(data, dict) else None
        if not isinstance(cards, list):
            raise RuntimeError("chimera collection JSON has no 'cards' list")
        return cards

    def _load_fixture_cards(self) -> list[dict[str, Any]]:
        assert self.fixture_dir is not None
        cards: list[dict[str, Any]] = []
        for path in sorted(self.fixture_dir.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("skipping unreadable fixture %s: %s", path, exc)
                continue
            if isinstance(data, dict) and isinstance(data.get("cards"), list):
                cards.extend(data["cards"])
            elif isinstance(data, list):
                cards.extend(data)
        return cards

    def _card_to_bulletin(self, card: dict[str, Any]) -> ChimeraBulletin | None:
        content = card.get("contentArea") or {}
        if not isinstance(content, dict):
            return None
        if content.get("detailText") != self.commerce_mnemonic:
            return None
        raw_id = (content.get("title") or "").strip()
        if not raw_id:
            return None
        advisory_id = raw_id.upper()
        if not APSB_ID_RE.match(advisory_id):
            logger.debug("skipping non-APSB commerce card: %s", raw_id)
            return None
        url = content.get("url") or card.get("ctaLink") or self.detail_url(advisory_id)
        cves = _parse_cve_list((card.get("search") or {}).get("search") or "")
        return ChimeraBulletin(
            advisory_id=advisory_id,
            title=(content.get("description") or advisory_id).strip() or advisory_id,
            url=url,
            priority=_parse_priority(content.get("description")),
            published_at=card.get("cardDate"),
            modified_at=card.get("modifiedDate"),
            cves=cves,
            raw_card=card,
        )

    def detail_url(self, advisory_id: str) -> str:
        return self.detail_url_template.format(aid_lower=advisory_id.lower())

    # ------------------------------------------------------------------
    # detail pages
    # ------------------------------------------------------------------

    def fetch_detail_html(self, bulletin: ChimeraBulletin) -> tuple[str | None, str]:
        """Return (html, status) where status is ok | blocked | missing."""
        if self.fixture_dir is not None:
            assert self.fixture_dir is not None
            aid = bulletin.advisory_id.lower()
            for path in sorted(self.fixture_dir.glob("*.html")):
                if aid in path.name.lower():
                    return path.read_text(encoding="utf-8", errors="replace"), "ok"
            return None, "missing"
        if not bulletin.url:
            return None, "missing"
        try:
            fetched = fetch_text(
                bulletin.url,
                user_agent=self.user_agent,
                timeout=self.request_timeout_seconds,
                prefer_curl=True,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("detail fetch failed for %s: %s", bulletin.advisory_id, exc)
            return None, "blocked"
        if fetched.status_code == 403 or fetched.status_code == 401:
            return None, "blocked"
        if fetched.status_code >= 400 or not fetched.text.strip():
            return None, "missing"
        return fetched.text, "ok"

    def parse_detail(self, bulletin: ChimeraBulletin, html: str) -> DetailParse:
        """Parse a bulletin detail page into packages / CVE details / fix kinds."""
        parsed = parse_affected_and_solution(html)
        packages = list(parsed["packages"])
        cve_details = extract_vuln_detail_by_cve(html)
        hotfix_cves: list[str] = []

        # "Hotfix for CVE-XXXX-YYYY" in the Solution table → hotfix fix kind.
        solution_scope = _extract_section_text(html, "Solution")
        if solution_scope:
            for m in _HOTFIX_FOR_CVE_RE.finditer(solution_scope):
                hotfix_cves.append(m.group(1).upper())

        # Hotfix wording anywhere on the page marks the bulletin as patched-only
        # when no version table exists (APSB26-146 shape).
        if not packages:
            for cve in extract_bulletin_cves(html):
                if re.search(rf"hotfix\s+for\s+{re.escape(cve)}", html, re.IGNORECASE):
                    hotfix_cves.append(cve.upper())

        signals = detect_isolated_patch_signals(html)
        if self.follow_release_notes and self.fixture_dir is None and not signals.get("has_isolated_patch"):
            for url in extract_release_note_urls(html)[: max(0, self.kb_fetch_limit_per_bulletin)]:
                try:
                    kb = fetch_text(
                        url,
                        user_agent=self.user_agent,
                        timeout=self.request_timeout_seconds,
                        prefer_curl=True,
                    )
                except Exception:  # noqa: BLE001
                    continue
                if kb.status_code < 400:
                    signals = merge_patch_signals(signals, detect_isolated_patch_signals(kb.text))
                    if signals.get("has_isolated_patch"):
                        break

        return DetailParse(
            ok=True,
            packages=packages,
            cve_details=cve_details,
            hotfix_cves=sorted(set(hotfix_cves)),
            has_isolated_patch=bool(signals.get("has_isolated_patch")),
            recommended_min_versions=parsed["recommended_min_versions"],
            solution_labels=parsed["solution_version_labels"],
        )

    def build_seed(self, bulletin: ChimeraBulletin, cve: str, detail: DetailParse | None) -> dict[str, Any]:
        """Build one advisory-item seed (packages + fix kinds) for a CVE."""
        seed: dict[str, Any] = {
            "title": f"{bulletin.advisory_id} {cve}",
            "cve_ids": [cve],
            "severity": "unknown",
        }
        if detail is not None and detail.ok:
            row = detail.cve_details.get(cve) or {}
            if row.get("severity"):
                seed["severity"] = row["severity"]
            if row.get("score") is not None:
                seed["score"] = row["score"]
                seed["score_source"] = "adobe-bulletin"
            if row.get("category"):
                seed["vuln_category"] = row["category"]
            if row.get("impact"):
                seed["vuln_impact"] = row["impact"]
            if detail.packages:
                # B2B-only CVEs keep only B2B packages (same rule as msw).
                pkgs = list(detail.packages)
                notes = f"{seed.get('title')} {row.get('impact') or ''}"
                if re.search(r"\bb2b\b", notes, re.IGNORECASE):
                    b2b = [p for p in pkgs if "b2b" in p["name"].lower()]
                    if b2b:
                        pkgs = b2b
                seed["packages"] = pkgs
                # Upgrade evidence needs a fixed version; APSB26-146-style
                # bulletins only offer affected ranges + a hotfix.
                if any(p.get("fixed_version") for p in pkgs):
                    seed["upgrade_available"] = True
                    seed.setdefault("remediation_offer", RemediationOffer.UPGRADE_ONLY.value)
            if detail.has_isolated_patch:
                seed["has_isolated_patch"] = True
            if detail.recommended_min_versions:
                seed["recommended_min_versions"] = list(detail.recommended_min_versions)
            if cve in detail.hotfix_cves:
                seed["fix_kind"] = "hotfix"
                seed["hotfix"] = True
            elif detail.has_isolated_patch:
                seed["fix_kind"] = "patch"
            elif detail.packages:
                seed["fix_kind"] = "upgrade"
        return seed

    def item_fix_kind(self, seed: dict[str, Any], detail: DetailParse | None, cve: str) -> str | None:
        """upgrade | hotfix | both | None.

        Upgrade evidence requires a fixed *version* — affected-version ranges
        alone (APSB26-146 shape) do not count as an upgrade offer.
        """
        has_upgrade = any(p.get("fixed_version") for p in seed.get("packages") or [])
        has_hotfix = bool(detail and detail.ok and (cve in detail.hotfix_cves or detail.has_isolated_patch))
        if has_upgrade and has_hotfix:
            return "both"
        if has_hotfix:
            return "hotfix"
        if has_upgrade:
            return "upgrade"
        return None


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

_CVE_SPLIT_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def _parse_cve_list(text: str) -> list[str]:
    return [c.upper() for c in _CVE_SPLIT_RE.findall(text or "")]


def _parse_priority(description: str | None) -> str | None:
    m = re.search(r"priority\s+(\d+)", description or "", re.IGNORECASE)
    return m.group(1) if m else None


def _extract_section_text(html: str, heading: str) -> str:
    m = re.search(rf"(?is)<h[1-6][^>]*>\s*{re.escape(heading)}\s*</h[1-6]>(.*?)(?=<h[1-6]\b|$)", html or "")
    return m.group(1) if m else ""
