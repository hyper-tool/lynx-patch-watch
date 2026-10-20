"""Parse Adobe Magento/Commerce APSB bulletin Affected + Solution tables.

Ported from msw ``adobe_bulletin.py``: version table parsing, product-to-package
mapping, isolated patch signal detection. msw:
src/magento_security_watcher/adobe_bulletin.py
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from lynx_patch_watch.magento_version import (
    MagentoVersion,
    bump_patch_level,
    composer_recommendable_versions,
    is_dated_security_label,
    parse_magento_version,
)
from lynx_patch_watch.models import PackageConstraint, RemediationOffer

# Product label on Adobe tables → composer package names to check.
_PRODUCT_MAP: List[Tuple[re.Pattern[str], List[str]]] = [
    (re.compile(r"magento\s+open\s+source", re.I), ["magento/product-community-edition"]),
    (
        re.compile(r"adobe\s+commerce\s+b2b", re.I),
        ["magento/module-b2b", "magento/extension-b2b"],
    ),
    (
        re.compile(r"^adobe\s+commerce$|adobe\s+commerce\s*\(", re.I),
        ["magento/product-enterprise-edition"],
    ),
    (
        re.compile(r"adobe\s+commerce\s+events", re.I),
        ["magento/commerce-eventing", "adobe-commerce/eventing"],
    ),
]

_AND_EARLIER_RE = re.compile(
    r"(?P<ver>2\.\d+\.\d+(?:-(?:p\d+|\d{4}-[a-z]{3}))?)\s+and\s+earlier",
    re.I,
)
_VER_TOKEN_RE = re.compile(
    r"\b(2\.\d+\.\d+(?:-(?:p\d+|\d{4}-[a-z]{3}))?)\b",
    re.I,
)


def map_product_to_packages(product: str) -> List[str]:
    text = (product or "").strip()
    # Prefer more specific labels first (B2B / Events before plain Commerce).
    for pattern, packages in _PRODUCT_MAP:
        if pattern.search(text):
            # Avoid matching "Adobe Commerce B2B" as plain Commerce.
            if pattern.pattern.startswith(r"^adobe\s+commerce$") and re.search(
                r"b2b|events", text, re.I
            ):
                continue
            return list(packages)
    # Fallback: if it looks like Magento/Commerce, check both product editions.
    if re.search(r"magento|commerce", text, re.I):
        return [
            "magento/product-community-edition",
            "magento/product-enterprise-edition",
        ]
    return []


def _split_version_phrases(cell: str) -> List[str]:
    text = re.sub(r"<[^>]+>", " ", cell or "")
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        return []
    # Prefer "X and earlier" spans kept intact.
    phrases: List[str] = []
    for m in _AND_EARLIER_RE.finditer(text):
        phrases.append(m.group(0))
    # Remaining bare versions not already covered.
    covered = set()
    for p in phrases:
        for t in _VER_TOKEN_RE.findall(p):
            covered.add(t.lower())
    for t in _VER_TOKEN_RE.findall(text):
        if t.lower() not in covered:
            phrases.append(t)
    return phrases


def phrase_to_constraint_bits(phrase: str) -> Optional[Tuple[str, Optional[str]]]:
    """Return (affected_versions specifier-like, suggested_fixed_version)."""
    phrase = phrase.strip()
    m = _AND_EARLIER_RE.search(phrase)
    if m:
        ver = m.group("ver")
        fixed = bump_patch_level(ver)
        return f"<={ver}", fixed
    # Bare version: that exact release line is affected until its security update.
    tok = _VER_TOKEN_RE.search(phrase)
    if not tok:
        return None
    ver = tok.group(1)
    return f"=={ver}", None


def _extract_tables(html: str) -> List[List[List[str]]]:
    """Return list of tables; each table is list of rows; each row list of cell texts."""
    tables: List[List[List[str]]] = []
    for tmatch in re.finditer(r"(?is)<table\b[^>]*>(.*?)</table>", html or ""):
        body = tmatch.group(1)
        rows: List[List[str]] = []
        for rmatch in re.finditer(r"(?is)<tr\b[^>]*>(.*?)</tr>", body):
            cells = re.findall(r"(?is)<t[hd]\b[^>]*>(.*?)</t[hd]>", rmatch.group(1))
            texts = [re.sub(r"\s+", " ", re.sub(r"(?is)<[^>]+>", " ", c)).strip() for c in cells]
            if any(texts):
                rows.append(texts)
        if rows:
            tables.append(rows)
    return tables


def _find_section_table(html: str, heading_pat: str) -> Optional[List[List[str]]]:
    """Find first HTML table after a heading matching heading_pat."""
    hm = re.search(heading_pat, html or "", flags=re.I | re.S)
    if not hm:
        return None
    tail = html[hm.end() :]
    # Next table only
    tm = re.search(r"(?is)<table\b[^>]*>(.*?)</table>", tail)
    if not tm:
        return None
    return _extract_tables(tm.group(0))[0] if _extract_tables(tm.group(0)) else None


def parse_affected_and_solution(html: str) -> Dict[str, Any]:
    """
    Parse Adobe APSB Magento bulletin version tables.

    Returns:
      {
        "packages": [PackageConstraint-like dicts],
        "recommended_min_versions": [...],
        "products": [...],
      }
    """
    affected_table = _find_section_table(html, r"<h[1-6][^>]*>\s*Affected Versions\s*</h[1-6]>")
    solution_table = _find_section_table(html, r"<h[1-6][^>]*>\s*Solution\s*</h[1-6]>")

    # Fallback: markdown-ish tables already converted (from WebFetch) — keep HTML path primary.
    if affected_table is None:
        affected_table = _parse_markdownish_affected(html)

    solution_by_core: Dict[str, str] = {}
    solution_labels: List[str] = []
    if solution_table:
        # Expect header row Product | Updated Version | ...
        for row in solution_table[1:]:
            if len(row) < 2:
                continue
            for ver in _VER_TOKEN_RE.findall(row[1]):
                solution_labels.append(ver)
                mv = parse_magento_version(ver)
                if mv:
                    core = ".".join(str(x) for x in mv.core)
                    prev = solution_by_core.get(core)
                    if prev is None or (parse_magento_version(ver) or MagentoVersion((0, 0, 0))) >= (
                        parse_magento_version(prev) or MagentoVersion((0, 0, 0))
                    ):
                        solution_by_core[core] = ver

    packages: List[Dict[str, Any]] = []
    products: List[str] = []
    baselines: List[str] = []
    if affected_table:
        for row in affected_table[1:]:
            if not row:
                continue
            product = row[0]
            version_cell = row[1] if len(row) > 1 else ""
            products.append(product)
            pkg_names = map_product_to_packages(product)
            if not pkg_names:
                continue
            for phrase in _split_version_phrases(version_cell):
                bits = phrase_to_constraint_bits(phrase)
                if not bits:
                    continue
                affected_spec, suggested_fixed = bits
                # Prefer -pN bump for composer.lock matching; keep Adobe dated
                # Solution strings as fixed_version when present (patched-state labels).
                fixed = suggested_fixed
                tok = _VER_TOKEN_RE.search(phrase)
                if tok:
                    baseline = tok.group(1)
                    if not is_dated_security_label(baseline):
                        baselines.append(baseline)
                    mv = parse_magento_version(baseline)
                    if mv:
                        core = ".".join(str(x) for x in mv.core)
                        if fixed is None and core in solution_by_core:
                            fixed = solution_by_core[core]
                for name in pkg_names:
                    packages.append(
                        {
                            "name": name,
                            "affected_versions": affected_spec,
                            "fixed_version": fixed,
                        }
                    )

    # Dedupe identical constraints
    uniq: List[Dict[str, Any]] = []
    seen = set()
    for p in packages:
        key = (p["name"], p.get("affected_versions"), p.get("fixed_version"))
        if key in seen:
            continue
        seen.add(key)
        uniq.append(p)

    # recommended_min_versions = Composer/security baselines (e.g. 2.4.8-p5),
    # NOT Solution "Updated Version" labels like 2.4.8-2026-jul.
    recommended = composer_recommendable_versions(baselines)
    if not recommended:
        recommended = composer_recommendable_versions(solution_labels)

    return {
        "packages": uniq,
        "recommended_min_versions": recommended,
        "solution_version_labels": list(dict.fromkeys(solution_labels)),
        "products": products,
        "has_affected_table": affected_table is not None,
        "has_solution_table": solution_table is not None,
    }


def _parse_markdownish_affected(text: str) -> Optional[List[List[str]]]:
    """Support plain-text / markdown tables (tests / converted pages)."""
    if not text or "Affected Versions" not in text:
        return None
    # Very small helper for fixtures that store markdown tables.
    section = text.split("Affected Versions", 1)[1]
    if "Solution" in section:
        section = section.split("Solution", 1)[0]
    rows: List[List[str]] = []
    for line in section.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        if re.match(r"^\|\s*-+", line):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if cells:
            rows.append(cells)
    return rows or None


def attach_bulletin_packages_to_seeds(
    seeds: List[Dict[str, Any]],
    html: str,
) -> List[Dict[str, Any]]:
    """Copy bulletin-level package constraints onto each CVE seed."""
    parsed = parse_affected_and_solution(html)
    packages = parsed["packages"]
    recommended = parsed["recommended_min_versions"]
    if not seeds:
        return seeds
    out: List[Dict[str, Any]] = []
    for seed in seeds:
        s = dict(seed)
        notes = (s.get("notes") or "") + " " + (s.get("title") or "")
        pkgs = list(packages)
        # B2B-only CVEs: keep B2B packages if present, else keep all.
        if re.search(r"\bb2b\b", notes, re.I):
            b2b = [p for p in pkgs if "b2b" in p["name"].lower()]
            if b2b:
                pkgs = b2b
        if not s.get("packages") and pkgs:
            s["packages"] = pkgs
        if recommended and not s.get("recommended_min_versions"):
            s["recommended_min_versions"] = recommended
        if pkgs:
            s["upgrade_available"] = True
            if s.get("has_isolated_patch"):
                s["remediation_offer"] = RemediationOffer.UPGRADE_OR_PATCH.value
            else:
                s.setdefault("remediation_offer", RemediationOffer.UPGRADE_ONLY.value)
        elif s.get("has_isolated_patch"):
            s.setdefault("remediation_offer", RemediationOffer.PATCH_ONLY.value)
        out.append(s)
    return out


_RELEASE_NOTE_ABS_RE = re.compile(
    r"https?://(?:www\.)?experienceleague\.adobe\.com/[^\s\"'<>]*/kbarticles/ka-\d+[^\s\"'<>]*",
    re.I,
)
_RELEASE_NOTE_REL_RE = re.compile(
    r'href=["\'](?P<href>/[^"\']*/kbarticles/ka-\d+[^"\']*)["\']',
    re.I,
)
_EXCLUDE_KB_RE = re.compile(
    r"upgrade-guide/modules/upgrade|cloud-patches|how-to-apply-a-composer-patch|quality-patches-tool",
    re.I,
)
_PATCH_ZIP_RE = re.compile(
    r"https?://repo\.magento\.com/patch/[^\s\"'<>]+\.zip",
    re.I,
)
_ISOLATED_TEXT_RE = re.compile(
    r"isolated\s+(?:security\s+)?patch|standalone\s+(?:security\s+)?patch|"
    r"isolat(?:ed|e)\s+security\s+fix|隔离修补|独立修补|"
    r"hotfix\s+for\s+cve-|m2-hotfixes|repo\.magento\.com/patch/",
    re.I,
)


def extract_release_note_urls(html: str, *, base_url: str = "https://experienceleague.adobe.com") -> List[str]:
    """Collect Experience League KB / Release Notes links from an APSB page."""
    found: List[str] = []
    seen: set[str] = set()

    def _add(url: str) -> None:
        url = url.strip()
        if not url or _EXCLUDE_KB_RE.search(url):
            return
        # Normalize language variants to a stable key (ka-id).
        m = re.search(r"(ka-\d+)", url, re.I)
        key = m.group(1).lower() if m else url.lower()
        if key in seen:
            return
        seen.add(key)
        if url.startswith("/"):
            url = base_url.rstrip("/") + url
        found.append(url)

    for m in _RELEASE_NOTE_ABS_RE.finditer(html or ""):
        _add(m.group(0).rstrip(").,]\"'"))
    for m in _RELEASE_NOTE_REL_RE.finditer(html or ""):
        _add(m.group("href"))
    return found


def extract_patch_zip_urls(html: str) -> List[str]:
    """repo.magento.com/patch/*.zip download links."""
    urls = []
    seen: set[str] = set()
    for m in _PATCH_ZIP_RE.finditer(html or ""):
        u = m.group(0).rstrip(").,]\"'")
        if u.lower() not in seen:
            seen.add(u.lower())
            urls.append(u)
    return urls


def detect_isolated_patch_signals(html: str) -> Dict[str, Any]:
    """Detect whether HTML documents an isolated/hotfix patch offering.

    Returns:
      has_isolated_patch: True only with strong evidence (zip links or clear wording)
      patch_zip_urls: list of zip URLs
      reasons: short tags for debugging
    """
    zip_urls = extract_patch_zip_urls(html)
    text_hit = bool(_ISOLATED_TEXT_RE.search(html or ""))
    reasons: List[str] = []
    if zip_urls:
        reasons.append("patch_zip")
    if text_hit:
        reasons.append("isolated_text")
    has_patch = bool(zip_urls) or text_hit
    return {
        "has_isolated_patch": has_patch,
        "patch_zip_urls": zip_urls,
        "reasons": reasons,
    }


def merge_patch_signals(*signals: Dict[str, Any]) -> Dict[str, Any]:
    zips: List[str] = []
    seen: set[str] = set()
    reasons: List[str] = []
    has_patch = False
    for sig in signals:
        if not sig:
            continue
        has_patch = has_patch or bool(sig.get("has_isolated_patch"))
        for r in sig.get("reasons") or []:
            if r not in reasons:
                reasons.append(r)
        for u in sig.get("patch_zip_urls") or []:
            key = str(u).lower()
            if key not in seen:
                seen.add(key)
                zips.append(u)
    return {
        "has_isolated_patch": has_patch,
        "patch_zip_urls": zips,
        "reasons": reasons,
    }


def attach_patch_signals_to_seeds(
    seeds: List[Dict[str, Any]],
    signals: Dict[str, Any],
    *,
    kb_urls: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """Stamp isolated-patch flags / zip URLs onto CVE seeds."""
    if not seeds:
        return seeds
    has_patch = bool(signals.get("has_isolated_patch"))
    zips = list(signals.get("patch_zip_urls") or [])
    out: List[Dict[str, Any]] = []
    for seed in seeds:
        s = dict(seed)
        if has_patch:
            s["has_isolated_patch"] = True
        if zips and not s.get("patch_zip_urls"):
            s["patch_zip_urls"] = zips
        if kb_urls and not s.get("patch_kb_urls"):
            s["patch_kb_urls"] = list(kb_urls)
        if has_patch and s.get("upgrade_available"):
            s["remediation_offer"] = RemediationOffer.UPGRADE_OR_PATCH.value
        elif has_patch:
            s.setdefault("remediation_offer", RemediationOffer.PATCH_ONLY.value)
        out.append(s)
    return out


def bulletin_packages_as_constraints(html: str) -> List[PackageConstraint]:
    parsed = parse_affected_and_solution(html)
    return [PackageConstraint.model_validate(p) for p in parsed["packages"]]
