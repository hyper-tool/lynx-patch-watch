"""CVE-table parsing ported from msw ``sources.py``.

Ported: ``extract_bulletin_cves``, ``extract_vuln_detail_by_cve``,
``_adobe_severity_token``, ``_parse_score_token``, ``options_from_offer``,
``seed_to_analysis``. msw: src/magento_security_watcher/sources.py

Plan note: the APSB id regex is widened to ``APSB\\d{2}-\\d{2,4}`` so
three-digit bulletin numbers (e.g. APSB26-146) are not truncated to
APSB26-14.
"""

from __future__ import annotations

import re
from typing import Any

from lynx_patch_watch.models import (
    PackageConstraint,
    RemediationOffer,
    RemediationOptions,
    RiskItemAnalysis,
    Severity,
    SourceMaterial,
)

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
# Widened from msw's \d{2}-\d{2}: Adobe now issues 3-digit bulletin numbers.
_APSB_RE = re.compile(r"APSB\d{2}-\d{2,4}", re.IGNORECASE)
_VULN_DETAILS_RE = re.compile(
    r"(?is)<h[1-6][^>]*>\s*Vulnerability Details\s*</h[1-6]>(.*?)(?=<h[1-6]\b|$)",
)


def options_from_offer(offer: RemediationOffer) -> RemediationOptions:
    """Map legacy aggregate remediation_offer into independent flags."""
    if offer == RemediationOffer.UPGRADE_OR_PATCH:
        return RemediationOptions(has_isolated_patch=True, upgrade_available=True)
    if offer == RemediationOffer.PATCH_ONLY:
        return RemediationOptions(has_isolated_patch=True, upgrade_available=False)
    if offer == RemediationOffer.UPGRADE_ONLY:
        return RemediationOptions(has_isolated_patch=False, upgrade_available=True)
    return RemediationOptions()


def extract_bulletin_cves(html: str) -> list[str]:
    """Prefer CVEs inside Vulnerability Details; fall back to full page."""
    if not html:
        return []
    scope = html
    m = _VULN_DETAILS_RE.search(html)
    if m and m.group(1).strip():
        scoped = sorted({c.upper() for c in _CVE_RE.findall(m.group(1))})
        if scoped:
            return scoped
    return sorted({c.upper() for c in _CVE_RE.findall(html)})


def extract_apsb_ids(text: str) -> list[str]:
    """All APSB ids in text, uppercased; supports 2-4 digit sequence numbers."""
    return [m.upper() for m in _APSB_RE.findall(text or "")]


def _adobe_severity_token(text: str) -> str | None:
    low = (text or "").strip().lower()
    return {
        "critical": "critical",
        "important": "high",
        "moderate": "medium",
        "low": "low",
    }.get(low)


def _parse_score_token(text: str) -> float | None:
    t = (text or "").strip()
    if re.fullmatch(r"\d+(?:\.\d+)?", t):
        try:
            return float(t)
        except ValueError:
            return None
    return None


def extract_vuln_detail_by_cve(html: str) -> dict[str, dict[str, Any]]:
    """
    Parse Vulnerability Details table rows → CVE → {category, impact, severity, score}.

    Adobe columns are typically:
    Vulnerability Category | Vulnerability Impact | Severity | … | CVE number(s)
    """
    mapping: dict[str, dict[str, Any]] = {}
    scope = html or ""
    m = _VULN_DETAILS_RE.search(scope)
    if m and m.group(1).strip():
        scope = m.group(1)

    header_idx: dict[str, int] = {}
    for row_html in re.findall(r"(?is)<tr\b[^>]*>(.*?)</tr>", scope):
        cells = re.findall(r"(?is)<t[hd]\b[^>]*>(.*?)</t[hd]>", row_html)
        texts = [re.sub(r"\s+", " ", re.sub(r"(?is)<[^>]+>", " ", c)).strip() for c in cells]
        if not texts:
            continue
        # Header row: learn column indexes.
        joined = " ".join(texts).lower()
        if "cve" in joined and ("category" in joined or "severity" in joined or "impact" in joined):
            header_idx = {}
            for i, t in enumerate(texts):
                low = t.lower()
                if "category" in low:
                    header_idx["category"] = i
                elif "impact" in low:
                    header_idx["impact"] = i
                elif "severity" in low:
                    header_idx["severity"] = i
                elif "cvss" in low and "score" in low:
                    header_idx["score"] = i
                elif "cve" in low:
                    header_idx["cve"] = i
            continue

        cves = [c.upper() for c in _CVE_RE.findall(row_html)]
        if not cves:
            continue

        category = None
        impact = None
        sev = None
        score = None
        if header_idx:
            if "category" in header_idx and header_idx["category"] < len(texts):
                category = texts[header_idx["category"]] or None
            if "impact" in header_idx and header_idx["impact"] < len(texts):
                impact = texts[header_idx["impact"]] or None
            if "severity" in header_idx and header_idx["severity"] < len(texts):
                sev = _adobe_severity_token(texts[header_idx["severity"]])
            if "score" in header_idx and header_idx["score"] < len(texts):
                score = _parse_score_token(texts[header_idx["score"]])
        else:
            # Fallback: first cell = category, second = impact (Adobe layout).
            if texts:
                category = texts[0] or None
            if len(texts) > 1:
                impact = texts[1] or None
            for t in texts:
                if sev is None:
                    sev = _adobe_severity_token(t)
                if score is None:
                    score = _parse_score_token(t)

        payload = {
            "category": category,
            "impact": impact,
            "severity": sev,
            "score": score,
        }
        for cve in cves:
            mapping[cve] = payload
    return mapping


def seed_to_analysis(seed: dict[str, Any], bulletin_text: str) -> RiskItemAnalysis:
    """Port of msw sources.seed_to_analysis (kept for test + source parity)."""
    cves = [c.upper() for c in seed.get("cve_ids") or []]
    packages = [
        PackageConstraint.model_validate(p) for p in (seed.get("packages") or [])
    ]
    offer_raw = seed.get("remediation_offer") or "unknown"
    try:
        offer = RemediationOffer(offer_raw)
    except ValueError:
        offer = RemediationOffer.UNKNOWN
    opts = options_from_offer(offer)
    # Explicit independent flags override legacy offer mapping.
    if seed.get("has_isolated_patch") is True:
        opts.has_isolated_patch = True
    if seed.get("has_isolated_patch") is False:
        opts.has_isolated_patch = False
    if seed.get("upgrade_available") is True:
        opts.upgrade_available = True
    if seed.get("upgrade_available") is False:
        opts.upgrade_available = False
    mins = seed.get("recommended_min_versions") or []
    if isinstance(mins, list) and mins:
        opts.recommended_min_versions = [str(x) for x in mins]
    elif packages:
        # Deterministic hint: package fixed_version is a min upgrade target.
        fixed = [p.fixed_version for p in packages if p.fixed_version]
        if fixed:
            opts.upgrade_available = True
            if not opts.recommended_min_versions:
                opts.recommended_min_versions = list(dict.fromkeys(fixed))
    offer = opts.to_offer() if (opts.has_isolated_patch or opts.upgrade_available) else offer
    sev_raw = (seed.get("severity") or "unknown").lower()
    try:
        severity = Severity(sev_raw)
    except ValueError:
        severity = Severity.UNKNOWN
    return RiskItemAnalysis(
        title=seed.get("title") or (cves[0] if cves else "Untitled risk"),
        cve_ids=cves,
        severity=severity,
        score=seed.get("score"),
        score_source=seed.get("score_source"),
        business_impact=seed.get("business_impact"),
        technical_summary=seed.get("technical_summary"),
        remediation_offer=offer,
        remediation_options=opts,
        packages=packages,
        materials=[
            SourceMaterial(kind="official", excerpt=(bulletin_text or "")[:2000]),
        ],
        confidence=float(seed.get("confidence") or 0.3),
        raw=seed,
    )
