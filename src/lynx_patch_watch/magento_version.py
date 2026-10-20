"""Magento-style version parsing (2.4.8-p5, 2.4.8-2026-jul) for deterministic matching.

Ported verbatim from msw ``magento_version.py``. msw:
src/magento_security_watcher/magento_version.py
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

_CORE_RE = re.compile(
    r"^(?P<core>\d+\.\d+\.\d+)(?:-(?:p(?P<p>\d+)|(?P<y>\d{4})-(?P<mon>[a-z]{3})))?$",
    re.IGNORECASE,
)

_MONTHS = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}


@dataclass(frozen=True, order=True)
class MagentoVersion:
    """Comparable Magento product version within a release line.

    Adobe bulletin phrases like "2.4.7-p7 and earlier" apply only to the
    2.4.7.* line — not to 2.4.6 or 2.4.8. Comparisons that cross cores are
    handled by callers (same_core checks).
    """

    core: tuple[int, int, int]
    patch: int = 0
    # 0 = none; dated hotfixes use year*12+month so they sort after -pN for same core
    rank: int = 0

    @property
    def text(self) -> str:
        a, b, c = self.core
        if self.rank and self.rank >= 10_000:
            return f"{a}.{b}.{c}-hotfix-{self.rank}"
        if self.patch:
            return f"{a}.{b}.{c}-p{self.patch}"
        return f"{a}.{b}.{c}"


def parse_magento_version(value: str) -> Optional[MagentoVersion]:
    if not value:
        return None
    text = value.strip().lstrip("v").lower()
    m = _CORE_RE.match(text)
    if not m:
        return None
    parts = tuple(int(x) for x in m.group("core").split("."))
    if len(parts) != 3:
        return None
    if m.group("p") is not None:
        return MagentoVersion(core=parts, patch=int(m.group("p")), rank=int(m.group("p")))
    if m.group("y") and m.group("mon"):
        mon = _MONTHS.get(m.group("mon").lower())
        if mon is None:
            return None
        rank = 10_000 + int(m.group("y")) * 12 + mon
        return MagentoVersion(core=parts, patch=rank, rank=rank)
    return MagentoVersion(core=parts, patch=0, rank=0)


def same_release_line(a: str, b: str) -> bool:
    """True when both versions share Magento core X.Y.Z (e.g. both 2.4.7.*)."""
    va = parse_magento_version(a)
    vb = parse_magento_version(b)
    if va is None or vb is None:
        return False
    return va.core == vb.core


def newer_release_line(current: str, reference: str) -> Optional[bool]:
    """True when current Magento core is strictly newer than reference core.

    Example: 2.4.7-p8 is newer than 2.4.6 / 2.4.6-p15 — a 2.4.6-line bulletin
    does not apply to 2.4.7.
    """
    cur = parse_magento_version(current)
    ref = parse_magento_version(reference)
    if cur is None or ref is None:
        return None
    return cur.core > ref.core


def magento_gte(current: str, minimum: str) -> Optional[bool]:
    """current >= minimum, only meaningful on the same release line."""
    cur = parse_magento_version(current)
    mn = parse_magento_version(minimum)
    if cur is None or mn is None:
        return None
    if cur.core != mn.core:
        return False
    return cur >= mn


def magento_lte(current: str, maximum: str) -> Optional[bool]:
    """current <= maximum, only meaningful on the same release line.

    Cross-line (e.g. 2.4.7-p8 vs 2.4.8-p5) → False: not in that line's range.
    """
    cur = parse_magento_version(current)
    mx = parse_magento_version(maximum)
    if cur is None or mx is None:
        return None
    if cur.core != mx.core:
        return False
    return cur <= mx


def bump_patch_level(version: str) -> Optional[str]:
    """2.4.8-p5 → 2.4.8-p6; 2.4.8 → 2.4.8-p1."""
    mv = parse_magento_version(version)
    if mv is None:
        return None
    a, b, c = mv.core
    if mv.rank >= 10_000:
        return None
    return f"{a}.{b}.{c}-p{mv.patch + 1}"


_DATED_HOTFIX_RE = re.compile(r"^\d+\.\d+\.\d+-\d{4}-[a-z]{3}$", re.I)


def is_dated_security_label(version: str) -> bool:
    """True for Adobe Solution labels like 2.4.8-2026-jul (not Composer package ids)."""
    return bool(_DATED_HOTFIX_RE.match((version or "").strip()))


def composer_recommendable_versions(versions: list[str]) -> list[str]:
    """Drop YYYY-mon hotfix labels; keep 2.4.x / 2.4.x-pN for display & Composer advice."""
    out: list[str] = []
    for v in versions or []:
        text = str(v).strip()
        if not text or is_dated_security_label(text):
            continue
        if text not in out:
            out.append(text)
    return out
