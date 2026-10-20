"""Magento adapter package."""

from lynx_patch_watch.adapters.magento.source import (
    APSB_ID_RE,
    ChimeraAdvisorySource,
    ChimeraBulletin,
    DetailParse,
)

__all__ = [
    "APSB_ID_RE",
    "ChimeraAdvisorySource",
    "ChimeraBulletin",
    "DetailParse",
]
