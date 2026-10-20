"""Composer inventory readers.

Ported from msw ``inventory.py``: ``load_composer_lock_packages``,
``load_composer_json_product_versions``, ``detect_magento_product_version``,
``merge_installed_for_matching``, ``MagentoInventory``. msw:
src/magento_security_watcher/inventory.py

Plan note: JSON parse errors in composer.lock are now tolerated (returns {}).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


_PRODUCT_KEYS = (
    "magento/product-community-edition",
    "magento/product-enterprise-edition",
    "magento/magento2-base",
)

_PRODUCT_VERSION_RE = re.compile(
    r"['\"]version['\"]\s*=>\s*['\"](?P<ver>[^'\"]+)['\"]",
    re.MULTILINE,
)


def load_composer_lock_packages(workspace: Path) -> dict[str, str]:
    lock = workspace / "composer.lock"
    if not lock.is_file():
        return {}
    try:
        data = json.loads(lock.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    packages: dict[str, str] = {}
    for section in ("packages", "packages-dev"):
        for pkg in data.get(section) or []:
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name")
            version = pkg.get("version")
            if name and version:
                packages[name] = version.lstrip("v")
    return packages


def _composer_json_data(workspace: Path) -> dict[str, Any]:
    composer = workspace / "composer.json"
    if not composer.is_file():
        return {}
    try:
        data = json.loads(composer.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def load_composer_json_product_versions(workspace: Path) -> dict[str, str]:
    """Read Magento product versions from composer.json require / version."""
    data = _composer_json_data(workspace)
    out: dict[str, str] = {}
    for section in ("require", "require-dev"):
        req = data.get(section) or {}
        if not isinstance(req, dict):
            continue
        for key in _PRODUCT_KEYS:
            raw = req.get(key)
            if not isinstance(raw, str):
                continue
            # Strip composer constraint operators: "^2.4.7-p8" / "2.4.7-p8"
            ver = raw.strip().lstrip("v").lstrip("^~>=<!")
            # Take first token if range "2.4.7-p8 || ..."
            ver = ver.split()[0] if ver else ver
            ver = ver.split("|")[0].strip()
            if ver and re.match(r"^\d+\.\d+", ver):
                out[key] = ver
    root_ver = data.get("version")
    if isinstance(root_ver, str) and root_ver.strip():
        out.setdefault("_composer_json_version", root_ver.strip().lstrip("v"))
    return out


def detect_magento_product_version(workspace: Path, packages: dict[str, str] | None = None) -> str | None:
    packages = packages or load_composer_lock_packages(workspace)
    for key in _PRODUCT_KEYS:
        if key in packages:
            return packages[key]

    json_vers = load_composer_json_product_versions(workspace)
    for key in _PRODUCT_KEYS:
        if key in json_vers:
            return json_vers[key]
    return json_vers.get("_composer_json_version")


def merge_installed_for_matching(workspace: Path) -> dict[str, str]:
    """composer.lock packages + composer.json product pins for version matching."""
    packages = dict(load_composer_lock_packages(workspace))
    for key, ver in load_composer_json_product_versions(workspace).items():
        if key.startswith("_"):
            continue
        # Prefer lock when present; otherwise use composer.json require pin.
        packages.setdefault(key, ver)
    # If we know product_version but neither CE nor EE key exists, alias both.
    product = detect_magento_product_version(workspace, packages)
    if product:
        for key in ("magento/product-community-edition", "magento/product-enterprise-edition"):
            packages.setdefault(key, product)
    return packages


class MagentoInventory:
    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace

    def collect(self) -> dict[str, Any]:
        lock_packages = load_composer_lock_packages(self.workspace)
        installed = merge_installed_for_matching(self.workspace)
        product = detect_magento_product_version(self.workspace, installed)
        return {
            "product_version": product,
            "packages": installed,
            "lock_packages": lock_packages,
            "package_count": len(installed),
            "has_composer_lock": (self.workspace / "composer.lock").is_file(),
            "has_vendor": (self.workspace / "vendor").is_dir(),
        }
