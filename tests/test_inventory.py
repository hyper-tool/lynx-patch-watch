"""Ported from msw tests/test_inventory_version.py (inventory merge parts)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lynx_patch_watch.inventory import (
    MagentoInventory,
    load_composer_lock_packages,
    merge_installed_for_matching,
)
from lynx_patch_watch.magento_version import (
    magento_gte,
    magento_lte,
    parse_magento_version,
    same_release_line,
)


def _write_composer_json(workspace: Path, data: dict) -> None:
    (workspace / "composer.json").write_text(json.dumps(data), encoding="utf-8")


def _write_composer_lock(workspace: Path, packages: list[dict]) -> None:
    (workspace / "composer.lock").write_text(
        json.dumps({"packages": packages, "packages-dev": []}),
        encoding="utf-8",
    )


def test_merge_uses_composer_json_require(tmp_path: Path):
    _write_composer_json(
        tmp_path,
        {"require": {"magento/product-community-edition": "2.4.7-p8"}},
    )
    installed = merge_installed_for_matching(tmp_path)
    assert installed["magento/product-community-edition"] == "2.4.7-p8"
    inv = MagentoInventory(tmp_path).collect()
    assert inv["product_version"] == "2.4.7-p8"


def test_merge_strips_composer_constraint_operators(tmp_path: Path):
    _write_composer_json(
        tmp_path,
        {"require": {"magento/product-community-edition": "^2.4.7-p8"}},
    )
    installed = merge_installed_for_matching(tmp_path)
    assert installed["magento/product-community-edition"] == "2.4.7-p8"


def test_merge_prefers_lock_over_composer_json(tmp_path: Path):
    _write_composer_json(
        tmp_path,
        {"require": {"magento/product-community-edition": "2.4.7-p8"}},
    )
    _write_composer_lock(
        tmp_path,
        [{"name": "magento/product-community-edition", "version": "2.4.7-p7"}],
    )
    installed = merge_installed_for_matching(tmp_path)
    assert installed["magento/product-community-edition"] == "2.4.7-p7"
    assert MagentoInventory(tmp_path).collect()["product_version"] == "2.4.7-p7"


def test_merge_enterprise_and_aliases_ce(tmp_path: Path):
    _write_composer_json(
        tmp_path,
        {"require": {"magento/product-enterprise-edition": "2.4.6-p3"}},
    )
    installed = merge_installed_for_matching(tmp_path)
    assert installed["magento/product-enterprise-edition"] == "2.4.6-p3"
    # Alias missing CE so bulletin CE constraints can still match.
    assert installed["magento/product-community-edition"] == "2.4.6-p3"


def test_merge_magento2_base_fallback(tmp_path: Path):
    _write_composer_lock(
        tmp_path,
        [{"name": "magento/magento2-base", "version": "2.4.8-p1"}],
    )
    inv = MagentoInventory(tmp_path).collect()
    assert inv["product_version"] == "2.4.8-p1"
    assert inv["packages"]["magento/product-community-edition"] == "2.4.8-p1"


def test_load_composer_lock_tolerates_bad_json(tmp_path: Path):
    (tmp_path / "composer.lock").write_text("{not json", encoding="utf-8")
    assert load_composer_lock_packages(tmp_path) == {}


@pytest.mark.parametrize(
    ("left", "right", "expect_lt"),
    [
        ("2.4.7-p7", "2.4.7-p8", True),
        ("2.4.7", "2.4.7-p1", True),
        ("2.4.7-p10", "2.4.7-p2", False),  # numeric patch, not lexicographic
        ("2.4.8-p5", "2.4.8-2026-jul", True),
        ("2.4.8-p6", "2.4.8-p6", False),
    ],
)
def test_parse_order_within_line(left: str, right: str, expect_lt: bool):
    a = parse_magento_version(left)
    b = parse_magento_version(right)
    assert a is not None and b is not None
    assert (a < b) is expect_lt


@pytest.mark.parametrize(
    ("a", "b", "same"),
    [
        ("2.4.7-p8", "2.4.7-p1", True),
        ("2.4.7-p8", "2.4.8-p5", False),
        ("2.4.6-p3", "2.4.7-p7", False),
        ("2.4.8", "2.4.8-2026-jul", True),
    ],
)
def test_same_release_line(a: str, b: str, same: bool):
    assert same_release_line(a, b) is same


@pytest.mark.parametrize(
    ("current", "maximum", "expect"),
    [
        ("2.4.7-p7", "2.4.7-p7", True),
        ("2.4.7-p8", "2.4.7-p7", False),
        ("2.4.7-p6", "2.4.7-p7", True),
        # Cross-line must NOT be treated as "earlier"
        ("2.4.7-p8", "2.4.8-p5", False),
        ("2.4.6-p3", "2.4.7-p7", False),
        ("2.4.8-p5", "2.4.7-p7", False),
    ],
)
def test_magento_lte_line_scoped(current: str, maximum: str, expect: bool):
    assert magento_lte(current, maximum) is expect


@pytest.mark.parametrize(
    ("current", "minimum", "expect"),
    [
        ("2.4.7-p8", "2.4.7-p8", True),
        ("2.4.7-p9", "2.4.7-p8", True),
        ("2.4.7-p7", "2.4.7-p8", False),
        ("2.4.8-p6", "2.4.7-p8", False),  # different line
        ("2.4.8-2026-jul", "2.4.8-p6", True),
    ],
)
def test_magento_gte_line_scoped(current: str, minimum: str, expect: bool):
    assert magento_gte(current, minimum) is expect
