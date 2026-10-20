"""Magento project-type detection tests."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from lynx_patch_watch.detect import detect
from tests.conftest import requires_git


def _write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def test_detect_composer_json_only(tmp_path: Path):
    _write_json(
        tmp_path / "composer.json",
        {"require": {"magento/product-community-edition": "2.4.7-p8"}},
    )
    result = detect(tmp_path)
    assert result.type == "magento"
    assert result.version == "2.4.7-p8"
    assert result.edition == "CE"
    assert result.confidence >= 0.85
    assert any("composer.json requires" in s for s in result.signals)


def test_detect_prefers_composer_lock(tmp_path: Path):
    _write_json(
        tmp_path / "composer.json",
        {"require": {"magento/product-community-edition": "2.4.7-p8"}},
    )
    _write_json(
        tmp_path / "composer.lock",
        {"packages": [{"name": "magento/product-community-edition", "version": "2.4.7-p7"}], "packages-dev": []},
    )
    result = detect(tmp_path)
    assert result.version == "2.4.7-p7"
    assert result.confidence >= 0.95


def test_detect_bin_magento_and_di_xml(tmp_path: Path):
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "magento").write_text("#!/usr/bin/env php\n", encoding="utf-8")
    (tmp_path / "app" / "etc").mkdir(parents=True)
    (tmp_path / "app" / "etc" / "di.xml").write_text("<config/>", encoding="utf-8")
    result = detect(tmp_path)
    assert result.type == "magento"
    assert result.version is None
    assert any("bin/magento" in s for s in result.signals)


def test_detect_vendor_framework_only(tmp_path: Path):
    (tmp_path / "vendor" / "magento" / "framework").mkdir(parents=True)
    result = detect(tmp_path)
    assert result.type == "magento"
    assert any("vendor/magento/framework" in s for s in result.signals)


def test_detect_enterprise_edition(tmp_path: Path):
    _write_json(
        tmp_path / "composer.json",
        {
            "require": {
                "magento/product-enterprise-edition": "2.4.6-p3",
                "magento/extension-b2b": "1.5.2",
            }
        },
    )
    result = detect(tmp_path)
    assert result.type == "magento"
    assert result.edition == "B2B"


def test_detect_vendor_base_fallback(tmp_path: Path):
    _write_json(
        tmp_path / "vendor" / "magento" / "magento2-base" / "composer.json",
        {"name": "magento/magento2-base", "version": "2.4.8-p1"},
    )
    (tmp_path / "vendor" / "magento" / "framework").mkdir(parents=True)
    result = detect(tmp_path)
    assert result.type == "magento"
    assert result.version == "2.4.8-p1"
    assert any("magento2-base" in s for s in result.signals)


def test_detect_unknown(tmp_path: Path):
    (tmp_path / "index.php").write_text("<?php // not magento\n", encoding="utf-8")
    result = detect(tmp_path)
    assert result.type == "unknown"
    assert result.version is None


@requires_git
def test_detect_git_tag_version(tmp_path: Path):
    _write_json(
        tmp_path / "composer.json",
        {"require": {"magento/product-community-edition": "2.4.7-p8"}},
    )
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_json(
        repo / "composer.json",
        {"require": {"magento/product-community-edition": "2.4.7-p8"}},
    )
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"],
        check=True,
    )
    subprocess.run(["git", "-C", str(repo), "tag", "2.4.7-p7"], check=True)
    # version still comes from composer.json (higher priority than git)
    result = detect(repo)
    assert result.version == "2.4.7-p8"
