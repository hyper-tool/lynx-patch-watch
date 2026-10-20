"""Checker tests: composer_lock, composer_json, feature_file, hotfix_dir."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from lynx_patch_watch.checkers.base import CheckContext
from lynx_patch_watch.checkers.composer_json import ComposerJsonChecker
from lynx_patch_watch.checkers.composer_lock import ComposerLockChecker
from lynx_patch_watch.checkers.feature_file import FeatureFileChecker
from lynx_patch_watch.checkers.hotfix_dir import HotfixDirChecker
from lynx_patch_watch.engine.rules import Rule, RuleSet
from tests.conftest import make_magento_workspace

ITEM = {
    "item_id": "APSB26-73:CVE-2026-48356",
    "advisory_id": "APSB26-73",
    "cve_id": "CVE-2026-48356",
    "packages": [
        {
            "name": "magento/product-community-edition",
            "affected_versions": "<=2.4.8-p5",
            "fixed_version": "2.4.8-p6",
        }
    ],
    "fix_kind": "upgrade",
    "fingerprints": [],
}


def _ctx(workspace: Path, *, scan_mode: str = "local", installed=None, has_vendor=True) -> CheckContext:
    return CheckContext(
        project={"id": "p1", "type": "magento", "scan_mode": scan_mode},
        item=ITEM,
        workspace=workspace,
        installed=installed if installed is not None else {},
        has_vendor=has_vendor,
        scan_mode=scan_mode,
    )


# --- composer_lock ---


def test_composer_lock_fixed(tmp_path: Path):
    ws = make_magento_workspace(tmp_path / "shop", version="2.4.8-p6")
    from lynx_patch_watch.inventory import merge_installed_for_matching

    ctx = _ctx(ws, installed=merge_installed_for_matching(ws))
    results = ComposerLockChecker().run(ctx, ITEM, [])
    assert results and results[0].outcome == "fixed"


def test_composer_lock_vulnerable(tmp_path: Path):
    ws = make_magento_workspace(tmp_path / "shop", version="2.4.8-p3")
    from lynx_patch_watch.inventory import merge_installed_for_matching

    ctx = _ctx(ws, installed=merge_installed_for_matching(ws))
    results = ComposerLockChecker().run(ctx, ITEM, [])
    assert results and results[0].outcome == "vulnerable"


def test_composer_lock_not_applicable_newer_line(tmp_path: Path):
    ws = make_magento_workspace(tmp_path / "shop", version="2.4.9")
    from lynx_patch_watch.inventory import merge_installed_for_matching

    ctx = _ctx(ws, installed=merge_installed_for_matching(ws))
    results = ComposerLockChecker().run(ctx, ITEM, [])
    assert results and results[0].outcome == "not_applicable"


def test_composer_lock_manual_project_declared_version():
    """Manual projects compare against the declared version at low confidence."""
    ctx = _ctx(
        None,
        scan_mode="manual",
        installed={"magento/product-community-edition": "2.4.8-p3"},
    )
    results = ComposerLockChecker().run(ctx, ITEM, [])
    assert results and results[0].outcome == "vulnerable"
    assert results[0].confidence <= 0.5
    assert "declared" in (results[0].detail or "")


# --- composer_json ---


def test_composer_json_exact_pin_fixed(tmp_path: Path):
    ws = make_magento_workspace(tmp_path / "shop", version="2.4.8-p3")
    data = json.loads((ws / "composer.json").read_text())
    data["require"]["magento/product-community-edition"] = "2.4.8-p6"
    (ws / "composer.json").write_text(json.dumps(data), encoding="utf-8")
    ctx = _ctx(ws, installed={})
    results = ComposerJsonChecker().run(ctx, ITEM, [])
    fixed = [r for r in results if r.outcome == "fixed"]
    assert fixed, [r.outcome for r in results]


def test_composer_json_range_constraint_is_unknown(tmp_path: Path):
    ws = make_magento_workspace(tmp_path / "shop", version="2.4.8-p3")
    data = json.loads((ws / "composer.json").read_text())
    data["require"]["magento/product-community-edition"] = "^2.4.8"
    (ws / "composer.json").write_text(json.dumps(data), encoding="utf-8")
    ctx = _ctx(ws, installed={})
    results = ComposerJsonChecker().run(ctx, ITEM, [])
    unknowns = [r for r in results if r.outcome == "unknown"]
    assert any("not an exact pin" in (r.detail or "") for r in unknowns)


def test_composer_json_patch_declaration(tmp_path: Path):
    ws = make_magento_workspace(tmp_path / "shop", version="2.4.8-p3")
    data = json.loads((ws / "composer.json").read_text())
    data["extra"] = {
        "patches": {
            "ACME security patch": {
                "APSB26-73 CVE-2026-48356 fix": "patches/apsb26-73.patch"
            }
        }
    }
    (ws / "composer.json").write_text(json.dumps(data), encoding="utf-8")
    ctx = _ctx(ws, installed={})
    results = ComposerJsonChecker().run(ctx, ITEM, [])
    declared = [r for r in results if r.outcome == "declared"]
    assert declared, [r.outcome for r in results]


def test_composer_json_qpt_declaration(tmp_path: Path):
    ws = make_magento_workspace(tmp_path / "shop", version="2.4.8-p3")
    data = json.loads((ws / "composer.json").read_text())
    data["require"]["magento/quality-patches"] = "^1.1"
    (ws / "composer.json").write_text(json.dumps(data), encoding="utf-8")
    ctx = _ctx(ws, installed={})
    results = ComposerJsonChecker().run(ctx, ITEM, [])
    assert any(r.outcome == "declared" for r in results)


# --- feature_file ---


def test_feature_file_anchored_fixed(tmp_path: Path):
    ws = make_magento_workspace(tmp_path / "shop", version="2.4.8-p3")
    target = ws / "vendor/magento/module-customer/Model/AccountManagement.php"
    target.parent.mkdir(parents=True)
    target.write_text(
        "if ($user->isAllowed() && $this->csrfValidator->validate($request)) {\n",
        encoding="utf-8",
    )
    item = dict(ITEM)
    item["fingerprints"] = [
        {
            "path": "vendor/magento/module-customer/Model/AccountManagement.php",
            "before": "if ($user->isAllowed()",
            "after": "if ($user->isAllowed() && $this->csrfValidator->validate($request)) {",
            "hunk_id": "vendor/magento/module-customer/Model/AccountManagement.php#0",
        }
    ]
    ctx = _ctx(ws, has_vendor=True)
    results = FeatureFileChecker().run(ctx, item, [])
    assert results and results[0].outcome == "fixed"


def test_feature_file_rule_condition(tmp_path: Path):
    ws = make_magento_workspace(tmp_path / "shop", version="2.4.8-p3")
    (ws / "app/etc/config.php").write_text("<?php return ['modules' => ['Magento_Customer' => 1]];\n", encoding="utf-8")
    rule = Rule(
        id="test-rule",
        advisory="APSB26-73",
        items=["CVE-2026-48356"],
        checks=[
            {
                "path": "app/etc/config.php",
                "contains": "Magento_Customer",
            }
        ],
        verdict_on_match="fixed",
    )
    ctx = _ctx(ws, has_vendor=True)
    results = FeatureFileChecker().run(ctx, ITEM, [rule])
    assert results and results[0].outcome == "fixed"
    # flip verdict → vulnerable when the condition fails
    rule.verdict_on_match = "vulnerable"
    (ws / "app/etc/config.php").write_text("<?php return [];\n", encoding="utf-8")
    results = FeatureFileChecker().run(ctx, ITEM, [rule])
    assert results and results[0].outcome == "fixed"  # condition failed → opposite of vulnerable


# --- hotfix_dir ---


SAMPLE_PATCH = """diff --git a/vendor/magento/module-customer/Model/AccountManagement.php b/vendor/magento/module-customer/Model/AccountManagement.php
index 111..222 100644
--- a/vendor/magento/module-customer/Model/AccountManagement.php
+++ b/vendor/magento/module-customer/Model/AccountManagement.php
@@ -10,7 +10,7 @@ class AccountManagement
     public function doSomething($user, $request)
     {
-    if ($user->isAllowed()) {
+    if ($user->isAllowed() && $this->csrfValidator->validate($request)) {
         return true;
     }
"""


def test_hotfix_dir_declared_only(tmp_path: Path):
    ws = make_magento_workspace(tmp_path / "shop", version="2.4.8-p3")
    (ws / "m2-hotfixes").mkdir()
    (ws / "m2-hotfixes/CVE-2026-48356-fix.patch").write_text(SAMPLE_PATCH, encoding="utf-8")
    ctx = _ctx(ws, has_vendor=False)
    results = HotfixDirChecker().run(ctx, ITEM, [])
    assert results and results[0].outcome == "declared"


def test_hotfix_dir_verified_against_vendor(tmp_path: Path):
    ws = make_magento_workspace(tmp_path / "shop", version="2.4.8-p3")
    target = ws / "vendor/magento/module-customer/Model/AccountManagement.php"
    target.parent.mkdir(parents=True)
    target.write_text(
        "if ($user->isAllowed() && $this->csrfValidator->validate($request)) {\n",
        encoding="utf-8",
    )
    (ws / "m2-hotfixes").mkdir()
    (ws / "m2-hotfixes/CVE-2026-48356-fix.patch").write_text(SAMPLE_PATCH, encoding="utf-8")
    ctx = _ctx(ws, has_vendor=True)
    results = HotfixDirChecker().run(ctx, ITEM, [])
    assert results and results[0].outcome == "fixed"


def test_hotfix_dir_env_yaml_qpt(tmp_path: Path):
    ws = make_magento_workspace(tmp_path / "shop", version="2.4.8-p3")
    (ws / ".magento.env.yaml").write_text(
        "stage:\n  build:\n    QUALITY_PATCHES:\n      - APSB26-73\n",
        encoding="utf-8",
    )
    ctx = _ctx(ws, has_vendor=False)
    results = HotfixDirChecker().run(ctx, ITEM, [])
    assert results and results[0].outcome == "declared"


def test_hotfix_dir_no_match(tmp_path: Path):
    ws = make_magento_workspace(tmp_path / "shop", version="2.4.8-p3")
    (ws / "m2-hotfixes").mkdir()
    (ws / "m2-hotfixes/unrelated.patch").write_text(SAMPLE_PATCH, encoding="utf-8")
    ctx = _ctx(ws, has_vendor=False)
    results = HotfixDirChecker().run(ctx, ITEM, [])
    assert results == []


def test_composer_json_pin_with_uncomparable_range_is_unknown(tmp_path: Path):
    ws = make_magento_workspace(tmp_path / "shop", version="2.4.8-p3")
    data = json.loads((ws / "composer.json").read_text())
    data["require"]["magento/product-community-edition"] = "2.4.8-p3"
    (ws / "composer.json").write_text(json.dumps(data), encoding="utf-8")
    item = dict(ITEM, packages=[dict(ITEM["packages"][0], affected_versions=None)])
    results = ComposerJsonChecker().run(_ctx(ws, installed={}), item, [])
    pins = [r for r in results if r.evidence.get("package") == "magento/product-community-edition"]
    assert pins and all(r.outcome == "unknown" for r in pins), [r.outcome for r in pins]


@pytest.mark.parametrize("rel", ["APSB26-73-root.patch", "patches/nested/CVE-2026-48356.patch"])
def test_hotfix_dir_cache_sees_new_root_and_nested_patches(tmp_path: Path, rel: str):
    ws = make_magento_workspace(tmp_path / "shop", version="2.4.8-p3")
    (ws / "patches/nested").mkdir(parents=True)
    ctx = _ctx(ws, has_vendor=False)
    checker = HotfixDirChecker()
    assert checker.run(ctx, ITEM, []) == []
    (ws / rel).write_text(SAMPLE_PATCH, encoding="utf-8")
    results = checker.run(ctx, ITEM, [])
    assert results and results[0].outcome == "declared"
