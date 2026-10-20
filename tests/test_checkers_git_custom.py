"""Checker tests: git_commit (commits / message_grep / upstream) and custom_rule."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

from lynx_patch_watch.checkers.base import CheckContext
from lynx_patch_watch.checkers.custom_rule import CustomRuleChecker
from lynx_patch_watch.checkers.git_commit import GitCommitChecker
from lynx_patch_watch.engine.rules import Rule
from lynx_patch_watch.git_workspace import GitWorkspace
from tests.conftest import make_magento_workspace, requires_git

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

UPSTREAM_PATCH = """diff --git a/app/code/Magento/Customer/Model/AccountManagement.php b/app/code/Magento/Customer/Model/AccountManagement.php
index 111..222 100644
--- a/app/code/Magento/Customer/Model/AccountManagement.php
+++ b/app/code/Magento/Customer/Model/AccountManagement.php
@@ -10,7 +10,7 @@ class AccountManagement
     public function doSomething($user, $request)
     {
-    if ($user->isAllowed()) {
+    if ($user->isAllowed() && $this->csrfValidator->validate($request)) {
         return true;
     }
"""


def _ctx(workspace: Path | None, *, scan_mode: str = "local", installed=None, has_vendor=True,
         git=None, patch_cache_dir=None, detected_version=None, detected_edition=None,
         detected_type="magento") -> CheckContext:
    return CheckContext(
        project={"id": "p1", "type": "magento", "scan_mode": scan_mode},
        item=ITEM,
        workspace=workspace,
        installed=installed if installed is not None else {},
        has_vendor=has_vendor,
        scan_mode=scan_mode,
        git=git,
        patch_cache_dir=patch_cache_dir,
        detected_type=detected_type,
        detected_version=detected_version,
        detected_edition=detected_edition,
    )


def _rule(**kwargs) -> Rule:
    base = {"id": "test-rule", "advisory": "APSB26-73", "items": ["CVE-2026-48356"],
            "checks": [], "verdict_on_match": "fixed"}
    base.update(kwargs)
    return Rule(**base)


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=True
    )
    return proc.stdout.strip()


def _init_repo(repo: Path) -> str:
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@t")
    _git(repo, "config", "user.name", "t")
    _git(repo, "config", "commit.gpgsign", "false")
    (repo / "README.md").write_text("shop\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "initial import")
    return _git(repo, "rev-parse", "HEAD")


# ---------------------------------------------------------------------------
# git_commit — project repo modes
# ---------------------------------------------------------------------------


@requires_git
def test_git_commit_ancestor_is_fixed(tmp_path: Path):
    ws = make_magento_workspace(tmp_path / "shop", version="2.4.8-p3")
    head = _init_repo(ws)
    git = GitWorkspace(tmp_path / "mirrors")
    rule = _rule(checks=[{"commits": [head]}])
    ctx = _ctx(ws, git=git)
    results = GitCommitChecker().run(ctx, ITEM, [rule])
    assert results and results[0].outcome == "fixed"
    assert results[0].confidence >= 0.8
    assert results[0].evidence[f"commit:{head}"] is True


@requires_git
def test_git_commit_missing_sha_is_unknown(tmp_path: Path):
    ws = make_magento_workspace(tmp_path / "shop", version="2.4.8-p3")
    _init_repo(ws)
    git = GitWorkspace(tmp_path / "mirrors")
    bogus = "0" * 40
    rule = _rule(checks=[{"commits": [bogus]}])
    ctx = _ctx(ws, git=git)
    results = GitCommitChecker().run(ctx, ITEM, [rule])
    assert results and results[0].outcome == "unknown"
    assert results[0].evidence[f"commit:{bogus}"] is not True


@requires_git
def test_git_commit_message_grep_hit(tmp_path: Path):
    ws = make_magento_workspace(tmp_path / "shop", version="2.4.8-p3")
    _init_repo(ws)
    (ws / "composer.lock").write_text("{}\n", encoding="utf-8")
    _git(ws, "add", ".")
    _git(ws, "commit", "-qm", "APSB26-73: harden CSRF validation (CVE-2026-48356)")
    git = GitWorkspace(tmp_path / "mirrors")
    rule = _rule(checks=[{"message_grep": "CVE-2026-48356"}])
    ctx = _ctx(ws, git=git)
    results = GitCommitChecker().run(ctx, ITEM, [rule])
    assert results and results[0].outcome == "fixed"
    assert results[0].evidence["hits"]


@requires_git
def test_git_commit_message_grep_miss(tmp_path: Path):
    ws = make_magento_workspace(tmp_path / "shop", version="2.4.8-p3")
    _init_repo(ws)
    git = GitWorkspace(tmp_path / "mirrors")
    rule = _rule(checks=[{"message_grep": "nothing-matches-this"}])
    ctx = _ctx(ws, git=git)
    results = GitCommitChecker().run(ctx, ITEM, [rule])
    assert results and results[0].outcome == "unknown"
    assert not results[0].evidence["hits"]


def test_git_commit_without_git_is_silent(tmp_path: Path):
    ws = make_magento_workspace(tmp_path / "shop", version="2.4.8-p3")
    rule = _rule(checks=[{"commits": ["a" * 40]}])
    ctx = _ctx(ws, git=None)
    assert GitCommitChecker().run(ctx, ITEM, [rule]) == []


# ---------------------------------------------------------------------------
# git_commit — upstream mode (patch served from the local cache, no network)
# ---------------------------------------------------------------------------


def _cache_upstream_patch(cache_dir: Path, url: str, text: str) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    key = hashlib.sha256(url.encode()).hexdigest()[:16]
    (cache_dir / f"{key}.patch").write_text(text, encoding="utf-8")


def test_git_commit_upstream_cached_patch_fixed(tmp_path: Path):
    ws = make_magento_workspace(tmp_path / "shop", version="2.4.8-p3")
    target = ws / "vendor/magento/module-customer/Model/AccountManagement.php"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        "if ($user->isAllowed() && $this->csrfValidator->validate($request)) {\n",
        encoding="utf-8",
    )
    url = "https://example.invalid/apsb26-73-fix.patch"
    _cache_upstream_patch(tmp_path / "patch-cache", url, UPSTREAM_PATCH)
    rule = _rule(checks=[{"upstream": {"patch_url": url}}])
    ctx = _ctx(ws, has_vendor=True, patch_cache_dir=tmp_path / "patch-cache")
    results = GitCommitChecker().run(ctx, ITEM, [rule])
    assert results and results[0].outcome == "fixed", [r.outcome for r in results]


def test_git_commit_upstream_cached_patch_vulnerable(tmp_path: Path):
    ws = make_magento_workspace(tmp_path / "shop", version="2.4.8-p3")
    target = ws / "vendor/magento/module-customer/Model/AccountManagement.php"
    target.parent.mkdir(parents=True, exist_ok=True)
    # Deployed tree still has the pre-fix ("before") line.
    target.write_text("if ($user->isAllowed()) {\n", encoding="utf-8")
    url = "https://example.invalid/apsb26-73-fix.patch"
    _cache_upstream_patch(tmp_path / "patch-cache", url, UPSTREAM_PATCH)
    rule = _rule(checks=[{"upstream": {"patch_url": url}}])
    ctx = _ctx(ws, has_vendor=True, patch_cache_dir=tmp_path / "patch-cache")
    results = GitCommitChecker().run(ctx, ITEM, [rule])
    assert results and results[0].outcome == "vulnerable", [r.outcome for r in results]


def test_git_commit_upstream_unreachable_is_unknown(tmp_path: Path):
    ws = make_magento_workspace(tmp_path / "shop", version="2.4.8-p3")
    # Port 1 on localhost: connection refused immediately, no external network.
    url = "http://127.0.0.1:1/does-not-exist.patch"
    rule = _rule(checks=[{"upstream": {"patch_url": url}}])
    ctx = _ctx(ws, has_vendor=True, patch_cache_dir=tmp_path / "patch-cache")
    results = GitCommitChecker().run(ctx, ITEM, [rule])
    assert results and results[0].outcome == "unknown"
    assert results[0].evidence["reason"] == "patch unavailable"


# ---------------------------------------------------------------------------
# custom_rule
# ---------------------------------------------------------------------------


def test_custom_rule_file_contains_matched(tmp_path: Path):
    ws = make_magento_workspace(tmp_path / "shop", version="2.4.8-p3")
    (ws / "app/etc/config.php").write_text(
        "<?php return ['modules' => ['Magento_Customer' => 1]];\n", encoding="utf-8"
    )
    rule = _rule(
        checks=[{"custom": {"file": "app/etc/config.php", "contains": "Magento_Customer"}}]
    )
    results = CustomRuleChecker().run(_ctx(ws), ITEM, [rule])
    assert results and results[0].outcome == "fixed"
    assert results[0].evidence["verdict_on_match"] == "fixed"


def test_custom_rule_not_contains_flips_verdict(tmp_path: Path):
    ws = make_magento_workspace(tmp_path / "shop", version="2.4.8-p3")
    (ws / "app/etc/config.php").write_text("<?php return [];\n", encoding="utf-8")
    # verdict_on_match=vulnerable: condition matches → vulnerable; fails → fixed
    rule = _rule(
        checks=[{"custom": {"file": "app/etc/config.php", "not_contains": "Magento_Customer"}}],
        verdict_on_match="vulnerable",
    )
    results = CustomRuleChecker().run(_ctx(ws), ITEM, [rule])
    assert results and results[0].outcome == "vulnerable"
    (ws / "app/etc/config.php").write_text(
        "<?php return ['modules' => ['Magento_Customer' => 1]];\n", encoding="utf-8"
    )
    results = CustomRuleChecker().run(_ctx(ws), ITEM, [rule])
    assert results and results[0].outcome == "fixed"


def test_custom_rule_all_any_not_combinators(tmp_path: Path):
    ws = make_magento_workspace(tmp_path / "shop", version="2.4.8-p3")
    (ws / "app/etc/config.php").write_text(
        "<?php return ['modules' => ['Magento_Customer' => 1]];\n", encoding="utf-8"
    )
    # all: [file contains, any: [missing file, package gte]] → True
    rule = _rule(
        checks=[
            {
                "custom": {
                    "all": [
                        {"file": "app/etc/config.php", "contains": "Magento_Customer"},
                        {
                            "any": [
                                {"file": "nope.php", "contains": "x"},
                                {"package": "magento/module-customer", "version_gte": "2.4.0"},
                            ],
                        },
                    ]
                }
            }
        ]
    )
    ctx = _ctx(ws, installed={"magento/module-customer": "2.4.8-p3"})
    results = CustomRuleChecker().run(ctx, ITEM, [rule])
    assert results and results[0].outcome == "fixed"
    # not: inverts the failing file atom
    rule2 = _rule(checks=[{"custom": {"not": {"file": "nope.php", "contains": "x"}}}])
    results = CustomRuleChecker().run(ctx, ITEM, [rule2])
    assert results and results[0].outcome == "fixed"


def test_custom_rule_package_version_mismatch(tmp_path: Path):
    ws = make_magento_workspace(tmp_path / "shop", version="2.4.8-p3")
    rule = _rule(
        checks=[{"custom": {"package": "magento/module-customer", "version_gte": "2.4.9"}}],
        verdict_on_match="vulnerable",
    )
    ctx = _ctx(ws, installed={"magento/module-customer": "2.4.8-p3"})
    results = CustomRuleChecker().run(ctx, ITEM, [rule])
    # condition failed → opposite of vulnerable
    assert results and results[0].outcome == "fixed"


def test_custom_rule_patch_declared(tmp_path: Path):
    import json

    ws = make_magento_workspace(tmp_path / "shop", version="2.4.8-p3")
    data = json.loads((ws / "composer.json").read_text())
    data["extra"] = {"patches": {"vendor": {"APSB26-73": "patches/x.patch"}}}
    (ws / "composer.json").write_text(json.dumps(data), encoding="utf-8")
    rule = _rule(checks=[{"custom": {"patch_declared": True}}])
    results = CustomRuleChecker().run(_ctx(ws), ITEM, [rule])
    assert results and results[0].outcome == "fixed"
    # without a declaration the same rule does not match
    data.pop("extra")
    (ws / "composer.json").write_text(json.dumps(data), encoding="utf-8")
    results = CustomRuleChecker().run(_ctx(ws), ITEM, [rule])
    assert results and results[0].outcome == "vulnerable"


@requires_git
def test_custom_rule_commit_atom(tmp_path: Path):
    ws = make_magento_workspace(tmp_path / "shop", version="2.4.8-p3")
    head = _init_repo(ws)
    git = GitWorkspace(tmp_path / "mirrors")
    rule = _rule(checks=[{"custom": {"commit": head}}])
    results = CustomRuleChecker().run(_ctx(ws, git=git), ITEM, [rule])
    assert results and results[0].outcome == "fixed"
    rule2 = _rule(checks=[{"custom": {"commit": "0" * 40}}])
    results = CustomRuleChecker().run(_ctx(ws, git=git), ITEM, [rule2])
    assert results and results[0].outcome == "vulnerable"


def test_custom_rule_applies_to_version_gate(tmp_path: Path):
    ws = make_magento_workspace(tmp_path / "shop", version="2.4.8-p3")
    (ws / "app/etc/config.php").write_text(
        "<?php return ['modules' => ['Magento_Customer' => 1]];\n", encoding="utf-8"
    )
    rule = _rule(
        applies_to={"type": "magento", "version": ">=2.4.9"},
        checks=[{"custom": {"file": "app/etc/config.php", "contains": "Magento_Customer"}}],
    )
    # project is 2.4.8-p3 → rule does not apply → no results at all
    results = CustomRuleChecker().run(_ctx(ws, detected_version="2.4.8-p3"), ITEM, [rule])
    assert results == []
    # detected 2.4.9 → applies
    results = CustomRuleChecker().run(_ctx(ws, detected_version="2.4.9"), ITEM, [rule])
    assert results and results[0].outcome == "fixed"


def test_custom_rule_applies_to_edition_gate(tmp_path: Path):
    ws = make_magento_workspace(tmp_path / "shop", version="2.4.8-p3")
    rule = _rule(
        applies_to={"edition": "B2B"},
        checks=[{"custom": {"patch_declared": True}}],
    )
    assert CustomRuleChecker().run(_ctx(ws, detected_edition="CE"), ITEM, [rule]) == []
    results = CustomRuleChecker().run(_ctx(ws, detected_edition="B2B"), ITEM, [rule])
    assert results  # edition matches; declaration missing → opposite of fixed


def test_custom_rule_sha256_atom(tmp_path: Path):
    ws = make_magento_workspace(tmp_path / "shop", version="2.4.8-p3")
    marker = ws / "app/etc/config.php"
    marker.write_text("<?php return [];\n", encoding="utf-8")
    digest = hashlib.sha256(marker.read_bytes()).hexdigest()
    rule = _rule(checks=[{"custom": {"file": "app/etc/config.php", "sha256": digest}}])
    results = CustomRuleChecker().run(_ctx(ws), ITEM, [rule])
    assert results and results[0].outcome == "fixed"
    rule2 = _rule(checks=[{"custom": {"file": "app/etc/config.php", "sha256": "0" * 64}}])
    results = CustomRuleChecker().run(_ctx(ws), ITEM, [rule2])
    assert results and results[0].outcome == "vulnerable"


@requires_git
def test_is_ancestor_distinguishes_not_ancestor_from_error(tmp_path: Path):
    ws = tmp_path / "shop"
    first = _init_repo(ws)
    _git(ws, "checkout", "-qb", "side")
    (ws / "side.txt").write_text("side\n", encoding="utf-8")
    _git(ws, "add", ".")
    _git(ws, "commit", "-qm", "side commit")
    side = _git(ws, "rev-parse", "HEAD")
    _git(ws, "checkout", "-q", "-")
    git = GitWorkspace(tmp_path / "mirrors")
    assert git.is_ancestor(ws, first) is True
    assert git.is_ancestor(ws, side) is False
    assert git.is_ancestor(ws, "0" * 40) is None
