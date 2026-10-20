"""Shared pytest fixtures for lynx-patch-watch tests."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from lynx_patch_watch.store import Store  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "advisories"


# ---------------------------------------------------------------------------
# Sandbox compatibility.
#
# Some sandboxed environments intercept file deletes, which breaks Python's
# tempfile probe (and therefore pytest capture / tmp_path). Detect that once
# and wrap os.unlink so failed deletes become no-ops in this process only.
# ---------------------------------------------------------------------------
def _sandbox_blocks_unlink() -> bool:
    try:
        fd, probe = tempfile.mkstemp()
    except OSError:
        return True
    try:
        os.close(fd)
        os.unlink(probe)
        return False
    except OSError:
        return True
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


if _sandbox_blocks_unlink():
    _orig_unlink = os.unlink

    def _tolerant_unlink(path, *args, **kwargs):
        try:
            return _orig_unlink(path, *args, **kwargs)
        except OSError:
            return None

    os.unlink = _tolerant_unlink
    os.remove = _tolerant_unlink
    # Point tempfile at a workspace-local dir so probes succeed.
    workspace_tmp = REPO_ROOT / ".tmp" / "pytest"
    workspace_tmp.mkdir(parents=True, exist_ok=True)
    tempfile.tempdir = str(workspace_tmp)


@pytest.fixture()
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / "lpw.sqlite")


def git_available() -> bool:
    """git init + config work in this environment (blocked in some sandboxes)."""
    import subprocess
    import tempfile

    try:
        os.makedirs(REPO_ROOT / ".tmp", exist_ok=True)
        with tempfile.TemporaryDirectory(dir=str(REPO_ROOT / ".tmp")) as d:
            repo = os.path.join(d, "repo")
            os.makedirs(repo)
            init = subprocess.run(
                ["git", "init", "-q", repo],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            if init.returncode != 0:
                return False
            cfg = subprocess.run(
                ["git", "-C", repo, "config", "user.email", "t@t"],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            return cfg.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


requires_git = pytest.mark.skipif(not git_available(), reason="git subprocess unavailable in this environment")


@pytest.fixture()
def store_factory(tmp_path: Path):
    counter = {"n": 0}

    def _make() -> Store:
        counter["n"] += 1
        return Store(tmp_path / f"lpw-{counter['n']}.sqlite")

    return _make


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=1), encoding="utf-8")


def make_magento_workspace(
    root: Path,
    *,
    version: str = "2.4.7-p7",
    edition: str = "community",
    with_vendor: bool = True,
    with_lock: bool = True,
) -> Path:
    """Build a minimal Magento-looking workspace under root."""
    root.mkdir(parents=True, exist_ok=True)
    product_key = (
        "magento/product-community-edition"
        if edition == "community"
        else "magento/product-enterprise-edition"
    )
    write_json(
        root / "composer.json",
        {"require": {product_key: version}, "name": "acme/shop", "type": "project"},
    )
    if with_lock:
        write_json(
            root / "composer.lock",
            {
                "packages": [
                    {"name": product_key, "version": version},
                    {"name": "magento/magento2-base", "version": version},
                    {"name": "magento/module-customer", "version": version},
                ],
                "packages-dev": [],
            },
        )
    (root / "bin").mkdir(exist_ok=True)
    (root / "bin" / "magento").write_text("#!/usr/bin/env php\n", encoding="utf-8")
    etc = root / "app" / "etc"
    etc.mkdir(parents=True, exist_ok=True)
    (etc / "di.xml").write_text('<?xml version="1.0"?><config/>\n', encoding="utf-8")
    if with_vendor:
        fw = root / "vendor" / "magento" / "framework"
        fw.mkdir(parents=True, exist_ok=True)
        (fw / "composer.json").write_text(
            json.dumps({"name": "magento/framework", "version": version}), encoding="utf-8"
        )
    return root
