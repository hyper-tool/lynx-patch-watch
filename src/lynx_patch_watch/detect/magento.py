"""Magento project-type detection.

detect(workspace) -> DetectResult(type, version, edition, signals[])

Signals:
- composer.json depends on magento/product-(community|enterprise)-edition or
  magento/magento2-base;
- bin/magento or app/etc/di.xml exists;
- vendor/magento/framework exists.

Version source order (first hit wins):
1. composer.lock (via inventory.load_composer_lock_packages);
2. composer.json exact version;
3. vendor/magento/magento2-base/composer.json;
4. git tag / branch name (low confidence).

Edition: CE / EE; B2B when magento/extension-b2b is present.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from lynx_patch_watch.inventory import (
    _PRODUCT_KEYS,
    load_composer_json_product_versions,
    load_composer_lock_packages,
)
from lynx_patch_watch.models import DetectResult

_PRODUCT_DEP_RE = re.compile(
    r"magento/(?:product-(?:community|enterprise)-edition|magento2-base)",
)
_GIT_TAG_VER_RE = re.compile(r"^(?:\d+\.\d+\.\d+(?:-p\d+)?)$")


def detect(workspace: Path) -> DetectResult:
    signals: list[str] = []
    version: str | None = None
    version_source: str | None = None
    edition: str | None = None
    confidence = 0.0

    composer_json = _read_json(workspace / "composer.json")

    # --- signals ---
    requires: dict[str, Any] = {}
    for section in ("require", "require-dev"):
        req = composer_json.get(section)
        if isinstance(req, dict):
            requires.update(req)
    dep_hits = [k for k in requires if _PRODUCT_DEP_RE.search(k)]
    if dep_hits:
        signals.append(f"composer.json requires {', '.join(sorted(dep_hits))}")
    if (workspace / "bin" / "magento").is_file():
        signals.append("bin/magento present")
    if (workspace / "app" / "etc" / "di.xml").is_file():
        signals.append("app/etc/di.xml present")
    if (workspace / "vendor" / "magento" / "framework").is_dir():
        signals.append("vendor/magento/framework present")
    if re.search(r"magento", json.dumps(composer_json), re.I) if composer_json else False:
        pass  # weak signal; not counted

    is_magento = bool(dep_hits) or (
        (workspace / "bin" / "magento").is_file()
        and (workspace / "app" / "etc" / "di.xml").is_file()
    ) or (workspace / "vendor" / "magento" / "framework").is_dir()

    if not is_magento:
        return DetectResult(type="unknown", signals=signals, confidence=0.0)

    # --- version ---
    lock_packages = load_composer_lock_packages(workspace)
    for key in _PRODUCT_KEYS:
        if key in lock_packages:
            version = lock_packages[key]
            version_source = "composer.lock"
            confidence = max(confidence, 0.95)
            break
    if version is None:
        json_versions = load_composer_json_product_versions(workspace)
        for key in _PRODUCT_KEYS:
            if key in json_versions:
                version = json_versions[key]
                version_source = "composer.json"
                confidence = max(confidence, 0.85)
                break
    if version is None:
        base_json = workspace / "vendor" / "magento" / "magento2-base" / "composer.json"
        base_version = _read_json(base_json).get("version")
        if isinstance(base_version, str) and base_version.strip():
            version = base_version.strip().lstrip("v")
            version_source = "vendor/magento/magento2-base/composer.json"
            confidence = max(confidence, 0.8)
    if version is None:
        git_version = _version_from_git(workspace)
        if git_version:
            version = git_version
            version_source = "git tag/branch"
            confidence = max(confidence, 0.4)

    # --- edition --- (B2B takes precedence per plan: CE / EE / B2B)
    edition = "CE"
    if any("extension-b2b" in k or "module-b2b" in k for k in list(lock_packages) + list(requires)):
        edition = "B2B"
    elif "magento/product-enterprise-edition" in lock_packages or "magento/product-enterprise-edition" in requires:
        edition = "EE"
    if edition != "CE":
        signals.append(f"edition={edition}")

    if version_source:
        signals.append(f"version={version} (from {version_source})")

    return DetectResult(
        type="magento",
        version=version,
        edition=edition,
        signals=signals,
        confidence=confidence,
    )


def detect_magento(workspace: Path) -> DetectResult:
    """Backwards-compatible alias."""
    return detect(workspace)


def _read_json(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _version_from_git(workspace: Path) -> str | None:
    """Best-effort version from the checked-out git tag / branch name."""
    git_dir = workspace / ".git"
    if not git_dir.exists():
        return None
    import subprocess

    def _run(args: list[str]) -> str | None:
        try:
            proc = subprocess.run(
                ["git", *args],
                cwd=str(workspace),
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if proc.returncode != 0:
            return None
        return proc.stdout.strip()

    tag = _run(["describe", "--tags", "--exact-match"])
    if tag:
        m = _GIT_TAG_VER_RE.match(tag.lstrip("v"))
        if m:
            return m.group(0)
    branch = _run(["rev-parse", "--abbrev-ref", "HEAD"])
    if branch:
        m = _GIT_TAG_VER_RE.match(branch)
        if m:
            return m.group(0)
    return None
