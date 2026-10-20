"""Magento path mapping: upstream repo layout → vendor layout.

Used by the git_commit checker's upstream mode to map paths in an upstream
.patch (magento2 repo layout) onto the deployed vendor tree:

    app/code/Magento/Foo/...        → vendor/magento/module-foo/...
    app/code/Magento/Framework/...  → vendor/magento/framework/...
    lib/internal/Magento/Framework/ → vendor/magento/framework/...
    app/design/...                  → app/design/... (unchanged)
"""

from __future__ import annotations

import re

_UPSTREAM_MODULE_RE = re.compile(r"^app/code/Magento/([A-Z][A-Za-z0-9]+)/")
_UPSTREAM_FRAMEWORK_RE = re.compile(r"^(?:app/code/Magento/Framework|lib/internal/Magento/Framework)/")
_VENDOR_NAMESPACE_RE = re.compile(r"^vendor/magento/([a-z0-9-]+)/")


def map_upstream_path(path: str) -> str | None:
    """Map an upstream magento2 repo path to the deployed vendor path.

    Returns None when the path has no vendor mapping (kept as-is by callers
    that want unchanged paths).
    """
    text = (path or "").strip()
    # Strip a diff-style a/ or b/ prefix if present (e.g. "a/app/code/...").
    if text.startswith(("a/", "b/")):
        text = text[2:]
    m = _UPSTREAM_FRAMEWORK_RE.match(text)
    if m:
        rest = re.sub(r"^(?:app/code/Magento/Framework|lib/internal/Magento/Framework)/", "", text)
        return f"vendor/magento/framework/{rest}"
    m = _UPSTREAM_MODULE_RE.match(text)
    if m:
        module = m.group(1)
        rest = text[m.end():]
        return f"vendor/magento/module-{module.lower()}/{rest}"
    return None


def map_vendor_path(path: str) -> str | None:
    """Reverse mapping vendor/magento/module-foo → app/code/Magento/Foo."""
    m = _VENDOR_NAMESPACE_RE.match(path or "")
    if not m:
        return None
    rest = (path or "")[m.end():]
    pkg = m.group(1)
    if pkg == "framework":
        return f"lib/internal/Magento/Framework/{rest}"
    module = "".join(part.capitalize() for part in pkg.split("-"))
    return f"app/code/Magento/{module}/{rest}"
