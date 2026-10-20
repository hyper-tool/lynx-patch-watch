"""custom_rule checker: YAML-composed atomic conditions.

A rule check of the form::

    checks:
      - custom:
          all:
            - {file: app/etc/config.php, contains: "'Magento_X'"}
            - any:
                - {package: magento/module-customer, version_gte: 2.4.7}
                - {patch_declared: true}

Atomic conditions:
- {file: PATH, contains: S} / {file: PATH, not_contains: S}
- {file: PATH, regex: R}
- {file: PATH, sha256: HEX}
- {package: NAME, version_gte|version_lte|version_eq: VER}
- {patch_declared: true}
- {commit: SHA}
- {not: {...}} / {all: [...]} / {any: [...]}

Rules apply only when ``applies_to`` matches the project (type, edition,
version range).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from lynx_patch_watch.checkers.base import CheckContext, Checker, CheckResult
from lynx_patch_watch.engine.rules import version_in_spec


class CustomRuleChecker(Checker):
    name = "custom_rule"

    def run(self, ctx: CheckContext, item: dict[str, Any], rules: list[Any]) -> list[CheckResult]:
        results: list[CheckResult] = []
        for rule in rules or []:
            if not _applies_to_matches(rule, ctx):
                continue
            for check in getattr(rule, "checks", []) or []:
                if not isinstance(check, dict) or "custom" not in check:
                    continue
                spec = check.get("custom") or {}
                ok, trace = _evaluate(spec, ctx, depth=0)
                verdict = getattr(rule, "verdict_on_match", "fixed") or "fixed"
                outcome = verdict if ok else _opposite(verdict)
                results.append(
                    CheckResult(
                        checker=self.name,
                        outcome=outcome,
                        confidence=0.7 if ok else 0.4,
                        evidence={
                            "rule": getattr(rule, "id", "?"),
                            "trace": trace,
                            "verdict_on_match": verdict,
                        },
                        detail=f"custom rule {getattr(rule, 'id', '?')} "
                        + ("matched" if ok else "did not match"),
                    )
                )
        return results


def _opposite(verdict: str) -> str:
    if verdict == "fixed":
        return "vulnerable"
    if verdict == "vulnerable":
        return "fixed"
    return "unknown"


def _applies_to_matches(rule: Any, ctx: CheckContext) -> bool:
    """Delegate to the shared Rule.applies logic (natural version ordering)."""
    applies = getattr(rule, "applies", None)
    if callable(applies):
        try:
            return bool(applies(ctx))
        except Exception:  # noqa: BLE001
            return False
    return True


def _evaluate(spec: Any, ctx: CheckContext, depth: int) -> tuple[bool, list[dict[str, Any]]]:
    trace: list[dict[str, Any]] = []
    if depth > 8:
        return False, [{"error": "max depth exceeded"}]
    if isinstance(spec, list):
        ok = all(_evaluate(s, ctx, depth + 1)[0] for s in spec)
        return ok, [{"all": [{"ok": _evaluate(s, ctx, depth + 1)[0]} for s in spec]}]
    if not isinstance(spec, dict):
        return False, [{"error": f"unsupported spec {type(spec).__name__}"}]

    if "all" in spec:
        results = [_evaluate(s, ctx, depth + 1) for s in spec["all"]]
        ok = all(r[0] for r in results)
        return ok, [{"all": [r[1] for r in results]}]
    if "any" in spec:
        results = [_evaluate(s, ctx, depth + 1) for s in spec["any"]]
        ok = any(r[0] for r in results)
        return ok, [{"any": [r[1] for r in results]}]
    if "not" in spec:
        inner_ok, inner_trace = _evaluate(spec["not"], ctx, depth + 1)
        return (not inner_ok), [{"not": inner_trace}]
    return _evaluate_atom(spec, ctx)


def _evaluate_atom(atom: dict[str, Any], ctx: CheckContext) -> tuple[bool, list[dict[str, Any]]]:
    if "file" in atom:
        path = ctx.workspace / str(atom["file"]) if ctx.workspace else None
        if path is None or not path.is_file():
            return False, [{"file": atom["file"], "ok": False, "reason": "missing"}]
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False, [{"file": atom["file"], "ok": False, "reason": "unreadable"}]
        ok = True
        if "contains" in atom:
            ok = ok and str(atom["contains"]) in text
        if "not_contains" in atom:
            ok = ok and str(atom["not_contains"]) not in text
        if "regex" in atom:
            ok = ok and bool(re.search(str(atom["regex"]), text))
        if "sha256" in atom:
            import hashlib

            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            ok = ok and digest.lower() == str(atom["sha256"]).lower()
        return ok, [{"file": atom["file"], "ok": ok}]
    if "package" in atom:
        name = str(atom["package"])
        current = (ctx.installed or {}).get(name)
        if not current:
            return False, [{"package": name, "ok": False, "reason": "not installed"}]
        ok = True
        if "version_gte" in atom:
            ok = ok and version_in_spec(current, f">={atom['version_gte']}")
        if "version_lte" in atom:
            ok = ok and version_in_spec(current, f"<={atom['version_lte']}")
        if "version_eq" in atom:
            ok = ok and version_in_spec(current, f"=={atom['version_eq']}")
        return ok, [{"package": name, "current": current, "ok": ok}]
    if "patch_declared" in atom:
        ok = bool(atom["patch_declared"])
        declared = _has_patch_declaration(ctx)
        return (declared is ok), [{"patch_declared": atom["patch_declared"], "actual": declared}]
    if "commit" in atom:
        sha = str(atom["commit"])
        if ctx.git is None or ctx.workspace is None:
            return False, [{"commit": sha, "ok": False, "reason": "no git workspace"}]
        is_ancestor = ctx.git.is_ancestor(ctx.workspace, sha)
        return (is_ancestor is True), [{"commit": sha, "ok": is_ancestor}]
    return False, [{"error": f"unsupported atom keys {sorted(atom)}"}]


def _has_patch_declaration(ctx: CheckContext) -> bool:
    if ctx.workspace is None:
        return False
    import json

    composer = ctx.workspace / "composer.json"
    if not composer.is_file():
        return False
    try:
        data = json.loads(composer.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return False
    extra = data.get("extra") if isinstance(data, dict) else None
    if not isinstance(extra, dict):
        return False
    for key in ("patches", "magento-patches", "composer-patches", "patches-file", "patchesFile"):
        if extra.get(key):
            return True
    requires = data.get("require") or {}
    return any("quality-patches" in k.lower() for k in requires) if isinstance(requires, dict) else False
