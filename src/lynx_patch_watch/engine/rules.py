"""YAML check-rule loading.

Rule file format (rules/magento/*.yaml)::

    id: apsb26-146-hotfix
    advisory: APSB26-146
    items: [CVE-2026-75650]
    applies_to: {type: magento, version: ">=2.4.4"}
    checks:
      - hotfix_dir: {}
      - custom:
          all:
            - {file: m2-hotfixes/CVE-2026-75650.patch, regex: "AccountManagement"}
    verdict_on_match: fixed   # or vulnerable
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

APSB_ID_RE = re.compile(r"^APSB\d{2}-\d{2,4}$", re.IGNORECASE)
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

_VERSION_SPEC_RE = re.compile(r"^(>=|<=|==|>|<)?\s*(.+)$")


def version_in_spec(current: str, spec: str) -> bool:
    """Evaluate a version spec like ``>=2.4.4`` against ``current``.

    Uses natural MagentoVersion ordering (core, then patch level, then dated
    hotfix rank), so cross-line comparisons behave as rule authors expect:
    2.4.8-p3 satisfies ``>=2.4.4`` but not ``>=2.4.9``.
    """
    from lynx_patch_watch.magento_version import parse_magento_version

    m = _VERSION_SPEC_RE.match((spec or "").strip())
    if not m:
        return False
    op = m.group(1) or ">="
    cur = parse_magento_version(current)
    tgt = parse_magento_version(m.group(2).strip())
    if cur is None or tgt is None:
        return False
    if op == ">=":
        return cur >= tgt
    if op == "<=":
        return cur <= tgt
    if op == "==":
        return cur == tgt
    if op == ">":
        return cur > tgt
    if op == "<":
        return cur < tgt
    return False


@dataclass
class Rule:
    id: str
    advisory: str
    items: list[str] = field(default_factory=list)
    applies_to: dict[str, Any] = field(default_factory=dict)
    checks: list[Any] = field(default_factory=list)
    verdict_on_match: str = "fixed"
    source_path: str = ""

    def matches_item(self, advisory_id: str, cve_id: str | None) -> bool:
        if self.advisory.upper() != (advisory_id or "").upper():
            return False
        if not self.items:
            return True
        if not cve_id:
            return False
        return cve_id.upper() in {i.upper() for i in self.items}

    def applies(self, ctx: Any) -> bool:
        """True when the rule's ``applies_to`` gate matches the project context.

        Gates (all optional):
        - ``type``: project type (falls back to the detected type for ``auto``);
        - ``edition``: CE / EE / B2B (skipped when unknown);
        - ``version``: natural ordering spec like ``>=2.4.4`` — cross-line
          comparisons use the full MagentoVersion ordering, so 2.4.8-p3 does
          satisfy ``>=2.4.4``.
        """
        applies = self.applies_to or {}
        if not isinstance(applies, dict) or not applies:
            return True
        ptype = applies.get("type")
        if ptype and ptype != "unknown":
            project_type = ctx.project.get("type") or "auto"
            if project_type == "auto":
                if ctx.detected_type and ctx.detected_type != ptype:
                    return False
            elif project_type != ptype:
                return False
        edition = applies.get("edition")
        if edition:
            actual = ctx.detected_edition or ctx.project.get("declared_edition")
            if actual and actual != edition:
                return False
        version_spec = applies.get("version")
        if version_spec:
            current = ctx.detected_version or ctx.project.get("declared_version")
            if not current or not version_in_spec(str(current), str(version_spec)):
                return False
        return True


@dataclass
class RuleSet:
    rules: list[Rule] = field(default_factory=list)

    @property
    def hash(self) -> str:
        payload = "\n".join(
            f"{r.advisory}|{','.join(r.items)}|{r.verdict_on_match}|{r.checks!r}"
            for r in sorted(self.rules, key=lambda x: x.id)
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def for_item(self, advisory_id: str, cve_id: str | None) -> list[Rule]:
        return [r for r in self.rules if r.matches_item(advisory_id, cve_id)]


def load_ruleset(rules_dir: Path) -> RuleSet:
    rules: list[Rule] = []
    if not rules_dir.is_dir():
        return RuleSet(rules)
    for path in sorted(rules_dir.glob("*.yaml")) + sorted(rules_dir.glob("*.yml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (yaml.YAMLError, OSError) as exc:
            raise ValueError(f"invalid rule file {path}: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError(f"rule file must be a mapping: {path}")
        advisory = str(data.get("advisory") or "").upper()
        if not APSB_ID_RE.match(advisory):
            raise ValueError(f"rule {path}: advisory must look like APSB26-146, got {advisory!r}")
        items = [str(i).upper() for i in (data.get("items") or [])]
        for cve in items:
            if not CVE_ID_RE.match(cve):
                raise ValueError(f"rule {path}: items must be CVE ids, got {cve!r}")
        verdict = str(data.get("verdict_on_match") or "fixed").lower()
        if verdict not in ("fixed", "vulnerable"):
            raise ValueError(f"rule {path}: verdict_on_match must be fixed|vulnerable")
        rules.append(
            Rule(
                id=str(data.get("id") or path.stem),
                advisory=advisory,
                items=items,
                applies_to=data.get("applies_to") or {},
                checks=data.get("checks") or [],
                verdict_on_match=verdict,
                source_path=str(path),
            )
        )
    ids = [r.id for r in rules]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate rule ids in rules directory")
    return RuleSet(rules)
