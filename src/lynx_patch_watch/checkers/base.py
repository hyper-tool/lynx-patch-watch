"""Pluggable checker framework."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from lynx_patch_watch.models import CheckResult


@dataclass
class CheckContext:
    """Everything a checker may need for one (project, advisory item) pair."""

    project: dict[str, Any]
    item: dict[str, Any]
    workspace: Path | None = None
    installed: dict[str, str] = field(default_factory=dict)
    has_vendor: bool = False
    scan_mode: str = "manual"  # git | local | manual
    git_commit: str | None = None
    git: Any | None = None  # GitWorkspace
    patch_cache_dir: Path | None = None
    detected_type: str = "unknown"
    detected_version: str | None = None
    detected_edition: str | None = None

    @property
    def project_id(self) -> str:
        return self.project.get("id") or ""

    @property
    def is_manual(self) -> bool:
        return self.scan_mode == "manual" or self.project.get("scan_mode") == "manual"


class Checker(ABC):
    """A checker produces one or more CheckResults for an advisory item."""

    name: str = "checker"

    @abstractmethod
    def run(self, ctx: CheckContext, item: dict[str, Any], rules: list[Any]) -> list[CheckResult]:
        """Return checker results; empty list means 'nothing to say'."""

    # -- helpers shared by checkers --

    @staticmethod
    def _packages(item: dict[str, Any]) -> list[dict[str, Any]]:
        pkgs = item.get("packages") or []
        return [p for p in pkgs if isinstance(p, dict)]
