"""Checker registry."""

from __future__ import annotations

from lynx_patch_watch.checkers.base import CheckContext, Checker, CheckResult
from lynx_patch_watch.checkers.composer_json import ComposerJsonChecker
from lynx_patch_watch.checkers.composer_lock import ComposerLockChecker
from lynx_patch_watch.checkers.custom_rule import CustomRuleChecker
from lynx_patch_watch.checkers.feature_file import FeatureFileChecker
from lynx_patch_watch.checkers.git_commit import GitCommitChecker
from lynx_patch_watch.checkers.hotfix_dir import HotfixDirChecker

CHECKERS: list[Checker] = [
    ComposerLockChecker(),
    ComposerJsonChecker(),
    FeatureFileChecker(),
    HotfixDirChecker(),
    GitCommitChecker(),
    CustomRuleChecker(),
]

__all__ = [
    "CHECKERS",
    "CheckContext",
    "Checker",
    "CheckResult",
]
