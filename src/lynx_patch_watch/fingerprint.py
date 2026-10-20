"""Unified-diff fingerprinting.

Ported from msw ``fingerprint.py``: ``parse_unified_diff``,
``validate_fingerprints``, ``fingerprint_set_hash``, ``write_fingerprint_bundle``,
``FingerprintBuilder``. msw: src/magento_security_watcher/fingerprint.py
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from lynx_patch_watch.models import ContentFingerprint


_HUNK_RE = re.compile(r"^@@.*?@@", re.MULTILINE)
_DIFF_HEADER_RE = re.compile(
    r"^diff --git a/(?P<a>.+?) b/(?P<b>.+?)$",
    re.MULTILINE,
)
_PLUS_FILE_RE = re.compile(r"^\+\+\+ [ab]/(?P<path>.+)$", re.MULTILINE)


def parse_unified_diff(patch_text: str) -> list[ContentFingerprint]:
    """Extract before/after fingerprints from a unified diff (deterministic)."""
    fingerprints: list[ContentFingerprint] = []
    files = _split_diff_by_file(patch_text)
    for path, body in files:
        hunks = _split_hunks(body)
        for idx, hunk in enumerate(hunks):
            before_lines, after_lines = _hunk_lines(hunk)
            before = _pick_snippet(before_lines)
            after = _pick_snippet(after_lines)
            if not before and not after:
                continue
            fingerprints.append(
                ContentFingerprint(
                    path=path,
                    before=before or None,
                    after=after or None,
                    hunk_id=f"{path}#{idx}",
                    critical=True,
                )
            )
    return fingerprints


def _split_diff_by_file(patch_text: str) -> list[tuple[str, str]]:
    matches = list(_DIFF_HEADER_RE.finditer(patch_text))
    if not matches:
        # Single-file patches sometimes only have +++ header
        m = _PLUS_FILE_RE.search(patch_text)
        if m:
            return [(m.group("path").strip(), patch_text)]
        return []
    out: list[tuple[str, str]] = []
    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(patch_text)
        path = m.group("b").strip()
        out.append((path, patch_text[start:end]))
    return out


def _split_hunks(file_body: str) -> list[str]:
    parts = _HUNK_RE.split(file_body)
    # parts[0] is preamble; remaining alternate? Actually split removes delimiters.
    # Re-find hunks with content after each @@
    hunks: list[str] = []
    positions = list(_HUNK_RE.finditer(file_body))
    for i, m in enumerate(positions):
        start = m.end()
        end = positions[i + 1].start() if i + 1 < len(positions) else len(file_body)
        hunks.append(file_body[start:end])
    return hunks


def _hunk_lines(hunk: str) -> tuple[list[str], list[str]]:
    before: list[str] = []
    after: list[str] = []
    for line in hunk.splitlines():
        if not line:
            continue
        if line.startswith("---") or line.startswith("+++"):
            continue
        if line.startswith("-"):
            before.append(line[1:])
        elif line.startswith("+"):
            after.append(line[1:])
    return before, after


def _pick_snippet(lines: list[str], max_chars: int = 240) -> str:
    meaningful = [ln for ln in lines if ln.strip() and not ln.strip().startswith("#")]
    if not meaningful:
        meaningful = [ln for ln in lines if ln.strip()]
    if not meaningful:
        return ""
    # Prefer a mid-length distinctive line
    candidate = max(meaningful, key=lambda s: min(len(s.strip()), 80))
    snippet = candidate.strip()
    if len(snippet) > max_chars:
        snippet = snippet[: max_chars - 3] + "..."
    return snippet


def validate_fingerprints(fps: list[ContentFingerprint]) -> list[ContentFingerprint]:
    """Schema-ish validation: keep only fingerprints with path and at least one side."""
    valid: list[ContentFingerprint] = []
    for fp in fps:
        if not fp.path or not fp.path.strip():
            continue
        if not (fp.before or fp.after):
            continue
        # reject overly generic snippets
        for side in (fp.before, fp.after):
            if side and len(side.strip()) < 8:
                break
        else:
            valid.append(fp)
            continue
        # if broke due to short snippet but other side ok, still keep if other is long enough
        if (fp.before and len(fp.before.strip()) >= 8) or (fp.after and len(fp.after.strip()) >= 8):
            valid.append(fp)
    return valid


def fingerprint_set_hash(fps: list[ContentFingerprint]) -> str:
    payload = "|".join(
        f"{fp.path}:{fp.before or ''}->{fp.after or ''}" for fp in sorted(fps, key=lambda x: (x.path, x.hunk_id or ""))
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def write_fingerprint_bundle(path: Path, fps: list[ContentFingerprint]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps([fp.model_dump() for fp in fps], indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


class FingerprintBuilder:
    """Build fingerprints from patch text: rules first, optional AI draft merge."""

    def __init__(self, llm_client: object | None = None) -> None:
        self.llm_client = llm_client

    def build(self, patch_text: str, *, allow_ai_draft: bool = True) -> list[ContentFingerprint]:
        rule_fps = validate_fingerprints(parse_unified_diff(patch_text))
        if not allow_ai_draft or self.llm_client is None:
            return rule_fps
        try:
            draft = self.llm_client.draft_fingerprints(patch_text)  # type: ignore[attr-defined]
        except Exception:
            return rule_fps
        merged = {f"{fp.path}|{fp.before}|{fp.after}": fp for fp in rule_fps}
        for fp in validate_fingerprints(draft or []):
            key = f"{fp.path}|{fp.before}|{fp.after}"
            merged.setdefault(key, fp)
        return list(merged.values())
