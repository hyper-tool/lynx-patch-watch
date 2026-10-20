"""Presentation helpers for lpw web templates."""

from __future__ import annotations

import json
from typing import Any, Optional
from urllib.parse import urlparse, urlunparse

STATUS_ZH = {
    "fixed": "已修复",
    "vulnerable": "存在漏洞",
    "conflict": "冲突待复核",
    "declared": "已声明补丁",
    "not_applicable": "不适用",
    "unknown": "未知",
    "error": "检查出错",
    "ignored": "已忽略",
    "false_positive": "误报",
}

SEVERITY_ZH = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "none": "无",
    "unknown": "未知",
}

FIX_KIND_ZH = {
    "upgrade": "升级修复",
    "hotfix": "热修复补丁",
    "both": "升级或补丁",
    "patch": "补丁",
}


def redact_git_url(url: str) -> str:
    """Hide credentials embedded in git URLs (ported from msw presenters)."""
    if not url:
        return ""
    try:
        parsed = urlparse(url)
    except Exception:  # noqa: BLE001
        return "***"
    if parsed.username or parsed.password or "@" in (parsed.netloc or ""):
        host = parsed.hostname or "unknown"
        port = f":{parsed.port}" if parsed.port else ""
        netloc = f"***@{host}{port}"
        return urlunparse((parsed.scheme, netloc, parsed.path, "", parsed.query, ""))
    return url


def status_zh(status: Optional[str]) -> str:
    return STATUS_ZH.get(status or "", STATUS_ZH["unknown"])


def severity_zh(severity: Optional[str]) -> str:
    return SEVERITY_ZH.get(severity or "", SEVERITY_ZH["unknown"])


def fix_kind_zh(kind: Optional[str]) -> str:
    return FIX_KIND_ZH.get(kind or "", "—")


def parse_json_list(raw: Optional[str]) -> list[Any]:
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return []
    return data if isinstance(data, list) else []


def parse_json_dict(raw: Optional[str]) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {}
    return data if isinstance(data, dict) else {}


def format_date(value: Any) -> str:
    if value is None:
        return "—"
    text = str(value).strip()
    if not text:
        return "—"
    return text[:10] if len(text) >= 10 else text


def days_since(value: Any) -> Optional[int]:
    """Whole days between an ISO timestamp and now (None when unparseable)."""
    from datetime import datetime, timezone

    if not value:
        return None
    text = str(value).strip()
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = datetime.now(timezone.utc) - dt
    return max(0, delta.days)
