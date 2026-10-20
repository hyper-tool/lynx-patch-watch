"""Excel enum mappings (Chinese display ↔ internal values)."""

from __future__ import annotations

PROJECT_TYPE = {
    "自动识别": "auto",
    "auto": "auto",
    "magento": "magento",
}

SCAN_MODE = {
    "git仓库": "git",
    "git 仓库": "git",
    "git": "git",
    "本地目录": "local",
    "本地": "local",
    "local": "local",
    "手动登记": "manual",
    "手动": "manual",
    "manual": "manual",
}

EDITION = {
    "ce": "CE",
    "ee": "EE",
    "b2b": "B2B",
}

REVIEW_STATUS = {
    "确认已修": "confirmed_fixed",
    "确认修复": "confirmed_fixed",
    "确认存在漏洞": "confirmed_vulnerable",
    "确认漏洞": "confirmed_vulnerable",
    "忽略": "ignored",
    "误报": "false_positive",
    "待定": "pending",
}

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


def to_bool(value: object) -> bool | None:
    """Chinese/English truthy parsing: 是/否/TRUE/FALSE/1/0."""
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in ("是", "true", "1", "yes", "y", "启用"):
        return True
    if text in ("否", "false", "0", "no", "n", "禁用", ""):
        return False
    return None


def split_list(value: object) -> list[str]:
    """Split comma-separated lists, supporting full-width commas."""
    if value is None:
        return []
    text = str(value).replace("，", ",").replace("、", ",")
    return [part.strip() for part in text.split(",") if part.strip()]


def cell_text(value: object) -> str:
    """Read a cell as text; integral numbers keep their digits (no float noise)."""
    if value is None:
        return ""
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    if isinstance(value, int):
        return str(value)
    return str(value).strip()
