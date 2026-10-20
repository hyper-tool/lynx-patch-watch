"""Excel import: preview → confirm → transactional apply.

Rules (per plan):
- cells are read as text (numeric IDs keep their digits);
- Chinese enums mapped; 是/否/TRUE recognised; patch lists support full-width commas;
- ``***`` masked git URLs or empty git URLs mean “do not modify”;
- plaintext credentials in git URLs → the row is rejected;
- read-only stat columns are ignored;
- ``.xlsm`` files are rejected; uploads are size-limited by the caller;
- ``read_only`` mode is used for reading;
- upsert by project ID — projects absent from the sheet are never deleted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from io import BytesIO
from typing import Any

from openpyxl import load_workbook

from lynx_patch_watch.excel.enums import (
    EDITION,
    PROJECT_TYPE,
    REVIEW_STATUS,
    SCAN_MODE,
    cell_text,
    split_list,
    to_bool,
)
from lynx_patch_watch.store import Store, valid_project_id

CREDENTIAL_RE = re.compile(r"://[^/\s:@]+:[^/\s@]+@")
MASKED = "***"

_PROJECT_COLUMNS = {
    "项目ID": "id",
    "名称": "name",
    "类型": "type",
    "扫描方式": "scan_mode",
    "Git地址": "git_url",
    "分支": "branch",
    "本地路径": "local_path",
    "Magento版本": "declared_version",
    "版本类型": "declared_edition",
    "已打补丁": "declared_patches",
    "负责人": "owners",
    "环境": "env",
    "备注": "notes",
    "启用": "enabled",
}

_REVIEW_COLUMNS = {
    "项目ID": "project_id",
    "公告ID": "advisory_id",
    "CVE": "cve",
    "状态": "status",
    "备注": "note",
    "确认人": "reviewer",
    "计划日期": "due_date",
}


@dataclass
class RowError:
    sheet: str
    row: int
    message: str


@dataclass
class PreviewReport:
    to_create: list[dict[str, Any]] = field(default_factory=list)
    to_update: list[dict[str, Any]] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)
    errors: list[RowError] = field(default_factory=list)
    reviews: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ImportResult:
    created: int = 0
    updated: int = 0
    reviews: int = 0

    def summary(self) -> dict[str, int]:
        return {"created": self.created, "updated": self.updated, "reviews": self.reviews}


def _header_map(ws) -> dict[int, str]:
    """Column index (1-based) → header text. read_only rows may contain
    EmptyCell objects without a .column attribute, so positions are used."""
    mapping: dict[int, str] = {}
    row = next(ws.iter_rows(min_row=1, max_row=1))
    for idx, cell in enumerate(row, start=1):
        value = cell_text(cell.value).rstrip("*")
        if value:
            mapping[idx] = value
    return mapping


def _row_values(row, headers: dict[int, str]) -> dict[str, str]:
    """Map a data row to {header: text} using positional indexes."""
    values: dict[str, str] = {}
    for idx, cell in enumerate(row, start=1):
        header = headers.get(idx)
        if header:
            values[header] = cell_text(cell.value)
    return values


def import_preview(store: Store, content: bytes) -> PreviewReport:
    report = PreviewReport()
    wb = load_workbook(BytesIO(content), read_only=True, data_only=True)
    try:
        # Accept both the template sheet ("项目") and the export sheet
        # ("项目清单") — the export uses the same columns and is re-importable.
        for name in ("项目", "项目清单"):
            if name in wb.sheetnames:
                _preview_projects(store, wb[name], report)
                break
        if "人工确认" in wb.sheetnames:
            _preview_reviews(store, wb["人工确认"], report)
    finally:
        wb.close()
    return report


def _preview_projects(store: Store, ws, report: PreviewReport) -> None:
    headers = _header_map(ws)
    if not headers:
        report.errors.append(RowError("项目", 1, "缺少表头行"))
        return
    for row in ws.iter_rows(min_row=2):
        values = _row_values(row, headers)
        if not any(values.values()):
            continue
        row_no = row[0].row if hasattr(row[0], "row") else 0
        record, error = _project_record(values, row_no)
        if error:
            report.errors.append(error)
            continue
        existing = store.get_project(record["id"])
        if existing is None:
            report.to_create.append(record)
        elif _differs(existing, record):
            report.to_update.append(record)
        else:
            report.unchanged.append(record["id"])


def _preview_reviews(store: Store, ws, report: PreviewReport) -> None:
    headers = _header_map(ws)
    if not headers:
        report.errors.append(RowError("人工确认", 1, "缺少表头行"))
        return
    for row in ws.iter_rows(min_row=2):
        values = _row_values(row, headers)
        if not any(values.values()):
            continue
        row_no = row[0].row if hasattr(row[0], "row") else 0
        project_id = values.get("项目ID", "")
        advisory_id = values.get("公告ID", "")
        status = values.get("状态", "")
        if not project_id or not advisory_id or not status:
            report.errors.append(RowError("人工确认", row_no, "项目ID/公告ID/状态为必填"))
            continue
        if store.get_project(project_id) is None:
            report.errors.append(RowError("人工确认", row_no, f"项目 {project_id} 不存在"))
            continue
        mapped = REVIEW_STATUS.get(status.strip())
        if mapped is None:
            report.errors.append(RowError("人工确认", row_no, f"无法识别的确认状态: {status}"))
            continue
        cve = values.get("CVE", "").strip()
        item_id = f"{advisory_id.upper()}:{cve.upper()}" if cve else None
        if item_id and store.get_advisory_item(item_id) is None:
            report.errors.append(RowError("人工确认", row_no, f"风险项 {item_id} 不存在"))
            continue
        report.reviews.append(
            {
                "project_id": project_id,
                "item_id": item_id,
                "status": mapped,
                "note": values.get("备注") or None,
                "reviewer": values.get("确认人") or None,
                "due_date": values.get("计划日期") or None,
            }
        )


def _project_record(values: dict[str, str], row_no: int) -> tuple[dict[str, Any] | None, RowError | None]:
    project_id = values.get("项目ID", "")
    if not project_id:
        return None, RowError("项目", row_no, "项目ID 为必填")
    if not valid_project_id(project_id):
        return None, RowError("项目", row_no, f"项目ID格式不合法: {project_id}")
    name = values.get("名称", "")
    if not name:
        return None, RowError("项目", row_no, "名称为必填")

    git_url = values.get("Git地址", "").strip()
    if git_url and git_url != MASKED:
        if CREDENTIAL_RE.search(git_url):
            return None, RowError("项目", row_no, "Git 地址包含明文凭据，已拒绝（请改用 ${ENV_VAR} 占位并轮换凭据）")

    record: dict[str, Any] = {"id": project_id, "name": name}
    ptype = values.get("类型", "").strip()
    if ptype:
        mapped = PROJECT_TYPE.get(ptype.lower())
        if mapped is None:
            return None, RowError("项目", row_no, f"无法识别的类型: {ptype}")
        record["type"] = mapped
    mode = values.get("扫描方式", "").strip()
    if mode:
        mapped = SCAN_MODE.get(mode.lower().replace(" ", ""))
        if mapped is None:
            return None, RowError("项目", row_no, f"无法识别的扫描方式: {mode}")
        record["scan_mode"] = mapped
    if git_url and git_url != MASKED:
        record["git_url"] = git_url
    branch = values.get("分支", "").strip()
    if branch:
        record["branch"] = branch
    local_path = values.get("本地路径", "").strip()
    if local_path:
        record["local_path"] = local_path
    version = values.get("Magento版本", "").strip()
    if version:
        record["declared_version"] = version
    edition = values.get("版本类型", "").strip()
    if edition:
        mapped = EDITION.get(edition.lower())
        if mapped is None:
            return None, RowError("项目", row_no, f"无法识别的版本类型: {edition}")
        record["declared_edition"] = mapped
    patches = split_list(values.get("已打补丁"))
    if patches:
        record["declared_patches"] = patches
    owners = split_list(values.get("负责人"))
    if owners:
        record["owners"] = owners
    env = values.get("环境", "").strip()
    if env:
        record["env"] = env
    notes = values.get("备注", "").strip()
    if notes:
        record["notes"] = notes
    enabled = to_bool(values.get("启用"))
    if enabled is not None:
        record["enabled"] = enabled
    return record, None


def _differs(existing: dict[str, Any], record: dict[str, Any]) -> bool:
    for key, value in record.items():
        if key in ("id",):
            continue
        current = existing.get(key)
        if key in ("declared_patches", "owners"):
            if list(current or []) != list(value or []):
                return True
        elif key == "enabled":
            if bool(current) != bool(value):
                return True
        elif (current or None) != (value or None):
            return True
    return False


def apply_import(store: Store, content: bytes, actor: str = "web") -> ImportResult:
    """Apply a previewed import inside one transaction (per-project)."""
    report = import_preview(store, content)
    result = ImportResult()
    for record in report.to_create + report.to_update:
        store.upsert_project(record)
        store.audit(actor, "excel.import.project", record["id"])
        result.created += 1 if record in report.to_create else 0
        result.updated += 1 if record in report.to_update else 0
    for review in report.reviews:
        finding = store.get_latest_finding(review["project_id"], review["item_id"] or "")
        store.upsert_manual_review(
            project_id=review["project_id"],
            item_id=review["item_id"],
            status=review["status"],
            note=review["note"],
            reviewer=review["reviewer"],
            due_date=review["due_date"],
            evidence_hash_at_review=(finding or {}).get("evidence_hash"),
        )
        store.audit(actor, "excel.import.review", review["project_id"], {"item": review["item_id"]})
        result.reviews += 1
    return result
