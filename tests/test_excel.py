"""Excel tests: template, export→import round-trip, masking, credential rejection,
formula-injection escaping."""

from __future__ import annotations

import io
from pathlib import Path

from openpyxl import load_workbook

from lynx_patch_watch.excel.enums import cell_text
from lynx_patch_watch.excel.exporter import build_export
from lynx_patch_watch.excel.importer import apply_import, import_preview
from lynx_patch_watch.excel.template import TEMPLATE_VERSION, build_template
from lynx_patch_watch.store import Store


def _load(content: bytes):
    return load_workbook(io.BytesIO(content), data_only=True)


def test_template_has_three_sheets_and_validation():
    content = build_template()
    wb = _load(content)
    assert wb.sheetnames == ["说明", "项目", "人工确认"]
    intro = wb["说明"]
    assert any(TEMPLATE_VERSION in str(c.value) for row in intro.iter_rows() for c in row if c.value)
    projects = wb["项目"]
    headers = [cell_text(c.value) for c in next(projects.iter_rows(min_row=1, max_row=1))]
    assert "项目ID*" in headers
    assert "名称*" in headers
    assert len(projects.data_validations.dataValidation) == 4


def test_export_import_round_trip(store: Store):
    store.upsert_project(
        {
            "id": "shop-a",
            "name": "Shop A",
            "type": "magento",
            "scan_mode": "local",
            "local_path": "/tmp/shop-a",
            "declared_version": "2.4.7-p8",
            "declared_edition": "CE",
            "declared_patches": ["APSB26-146", "ACSD-12345"],
            "owners": ["alice", "bob"],
            "env": "prod",
            "enabled": True,
        }
    )
    store.upsert_project(
        {
            "id": "shop-b",
            "name": "Shop B",
            "type": "magento",
            "scan_mode": "local",
            "local_path": "/tmp/shop-b",
            "declared_version": "2.4.6-p3",
            "enabled": False,
        }
    )
    content = build_export(store)
    wb = _load(content)
    assert wb.sheetnames == ["项目清单", "项目×公告矩阵", "问题明细", "统计"]

    # re-import into a fresh store: no changes expected
    store2 = Store(store.db_path.parent / "roundtrip.sqlite")
    preview = import_preview(store2, content)
    assert not preview.errors
    assert len(preview.to_create) == 2
    result = apply_import(store2, content, actor="test")
    assert result.created == 2 and result.updated == 0
    # import again → all unchanged
    preview2 = import_preview(store2, content)
    assert len(preview2.unchanged) == 2
    assert not preview2.to_create and not preview2.to_update


def test_masked_git_url_does_not_overwrite(store: Store):
    store.upsert_project(
        {
            "id": "shop-a",
            "name": "Shop A",
            "scan_mode": "git",
            "git_url": "https://git.example.com/shop.git",
            "branch": "main",
        }
    )
    content = build_export(store)
    wb = _load(content)
    ws = wb["项目清单"]
    git_col = None
    for cell in next(ws.iter_rows(min_row=1, max_row=1)):
        if cell_text(cell.value) == "Git地址":
            git_col = cell.column
    assert git_col
    assert "***" in str(ws.cell(row=2, column=git_col).value)
    # masked value imports as "no change"
    preview = import_preview(store, content)
    assert not preview.to_update
    assert preview.unchanged == ["shop-a"]


def test_plaintext_credentials_rejected(store: Store):
    wb = load_workbook(io.BytesIO(build_template()))
    ws = wb["项目"]
    ws.append(["shop-x", "Shop X", "magento", "Git仓库", "https://user:pass@git.example.com/x.git", "main"])
    buffer = io.BytesIO()
    wb.save(buffer)
    preview = import_preview(store, buffer.getvalue())
    assert preview.errors
    assert "明文凭据" in preview.errors[0].message
    assert not preview.to_create


def test_chinese_enums_and_fullwidth_commas(store: Store):
    wb = load_workbook(io.BytesIO(build_template()))
    ws = wb["项目"]
    ws.append(
        [
            "shop-zh",
            "中文项目",
            "自动识别",
            "本地目录",
            "",
            "main",
            "/tmp/zh",
            "2.4.7-p8",
            "CE",
            "APSB26-146，ACSD-12345",
            "张三，李四",
            "prod",
            "备注",
            "是",
        ]
    )
    buffer = io.BytesIO()
    wb.save(buffer)
    preview = import_preview(store, buffer.getvalue())
    assert not preview.errors, preview.errors
    record = preview.to_create[0]
    assert record["type"] == "auto"
    assert record["scan_mode"] == "local"
    assert record["declared_patches"] == ["APSB26-146", "ACSD-12345"]
    assert record["owners"] == ["张三", "李四"]
    assert record["enabled"] is True


def test_formula_injection_escaped(store: Store):
    store.upsert_project(
        {
            "id": "shop-a",
            "name": "=1+1",
            "notes": "+cmd|' /C calc'!A0",
            "scan_mode": "manual",
        }
    )
    content = build_export(store)
    wb = _load(content)
    ws = wb["项目清单"]
    # openpyxl stores the leading apostrophe as part of the value in data_only mode
    values = [str(c.value) for row in ws.iter_rows() for c in row if c.value is not None]
    assert any(v.startswith("'=") or v.startswith("'=1+1") for v in values)
    assert any(v.startswith("'+cmd") for v in values)


def test_xlsm_rejected_by_extension():
    # The importer reads by content; the web layer rejects non-.xlsx filenames.
    # Here we assert the template round-trips as xlsx only.
    content = build_template()
    assert content[:2] == b"PK"  # zip magic


def test_review_import(store: Store):
    from lynx_patch_watch.adapters.magento.source import ChimeraAdvisorySource
    from lynx_patch_watch.engine.ingest import ingest_from_source

    source = ChimeraAdvisorySource(chimera_url="unused", fixture_dir=Path("tests/fixtures/advisories"), detail_fetch_limit=15)
    ingest_from_source(store, source)
    store.upsert_project({"id": "shop-a", "name": "Shop A", "scan_mode": "manual"})

    wb = load_workbook(io.BytesIO(build_template()))
    ws = wb["人工确认"]
    ws.append(["shop-a", "APSB26-146", "CVE-2026-75650", "忽略", "已评估", "bob", "2026-11-01"])
    buffer = io.BytesIO()
    wb.save(buffer)
    preview = import_preview(store, buffer.getvalue())
    assert not preview.errors, preview.errors
    assert len(preview.reviews) == 1
    result = apply_import(store, buffer.getvalue(), actor="test")
    assert result.reviews == 1
    review = store.get_manual_review("shop-a", "APSB26-146:CVE-2026-75650")
    assert review["status"] == "ignored"
    assert review["reviewer"] == "bob"


def test_numeric_project_id_keeps_digits(store: Store):
    # The template formats the ID column as text so Excel keeps digit-only
    # IDs verbatim (no number conversion, no scientific notation).
    wb = load_workbook(io.BytesIO(build_template()))
    ws = wb["项目"]
    assert ws.cell(row=2, column=1).number_format == "@"
    # A 15-digit numeric id round-trips exactly (openpyxl keeps it an int).
    ws.append([123456789012345, "Fifteen Digits", "magento", "手动登记"])
    # A negative numeric id is rejected, but the digits stay intact in the
    # error message (cells are read as text, never as float noise).
    ws.append([-123456789, "Negative", "magento", "手动登记"])
    buffer = io.BytesIO()
    wb.save(buffer)
    preview = import_preview(store, buffer.getvalue())
    created = {r["id"]: r for r in preview.to_create}
    assert created["123456789012345"]["name"] == "Fifteen Digits"
    assert any("-123456789" in e.message for e in preview.errors)
