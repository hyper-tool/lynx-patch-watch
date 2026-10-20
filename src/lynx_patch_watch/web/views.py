"""Web routes: auth, dashboard, matrix, advisories, projects, reviews, excel, API."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from lynx_patch_watch.engine.orchestrator import (
    project_advisory_status,
    project_item_statuses,
)
from lynx_patch_watch.store import Store, valid_project_id
from lynx_patch_watch.web.auth import (
    CSRF_FORM_FIELD,
    CSRF_HEADER,
    SESSION_COOKIE,
    Session,
)
from lynx_patch_watch.web.middleware import resolve_client_ip
from lynx_patch_watch.web.presenters import (
    days_since,
    fix_kind_zh,
    format_date,
    parse_json_dict,
    parse_json_list,
    redact_git_url,
    severity_zh,
    status_zh,
)

logger = logging.getLogger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _templates(request: Request):
    return request.app.state.templates


def _store(request: Request) -> Store:
    return request.app.state.store


def _client_ip(request: Request) -> str:
    """Client IP for login rate limiting (same resolution as the IP allowlist)."""
    trust = bool(request.app.state.settings.web.trust_x_forwarded_for)
    return resolve_client_ip(request, trust_x_forwarded_for=trust) or "unknown"


def _safe_next(value: Any) -> str:
    """Only allow same-origin relative paths as post-login redirect targets."""
    target = str(value or "/")
    parts = urlsplit(target)
    if (
        not target.startswith("/")
        or target.startswith("//")
        or "\\" in target
        or parts.scheme
        or parts.netloc
        or any(ord(ch) < 0x20 for ch in target)
    ):
        return "/"
    return target


def _check_csrf(request: Request, form: dict[str, Any]) -> bool:
    auth = request.app.state.auth
    token = request.cookies.get(SESSION_COOKIE)
    submitted = form.get(CSRF_FORM_FIELD) or request.headers.get(CSRF_HEADER)
    return auth.check_csrf(token, submitted)


def _csrf_token(request: Request) -> str:
    auth = request.app.state.auth
    token = request.cookies.get(SESSION_COOKIE)
    return auth._csrf_for_session(token) or ""


def _context(request: Request, **extra: Any) -> dict[str, Any]:
    ctx = {
        "request": request,
        "csrf_token": _csrf_token(request),
        "status_zh": status_zh,
        "severity_zh": severity_zh,
        "fix_kind_zh": fix_kind_zh,
        "format_date": format_date,
        "days_since": days_since,
        "redact_git_url": redact_git_url,
        "parse_json_dict": parse_json_dict,
        "parse_json_list": parse_json_list,
    }
    ctx.update(extra)
    return ctx


def _render(request: Request, template: str, *, status_code: int = 200, **ctx: Any) -> HTMLResponse:
    return _templates(request).TemplateResponse(
        request, template, _context(request, **ctx), status_code=status_code
    )


async def _form(request: Request) -> dict[str, Any]:
    form = await request.form()
    return {k: v for k, v in form.items()}


# ---------------------------------------------------------------------------
# auth
# ---------------------------------------------------------------------------


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: Optional[str] = None, next: Optional[str] = None):
    return _render(request, "login.html", error=error, next=next or "/")


@router.post("/login")
async def login(request: Request):
    form = await _form(request)
    auth = request.app.state.auth
    ip = _client_ip(request)
    if auth.login_blocked(ip):
        return _render(request, "login.html", error="登录失败次数过多，请稍后再试", next=form.get("next") or "/")
    username = str(form.get("username") or "").strip()
    password = str(form.get("password") or "")
    if username != "admin" or not auth.verify_password(password):
        auth.record_login_failure(ip)
        return _render(request, "login.html", error="用户名或密码错误", next=form.get("next") or "/")
    auth.clear_login_failures(ip)
    token = auth.issue_session("admin")
    response = RedirectResponse(_safe_next(form.get("next")), status_code=303)
    response.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        samesite="strict",
        secure=request.url.scheme == "https",
        max_age=auth.config.idle_timeout_minutes * 60,
    )
    return response


@router.post("/logout")
async def logout(request: Request):
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE)
    return response


# ---------------------------------------------------------------------------
# dashboard
# ---------------------------------------------------------------------------


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    store = _store(request)
    projects = store.list_projects()
    advisories = store.list_advisories()

    by_type: dict[str, int] = {}
    for p in projects:
        key = p.get("detected_type") or p.get("type") or "unknown"
        by_type[key] = by_type.get(key, 0) + 1

    projects_with_open = 0
    severity_open: dict[str, int] = {}
    conflicts = 0
    stale_reviews = 0
    for project in projects:
        counts = store.count_latest_by_status(project["id"])
        if counts["vulnerable"] or counts["conflict"] or counts["unknown"] or counts["error"]:
            projects_with_open += 1
        conflicts += counts["conflict"]
        for finding in store.list_latest_findings(project["id"]):
            item = store.get_advisory_item(finding["item_id"])
            if item and finding["status"] in ("vulnerable", "conflict", "unknown"):
                sev = item.get("severity") or "unknown"
                severity_open[sev] = severity_open.get(sev, 0) + 1
        for review in store.list_manual_reviews(project["id"]):
            if review.get("stale"):
                stale_reviews += 1

    failed_scans = store.recent_failed_scans(limit=5)

    # Fix coverage for the latest 3 advisories.
    latest_advisories = advisories[:3]
    coverage = []
    for adv in latest_advisories:
        items = store.list_advisory_items(adv["id"])
        total = 0
        fixed = 0
        for item in items:
            if not items:
                continue
            total += 1
            # coverage counts only projects that scanned this item
            fixed_here = 0
            scanned = 0
            for project in projects:
                finding = store.get_latest_finding(project["id"], item["item_id"])
                if finding is None:
                    continue
                scanned += 1
                if finding["status"] == "fixed":
                    fixed_here += 1
            if scanned:
                fixed += fixed_here / scanned
        coverage.append(
            {
                "advisory": adv,
                "coverage": (fixed / total) if total else None,
                "items": total,
            }
        )

    return _render(
        request,
        "dashboard.html",
        projects=projects,
        advisories=advisories,
        by_type=by_type,
        projects_with_open=projects_with_open,
        severity_open=severity_open,
        conflicts=conflicts,
        stale_reviews=stale_reviews,
        failed_scans=failed_scans,
        coverage=coverage,
    )


# ---------------------------------------------------------------------------
# matrix
# ---------------------------------------------------------------------------


@router.get("/matrix", response_class=HTMLResponse)
async def matrix(request: Request):
    store = _store(request)
    projects = store.list_projects()
    advisories = store.list_advisories()
    rows = []
    for project in projects:
        statuses = project_advisory_status(store, project["id"])
        rows.append({"project": project, "statuses": statuses})
    return _render(request, "matrix.html", rows=rows, advisories=advisories, projects=projects)


# ---------------------------------------------------------------------------
# advisories
# ---------------------------------------------------------------------------


@router.get("/advisories", response_class=HTMLResponse)
async def advisories_page(request: Request):
    store = _store(request)
    advisories = store.list_advisories()
    return _render(request, "advisories.html", advisories=advisories)


@router.get("/advisories/{advisory_id}", response_class=HTMLResponse)
async def advisory_detail(request: Request, advisory_id: str):
    store = _store(request)
    adv = store.get_advisory(advisory_id)
    if adv is None:
        return _render(request, "error.html", message=f"公告 {advisory_id} 不存在", status_code=404)
    items = store.list_advisory_items(advisory_id)
    affected_projects = []
    for project in store.list_projects():
        statuses = project_item_statuses(store, project["id"]).get(advisory_id, [])
        # Only surface projects with real scan data for this advisory; purely
        # unscanned projects are represented as 未知 on the matrix instead.
        if statuses and any(s != "unknown" for s in statuses):
            affected_projects.append({"project": project, "statuses": statuses})
    return _render(
        request,
        "advisory_detail.html",
        advisory=adv,
        items=items,
        affected_projects=affected_projects,
    )


# ---------------------------------------------------------------------------
# rules (read-only)
# ---------------------------------------------------------------------------


@router.get("/rules", response_class=HTMLResponse)
async def rules_page(request: Request):
    ruleset = request.app.state.ruleset
    return _render(request, "rules.html", rules=ruleset.rules)


# ---------------------------------------------------------------------------
# API (read-only token for the Magento module)
# ---------------------------------------------------------------------------


@router.get("/api/projects/{project_id}/status")
async def api_project_status(request: Request, project_id: str, token: str = ""):
    store = _store(request)
    if not verify_api_token(store, token):
        return JSONResponse({"detail": "invalid token"}, status_code=403)
    project = store.get_project(project_id)
    if project is None:
        return JSONResponse({"detail": "unknown project"}, status_code=404)
    statuses = project_advisory_status(store, project_id)
    from datetime import datetime, timezone

    return {
        "project": project_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "advisories": statuses,
    }


def verify_api_token(store: Store, token: str) -> bool:
    import hashlib

    stored = store.get_setting("api_token_hash")
    if not stored or not token:
        return False
    return hashlib.sha256(token.encode()).hexdigest() == stored


# ---------------------------------------------------------------------------
# projects (management)
# ---------------------------------------------------------------------------

SCAN_MODE_ZH = {"git": "Git 仓库", "local": "本地目录", "manual": "手动登记"}
PROJECT_TYPE_ZH = {"auto": "自动识别", "magento": "Magento"}


def _project_view(store: Store, project: dict[str, Any]) -> dict[str, Any]:
    counts = store.count_latest_by_status(project["id"])
    last_run = store.latest_scan_run(project["id"])
    applicable = counts["fixed"] + counts["vulnerable"] + counts["conflict"] + counts["declared"] + counts["unknown"]
    maintenance = (counts["fixed"] / applicable) if applicable else None
    # longest unfixed age
    longest = 0
    for finding in store.list_latest_findings(project["id"]):
        if finding["status"] in ("vulnerable", "conflict", "unknown"):
            first = store.first_finding_time(project["id"], finding["item_id"])
            age = days_since(first)
            if age:
                longest = max(longest, age)
    return {
        "project": project,
        "counts": counts,
        "last_run": last_run,
        "maintenance": maintenance,
        "applicable": applicable,
        "longest_open_days": longest,
    }


@router.get("/projects", response_class=HTMLResponse)
async def projects_page(request: Request, q: Optional[str] = None, scan_mode: Optional[str] = None):
    store = _store(request)
    projects = store.list_projects()
    if q:
        projects = [p for p in projects if q.lower() in (p.get("name") or "").lower() or q in p["id"]]
    if scan_mode:
        projects = [p for p in projects if p.get("scan_mode") == scan_mode]
    rows = [_project_view(store, p) for p in projects]
    jobs = store.list_scan_jobs(limit=10)
    return _render(
        request,
        "projects.html",
        rows=rows,
        jobs=jobs,
        q=q or "",
        scan_mode=scan_mode or "",
        scan_mode_zh=SCAN_MODE_ZH,
        project_type_zh=PROJECT_TYPE_ZH,
    )


@router.post("/projects")
async def project_create(request: Request):
    form = await _form(request)
    if not _check_csrf(request, form):
        return _render(request, "error.html", message="CSRF 校验失败", status_code=403)
    store = _store(request)
    project_id = str(form.get("id") or "").strip()
    if not valid_project_id(project_id):
        return _render(
            request,
            "error.html",
            message="项目 ID 必须匹配 ^[a-z0-9][a-z0-9_-]{1,63}$（小写字母/数字/下划线/连字符，2-64 位）",
            status_code=400,
        )
    if store.get_project(project_id) is not None:
        return _render(request, "error.html", message=f"项目 {project_id} 已存在", status_code=400)
    record = _project_from_form(form)
    record["id"] = project_id
    store.upsert_project(record)
    store.audit("admin", "project.create", project_id)
    return RedirectResponse(f"/projects/{project_id}", status_code=303)


def _project_from_form(form: dict[str, Any]) -> dict[str, Any]:
    patches = [p.strip() for p in str(form.get("declared_patches") or "").replace("，", ",").split(",") if p.strip()]
    owners = [o.strip() for o in str(form.get("owners") or "").replace("，", ",").split(",") if o.strip()]
    enabled = str(form.get("enabled") or "").lower() in ("1", "true", "on", "yes", "是")
    return {
        "name": str(form.get("name") or "").strip() or str(form.get("id") or ""),
        "type": str(form.get("type") or "auto"),
        "scan_mode": str(form.get("scan_mode") or "manual"),
        "git_url": str(form.get("git_url") or "").strip() or None,
        "branch": str(form.get("branch") or "main").strip() or "main",
        "local_path": str(form.get("local_path") or "").strip() or None,
        "declared_version": str(form.get("declared_version") or "").strip() or None,
        "declared_edition": str(form.get("declared_edition") or "").strip() or None,
        "declared_patches": patches,
        "owners": owners,
        "env": str(form.get("env") or "").strip() or None,
        "notes": str(form.get("notes") or "").strip() or None,
        "enabled": enabled,
    }


@router.get("/projects/{project_id}", response_class=HTMLResponse)
async def project_detail(request: Request, project_id: str):
    store = _store(request)
    project = store.get_project(project_id)
    if project is None:
        return _render(request, "error.html", message=f"项目 {project_id} 不存在", status_code=404)
    view = _project_view(store, project)

    # per-item checker results from the latest scan run
    latest_run = store.latest_scan_run(project_id)
    item_results: dict[str, list[dict[str, Any]]] = {}
    if latest_run:
        from lynx_patch_watch.store import Store as _S  # noqa: F401

        with store.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM check_results WHERE scan_run_id=? ORDER BY id",
                (latest_run["id"],),
            ).fetchall()
        for row in rows:
            item_results.setdefault(row["item_id"], []).append(
                {
                    "checker": row["checker"],
                    "outcome": row["outcome"],
                    "confidence": row["confidence"],
                    "evidence": parse_json_dict(row["evidence_json"]),
                }
            )

    items = []
    for item in store.list_advisory_items():
        finding = store.get_latest_finding(project_id, item["item_id"])
        if finding is None and latest_run is None:
            continue
        review = store.get_manual_review(project_id, item["item_id"])
        items.append(
            {
                "item": item,
                "finding": finding,
                "review": review,
                "results": item_results.get(item["item_id"], []),
            }
        )

    history = store.list_scan_runs(project_id, limit=20)
    jobs = [j for j in store.list_scan_jobs(limit=50) if j["project_id"] == project_id][:10]
    advisories = {a["id"]: a for a in store.list_advisories()}
    return _render(
        request,
        "project_detail.html",
        view=view,
        project=project,
        items=items,
        history=history,
        jobs=jobs,
        advisories=advisories,
        scan_mode_zh=SCAN_MODE_ZH,
        project_type_zh=PROJECT_TYPE_ZH,
    )


@router.post("/projects/{project_id}/update")
async def project_update(request: Request, project_id: str):
    form = await _form(request)
    if not _check_csrf(request, form):
        return _render(request, "error.html", message="CSRF 校验失败", status_code=403)
    store = _store(request)
    if store.get_project(project_id) is None:
        return _render(request, "error.html", message=f"项目 {project_id} 不存在", status_code=404)
    record = _project_from_form(form)
    record["id"] = project_id
    store.upsert_project(record)
    store.audit("admin", "project.update", project_id)
    return RedirectResponse(f"/projects/{project_id}", status_code=303)


@router.post("/projects/{project_id}/toggle")
async def project_toggle(request: Request, project_id: str):
    form = await _form(request)
    if not _check_csrf(request, form):
        return _render(request, "error.html", message="CSRF 校验失败", status_code=403)
    store = _store(request)
    project = store.get_project(project_id)
    if project is None:
        return _render(request, "error.html", message=f"项目 {project_id} 不存在", status_code=404)
    store.upsert_project({"id": project_id, "enabled": not project.get("enabled", True)})
    store.audit("admin", "project.toggle", project_id, {"enabled": not project.get("enabled", True)})
    return RedirectResponse("/projects", status_code=303)


@router.post("/projects/{project_id}/delete")
async def project_delete(request: Request, project_id: str):
    form = await _form(request)
    if not _check_csrf(request, form) or str(form.get("confirm") or "") != project_id:
        return _render(request, "error.html", message="删除需要二次确认（输入项目 ID）", status_code=400)
    store = _store(request)
    if store.get_project(project_id) is None:
        return _render(request, "error.html", message=f"项目 {project_id} 不存在", status_code=404)
    store.delete_project(project_id)
    store.audit("admin", "project.delete", project_id)
    return RedirectResponse("/projects", status_code=303)


@router.post("/projects/{project_id}/scan")
async def project_scan(request: Request, project_id: str):
    form = await _form(request)
    if not _check_csrf(request, form):
        return _render(request, "error.html", message="CSRF 校验失败", status_code=403)
    store = _store(request)
    project = store.get_project(project_id)
    if project is None:
        return _render(request, "error.html", message=f"项目 {project_id} 不存在", status_code=404)
    job_id = store.enqueue_scan_job(project_id, trigger="web")
    store.audit("admin", "scan.enqueue", project_id, {"job_id": job_id})
    return RedirectResponse(f"/projects/{project_id}", status_code=303)


@router.post("/projects/{project_id}/review")
async def project_review(request: Request, project_id: str):
    form = await _form(request)
    if not _check_csrf(request, form):
        return _render(request, "error.html", message="CSRF 校验失败", status_code=403)
    store = _store(request)
    if store.get_project(project_id) is None:
        return _render(request, "error.html", message=f"项目 {project_id} 不存在", status_code=404)
    item_id = str(form.get("item_id") or "").strip() or None
    status = str(form.get("status") or "").strip()
    allowed = {"confirmed_fixed", "confirmed_vulnerable", "ignored", "false_positive", "pending"}
    if status not in allowed:
        return _render(request, "error.html", message=f"不支持的确认状态: {status}", status_code=400)
    finding = store.get_latest_finding(project_id, item_id or "")
    store.upsert_manual_review(
        project_id=project_id,
        item_id=item_id,
        status=status,
        note=str(form.get("note") or "").strip() or None,
        reviewer=str(form.get("reviewer") or "").strip() or "admin",
        due_date=str(form.get("due_date") or "").strip() or None,
        evidence_hash_at_review=(finding or {}).get("evidence_hash"),
    )
    store.audit("admin", "review.upsert", project_id, {"item_id": item_id, "status": status})
    return RedirectResponse(f"/projects/{project_id}", status_code=303)


# ---------------------------------------------------------------------------
# history
# ---------------------------------------------------------------------------


@router.get("/history", response_class=HTMLResponse)
async def history_page(request: Request):
    store = _store(request)
    projects = store.list_projects()
    advisories = store.list_advisories()
    latest_by_project = {p["id"]: store.list_latest_findings(p["id"]) for p in projects}
    times = store.finding_times()
    mttr_rows = []
    for project in projects:
        for finding in latest_by_project[project["id"]]:
            first, fixed = times.get((project["id"], finding["item_id"]), (None, None))
            if first and fixed:
                mttr_rows.append(
                    {
                        "project": project["id"],
                        "item_id": finding["item_id"],
                        "first": first,
                        "fixed": fixed,
                    }
                )
    series = _open_series(store, projects)
    item_advisory = {i["item_id"]: i["advisory_id"] for i in store.list_advisory_items()}
    advisory_progress = []
    for adv in advisories[:10]:
        points = []
        for project in projects:
            for f in latest_by_project[project["id"]]:
                if item_advisory.get(f["item_id"]) == adv["id"] and f["status"] == "fixed":
                    fixed_at = times.get((project["id"], f["item_id"]), (None, None))[1]
                    if fixed_at:
                        points.append((fixed_at[:10], 1))
        advisory_progress.append({"advisory": adv, "points": points})
    return _render(
        request,
        "history.html",
        mttr_rows=mttr_rows,
        series=series,
        advisory_progress=advisory_progress,
        projects=projects,
    )


def _open_series(store: Store, projects: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Open (unfixed) finding counts per project over scan runs."""
    series: list[dict[str, Any]] = []
    for project in projects:
        runs = list(reversed(store.list_scan_runs(project["id"], limit=30)))
        counts = store.open_counts_by_scan_run([run["id"] for run in runs])
        points = [
            {"date": (run.get("finished_at") or run.get("started_at") or "")[:10], "open": counts.get(run["id"], 0)}
            for run in runs
        ]
        series.append({"project": project["id"], "points": points})
    return series


# ---------------------------------------------------------------------------
# excel
# ---------------------------------------------------------------------------


@router.get("/excel", response_class=HTMLResponse)
async def excel_page(request: Request):
    return _render(request, "excel.html", message=None)


@router.get("/excel/template")
async def excel_template(request: Request):
    from lynx_patch_watch.excel.template import build_template

    content = build_template()
    return Response(
        content,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=lpw-template.xlsx"},
    )


@router.get("/excel/export")
async def excel_export(request: Request):
    from lynx_patch_watch.excel.exporter import build_export

    store = _store(request)
    content = build_export(store)
    return Response(
        content,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=lpw-export.xlsx"},
    )


@router.post("/excel/import")
async def excel_import(request: Request, file: UploadFile):
    from lynx_patch_watch.excel.importer import import_preview, apply_import

    store = _store(request)
    form = await _form(request)
    if not _check_csrf(request, form):
        return _render(request, "error.html", message="CSRF 校验失败", status_code=403)
    if not file.filename or not file.filename.endswith(".xlsx"):
        return _render(request, "excel.html", message="仅支持 .xlsx 文件（.xlsm 会被拒绝）")
    content = await file.read()
    if len(content) > 5 * 1024 * 1024:
        return _render(request, "excel.html", message="文件过大（>5MB）")
    dry_run = "apply" not in form
    preview = import_preview(store, content)
    if dry_run:
        return _render(request, "excel.html", message="预览模式", preview=preview)
    result = apply_import(store, content, actor="admin")
    store.audit("admin", "excel.import", file.filename, result.summary())
    return _render(request, "excel.html", message="导入完成", preview=preview, result=result)
