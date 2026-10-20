"""FastAPI application factory with auth, scan worker and IP allowlist."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from markupsafe import Markup, escape
from starlette.middleware.sessions import SessionMiddleware

from lynx_patch_watch.config import AppSettings, ensure_data_dirs, load_env_secrets
from lynx_patch_watch.engine.jobs import ScanWorker
from lynx_patch_watch.engine.rules import RuleSet, load_ruleset
from lynx_patch_watch.store import Store
from lynx_patch_watch.web.auth import (
    Authenticator,
    load_auth_config,
)
from lynx_patch_watch.web.middleware import IPAllowlistMiddleware

logger = logging.getLogger(__name__)

PACKAGE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = PACKAGE_DIR / "templates"
STATIC_DIR = PACKAGE_DIR / "static"

# Routes that never require authentication (/api uses its own token auth).
PUBLIC_PATHS = {"/login", "/static", "/healthz", "/api"}


def create_app(
    root: Optional[Path] = None,
    config_dir: Optional[Path] = None,
    *,
    settings: Optional[AppSettings] = None,
    store: Optional[Store] = None,
    testing: bool = False,
    start_worker: bool = True,
) -> FastAPI:
    """Build the lpw web app (dashboard, matrix, advisories, projects, excel)."""
    root = (root or Path.cwd()).resolve()
    config_dir = (config_dir or (root / "config")).resolve()
    if settings is None:
        from lynx_patch_watch.config import load_settings

        settings = load_settings(config_dir, root)
    paths = ensure_data_dirs(settings)
    if store is None:
        store = Store(settings.db_path)

    app = FastAPI(title="lynx-patch-watch", version="0.1.0", docs_url=None, redoc_url=None)
    app.state.root = root
    app.state.config_dir = config_dir
    app.state.settings = settings
    app.state.store = store
    app.state.paths = paths
    app.state.templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    app.state.templates.env.filters["status_zh"] = _filter_status_zh
    app.state.templates.env.filters["sparkline"] = _filter_sparkline
    app.state.templates.env.globals["status_zh"] = _filter_status_zh
    app.state.templates.env.globals["sparkline"] = _filter_sparkline

    secrets = load_env_secrets(root)
    auth_config = load_auth_config(settings, secrets)
    app.state.auth = Authenticator(auth_config)
    app.state.auth_config = auth_config

    ruleset = load_ruleset(Path(settings.rules.dir))
    app.state.ruleset = ruleset

    app.add_middleware(IPAllowlistMiddleware, allowed_cidrs=settings.web.allowed_cidrs,
                       trust_x_forwarded_for=settings.web.trust_x_forwarded_for, bypass=testing)

    worker: Optional[ScanWorker] = None
    if start_worker:
        worker = ScanWorker(
            store,
            ruleset=ruleset,
            settings=settings,
            locks_dir=paths["locks"],
        )
        worker.set_ruleset_loader(lambda: load_ruleset(Path(settings.rules.dir)))
        app.state.scan_worker = worker
    else:
        app.state.scan_worker = None

    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    from lynx_patch_watch.web.views import router

    app.include_router(router)

    @app.middleware("http")
    async def require_login(request: Request, call_next):
        path = request.url.path
        if any(path == p or path.startswith(p + "/") for p in PUBLIC_PATHS):
            return await call_next(request)
        if not auth_config.enabled:
            return JSONResponse(
                {"detail": "LPW_ADMIN_PASSWORD_HASH is not configured; run `lpw hash-password`"},
                status_code=503,
            )
        token = request.cookies.get("lpw_session")
        session = app.state.auth.load_session(token)
        if session is None:
            if path.startswith("/api/"):
                return JSONResponse({"detail": "unauthorized"}, status_code=401)
            return RedirectResponse(f"/login?next={path}", status_code=303)
        request.state.session = session
        return await call_next(request)

    @app.on_event("startup")
    async def _startup() -> None:
        if worker is not None:
            worker.start()

    @app.on_event("shutdown")
    async def _shutdown() -> None:
        if worker is not None:
            worker.stop()

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


def _filter_status_zh(value: str) -> str:
    from lynx_patch_watch.web.presenters import status_zh

    return status_zh(value)


def _filter_sparkline(points: list[dict[str, Any]]) -> Markup:
    """Server-side SVG line chart for [{date, open}, …] (history page)."""
    if not points or len(points) < 2:
        return Markup('<p class="muted">数据点不足</p>')
    values = [float(p.get("open") or 0) for p in points]
    labels = [escape(str(p.get("date") or "")[:10]) for p in points]
    width, height = 640, 160
    pad_left, pad_bottom, pad_top = 36, 22, 10
    vmax = max(values) or 1
    span_x = width - pad_left - 8
    span_y = height - pad_bottom - pad_top
    coords = []
    for i, v in enumerate(values):
        x = pad_left + span_x * (i / (len(values) - 1))
        y = pad_top + span_y * (1 - v / vmax)
        coords.append((x, y))
    polyline = " ".join(f"{x:.1f},{y:.1f}" for x, y in coords)
    circles = "".join(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="2.5" fill="#b91c1c"/>' for x, y in coords)
    grid = "".join(
        f'<line x1="{pad_left}" y1="{pad_top + span_y * f:.2f}" x2="{width - 8}" y2="{pad_top + span_y * f:.2f}" stroke="#c5d0da" stroke-width="0.5"/>'
        for f in (0, 0.25, 0.5, 0.75, 1.0)
    )
    y_labels = "".join(
        f'<text x="2" y="{pad_top + span_y * (1 - f) + 3:.1f}" font-size="9" fill="#5c6b7a">{round(vmax * f)}</text>'
        for f in (0, 0.5, 1.0)
    )
    x_labels = "".join(
        f'<text x="{pad_left + span_x * (i / max(1, len(labels) - 1)) - 14:.1f}" y="{height - 6}" font-size="9" fill="#5c6b7a">{lab}</text>'
        for i, lab in enumerate(labels)
        if i % max(1, len(labels) // 6) == 0 or i == len(labels) - 1
    )
    return Markup(
        f'<svg viewBox="0 0 {width} {height}" width="100%" style="max-width: 720px;" role="img" '
        f'aria-label="未修项数随时间变化">{grid}{y_labels}{x_labels}'
        f'<polyline points="{polyline}" fill="none" stroke="#b91c1c" stroke-width="1.6"/>{circles}</svg>'
    )
