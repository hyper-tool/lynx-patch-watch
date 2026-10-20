"""Web tests: auth wall, CSRF, project CRUD, scan queue, matrix, advisories."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from lynx_patch_watch.store import Store
from lynx_patch_watch.web.app import create_app
from lynx_patch_watch.web.auth import SESSION_COOKIE
from tests.conftest import FIXTURES, REPO_ROOT

from argon2 import PasswordHasher

REPO_ROOT = REPO_ROOT


def _app(store: Store, tmp_path: Path):
    from lynx_patch_watch.config import AppSettings

    settings = AppSettings()
    settings.data_dir = str(tmp_path / "data")
    settings.db_path = str(store.db_path)
    settings.scan.mirrors_dir = str(tmp_path / "data" / "mirrors")
    settings.scan.local_root = str(tmp_path)
    settings.rules.dir = str(REPO_ROOT / "rules" / "magento")
    app = create_app(
        root=tmp_path,
        config_dir=tmp_path / "config",
        settings=settings,
        store=store,
        testing=True,
        start_worker=False,
    )
    app.state.auth.config.password_hash = PasswordHasher().hash("test-password")
    return app


def _login(client: TestClient, app) -> str:
    response = client.post(
        "/login",
        data={"username": "admin", "password": "test-password", "next": "/"},
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text
    # The Set-Cookie header already lands in the client jar; setting it again
    # would create a duplicate cookie that survives logout deletion.
    token = response.cookies.get(SESSION_COOKIE)
    assert token
    assert client.cookies.get(SESSION_COOKIE) == token
    return token


def _csrf(app, token: str) -> str:
    return app.state.auth._csrf_for_session(token)


def test_unauthenticated_redirects_to_login(store: Store, tmp_path: Path):
    app = _app(store, tmp_path)
    client = TestClient(app)
    for path in ("/", "/projects", "/matrix", "/history", "/advisories", "/rules", "/excel"):
        response = client.get(path, follow_redirects=False)
        assert response.status_code == 303, path
        assert response.headers["location"].startswith("/login"), path


def test_login_and_logout(store: Store, tmp_path: Path):
    app = _app(store, tmp_path)
    client = TestClient(app)
    token = _login(client, app)
    response = client.get("/")
    assert response.status_code == 200
    assert "多项目看板" in response.text
    # wrong password
    response = client.post("/login", data={"username": "admin", "password": "wrong"})
    assert "用户名或密码错误" in response.text
    # logout
    response = client.post("/logout", follow_redirects=False)
    assert response.status_code == 303
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 303


def test_csrf_required_for_mutations(store: Store, tmp_path: Path):
    app = _app(store, tmp_path)
    client = TestClient(app)
    token = _login(client, app)
    # no csrf token → 403
    response = client.post(
        "/projects",
        data={"id": "shop-a", "name": "Shop A"},
        follow_redirects=False,
    )
    assert response.status_code == 403
    # wrong csrf token → 403
    response = client.post(
        "/projects",
        data={"id": "shop-a", "name": "Shop A", "csrf_token": "bogus"},
        follow_redirects=False,
    )
    assert response.status_code == 403


def test_project_crud_flow(store: Store, tmp_path: Path):
    app = _app(store, tmp_path)
    client = TestClient(app)
    token = _login(client, app)
    csrf = _csrf(app, token)

    # invalid id rejected
    response = client.post(
        "/projects",
        data={"id": "Bad-ID", "name": "x", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert response.status_code == 400

    # create
    response = client.post(
        "/projects",
        data={
            "id": "shop-a",
            "name": "Shop A",
            "type": "magento",
            "scan_mode": "local",
            "local_path": str(tmp_path / "shop"),
            "declared_version": "2.4.7-p8",
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    project = store.get_project("shop-a")
    assert project is not None
    assert project["declared_version"] == "2.4.7-p8"

    # duplicate rejected
    response = client.post(
        "/projects",
        data={"id": "shop-a", "name": "Shop A", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert response.status_code == 400

    # detail page
    response = client.get("/projects/shop-a")
    assert response.status_code == 200
    assert "Shop A" in response.text

    # update
    response = client.post(
        "/projects/shop-a/update",
        data={"id": "shop-a", "name": "Shop A2", "scan_mode": "local", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert store.get_project("shop-a")["name"] == "Shop A2"

    # scan enqueue
    response = client.post(
        "/projects/shop-a/scan",
        data={"csrf_token": csrf},
        follow_redirects=False,
    )
    assert response.status_code == 303
    jobs = store.list_scan_jobs()
    assert jobs and jobs[0]["project_id"] == "shop-a"

    # audit log recorded
    assert any(row["action"] == "project.create" for row in store.list_audit_log())

    # delete requires confirm
    response = client.post(
        "/projects/shop-a/delete",
        data={"csrf_token": csrf, "confirm": "wrong"},
        follow_redirects=False,
    )
    assert response.status_code == 400
    response = client.post(
        "/projects/shop-a/delete",
        data={"csrf_token": csrf, "confirm": "shop-a"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert store.get_project("shop-a") is None


def test_manual_review_flow(store: Store, tmp_path: Path):
    from lynx_patch_watch.adapters.magento.source import ChimeraAdvisorySource
    from lynx_patch_watch.engine.ingest import ingest_from_source

    source = ChimeraAdvisorySource(chimera_url="unused", fixture_dir=FIXTURES, detail_fetch_limit=15)
    ingest_from_source(store, source)
    app = _app(store, tmp_path)
    client = TestClient(app)
    token = _login(client, app)
    csrf = _csrf(app, token)
    store.upsert_project({"id": "shop-a", "name": "Shop A", "scan_mode": "manual"})
    item_id = "APSB26-146:CVE-2026-75650"

    response = client.post(
        "/projects/shop-a/review",
        data={
            "item_id": item_id,
            "status": "confirmed_fixed",
            "note": "verified by hand",
            "reviewer": "alice",
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    review = store.get_manual_review("shop-a", item_id)
    assert review is not None
    assert review["status"] == "confirmed_fixed"
    assert review["reviewer"] == "alice"

    # invalid status rejected
    response = client.post(
        "/projects/shop-a/review",
        data={"item_id": item_id, "status": "bogus", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert response.status_code == 400


def test_dashboard_and_matrix_render(store: Store, tmp_path: Path):
    from lynx_patch_watch.adapters.magento.source import ChimeraAdvisorySource
    from lynx_patch_watch.engine.ingest import ingest_from_source

    source = ChimeraAdvisorySource(chimera_url="unused", fixture_dir=FIXTURES, detail_fetch_limit=15)
    ingest_from_source(store, source)
    store.upsert_project({"id": "shop-a", "name": "Shop A", "scan_mode": "manual", "declared_version": "2.4.8-p6"})
    app = _app(store, tmp_path)
    client = TestClient(app)
    _login(client, app)
    for path in ("/", "/matrix", "/history", "/advisories", "/advisories/APSB26-146", "/rules", "/excel", "/projects", "/projects/shop-a"):
        response = client.get(path)
        assert response.status_code == 200, (path, response.status_code)


def test_api_status_token(store: Store, tmp_path: Path):
    from lynx_patch_watch.adapters.magento.source import ChimeraAdvisorySource
    from lynx_patch_watch.engine.ingest import ingest_from_source

    source = ChimeraAdvisorySource(chimera_url="unused", fixture_dir=FIXTURES, detail_fetch_limit=15)
    ingest_from_source(store, source)
    store.upsert_project({"id": "shop-a", "name": "Shop A", "scan_mode": "manual", "declared_version": "2.4.8-p6"})
    import secrets

    token = secrets.token_urlsafe(24)
    store.set_setting("api_token_hash", Store.hash_api_token(token))
    app = _app(store, tmp_path)
    client = TestClient(app)
    response = client.get("/api/projects/shop-a/status", params={"token": "wrong"})
    assert response.status_code == 403
    response = client.get("/api/projects/shop-a/status", params={"token": token})
    assert response.status_code == 200
    data = response.json()
    assert data["project"] == "shop-a"
    assert "APSB26-146" in data["advisories"]


def test_login_rate_limit(store: Store, tmp_path: Path):
    app = _app(store, tmp_path)
    client = TestClient(app)
    for _ in range(5):
        client.post("/login", data={"username": "admin", "password": "wrong"})
    response = client.post("/login", data={"username": "admin", "password": "test-password"})
    assert "登录失败次数过多" in response.text


def test_login_rejects_offsite_next(store: Store, tmp_path: Path):
    app = _app(store, tmp_path)
    for target in ("//evil.example/x", "/\\evil.example", "https://evil.example", "/projects?x=1"):
        client = TestClient(app)
        response = client.post(
            "/login",
            data={"username": "admin", "password": "test-password", "next": target},
            follow_redirects=False,
        )
        assert response.status_code == 303
        expected = target if target == "/projects?x=1" else "/"
        assert response.headers["location"] == expected, target


def test_excel_import_requires_csrf(store: Store, tmp_path: Path):
    app = _app(store, tmp_path)
    client = TestClient(app)
    _login(client, app)
    response = client.post(
        "/excel/import",
        data={"apply": "1"},
        files={"file": ("x.xlsx", b"not-a-workbook", "application/octet-stream")},
    )
    assert response.status_code == 403


def test_history_renders_sparkline(store: Store, tmp_path: Path):
    store.upsert_project({"id": "shop-a", "name": "Shop A", "scan_mode": "manual"})
    for _ in range(2):
        run = store.start_scan_run("shop-a", ruleset_hash="h")
        store.finish_scan_run(run, "done")
    app = _app(store, tmp_path)
    client = TestClient(app)
    _login(client, app)
    response = client.get("/history")
    assert response.status_code == 200
    assert "<svg" in response.text and "&lt;svg" not in response.text


def test_session_secret_from_env_file_and_random_fallback(tmp_path: Path, monkeypatch):
    from lynx_patch_watch.config import AppSettings, load_env_secrets
    from lynx_patch_watch.web.auth import load_auth_config

    monkeypatch.delenv("LPW_SESSION_SECRET", raising=False)
    settings = AppSettings()
    (tmp_path / ".env").write_text("LPW_SESSION_SECRET=from-dotenv\n", encoding="utf-8")
    assert load_auth_config(settings, load_env_secrets(tmp_path)).secret_key == "from-dotenv"
    other = tmp_path / "other"
    other.mkdir()
    a = load_auth_config(settings, load_env_secrets(other)).secret_key
    b = load_auth_config(settings, load_env_secrets(other)).secret_key
    assert a != b and "change-me" not in a


def test_xff_uses_rightmost_hop():
    from starlette.requests import Request

    from lynx_patch_watch.web.middleware import resolve_client_ip

    scope = {
        "type": "http",
        "headers": [(b"x-forwarded-for", b"127.0.0.1, 203.0.113.9")],
        "client": ("10.0.0.2", 1234),
    }
    request = Request(scope)
    assert resolve_client_ip(request, trust_x_forwarded_for=True) == "203.0.113.9"
    assert resolve_client_ip(request, trust_x_forwarded_for=False) == "10.0.0.2"
    # Proxy appended a separate header line after the client-sent one.
    split = Request(dict(scope, headers=[
        (b"x-forwarded-for", b"127.0.0.1"),
        (b"x-forwarded-for", b"203.0.113.9"),
    ]))
    assert resolve_client_ip(split, trust_x_forwarded_for=True) == "203.0.113.9"
