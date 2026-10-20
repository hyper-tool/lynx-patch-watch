"""Ported from msw tests/test_http_fetch.py (marker string adapted to LPW)."""

from __future__ import annotations

import httpx

from lynx_patch_watch.http_fetch import fetch_text


def test_fetch_text_uses_client():
    class Resp:
        url = "https://example.com/x"
        status_code = 200
        text = "hello"

    class Client:
        def get(self, url: str):
            assert "example.com" in url
            return Resp()

    result = fetch_text(
        "https://example.com/x",
        user_agent="t",
        client=Client(),  # type: ignore[arg-type]
        prefer_curl=False,
    )
    assert result.text == "hello"
    assert result.status_code == 200


def test_fetch_text_httpx_error_falls_back_to_curl(monkeypatch):
    calls: list[str] = []

    class BoomClient:
        def get(self, url: str):
            raise httpx.ReadTimeout("boom")

    def fake_run(*args, **kwargs):
        calls.append("curl")

        class P:
            returncode = 0
            stdout = "body\n__LPW_HTTP_CODE__:200"
            stderr = ""

        return P()

    monkeypatch.setattr("lynx_patch_watch.http_fetch.subprocess.run", fake_run)
    monkeypatch.setattr("lynx_patch_watch.http_fetch.shutil.which", lambda _: "/usr/bin/curl")
    result = fetch_text(
        "https://example.com",
        user_agent="t",
        client=BoomClient(),  # type: ignore[arg-type]
        prefer_curl=False,
    )
    assert result.text == "body"
    assert result.status_code == 200
    assert calls == ["curl"]


def test_adobe_prefers_curl(monkeypatch):
    calls: list[str] = []

    def fake_run(*args, **kwargs):
        calls.append("curl")

        class P:
            returncode = 0
            stdout = "adobe\n__LPW_HTTP_CODE__:200"
            stderr = ""

        return P()

    monkeypatch.setattr("lynx_patch_watch.http_fetch.subprocess.run", fake_run)
    monkeypatch.setattr("lynx_patch_watch.http_fetch.shutil.which", lambda _: "/usr/bin/curl")
    result = fetch_text(
        "https://www.adobe.com/trust/security/products/commerce/apsb26-146.html",
        user_agent="t",
        prefer_curl=None,
    )
    assert result.text == "adobe"
    assert calls == ["curl"]
