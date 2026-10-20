"""Ported from msw tests/test_browser_identity.py."""

from lynx_patch_watch.browser_identity import (
    BROWSER_USER_AGENT,
    browser_headers,
    curl_header_args,
)


def test_browser_ua_looks_like_chrome():
    assert "Chrome/" in BROWSER_USER_AGENT
    assert "Mozilla/5.0" in BROWSER_USER_AGENT
    assert "lynx-patch-watch" not in BROWSER_USER_AGENT


def test_browser_headers_include_sec_fetch():
    h = browser_headers()
    assert h["User-Agent"] == BROWSER_USER_AGENT
    assert h["Sec-Fetch-Mode"] == "navigate"
    assert "Chromium" in h["Sec-Ch-Ua"]


def test_curl_header_args_skip_ua():
    args = curl_header_args()
    joined = " ".join(args)
    assert "Sec-Fetch-Dest: document" in joined
    assert "User-Agent:" not in joined
