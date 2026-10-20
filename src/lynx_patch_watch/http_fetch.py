"""HTTP fetching with browser-like identity (curl first for adobe.com).

Ported from msw ``http_fetch.py``. msw: src/magento_security_watcher/http_fetch.py
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass

import httpx

from lynx_patch_watch.browser_identity import (
    BROWSER_USER_AGENT,
    browser_headers,
    curl_header_args,
)


@dataclass
class FetchResult:
    url: str
    status_code: int
    text: str


_NETWORK_HINT = (
    "Browser can open Adobe while CLI times out usually means: "
    "(1) terminal is not using the same VPN/proxy as the browser — export HTTPS_PROXY=... ; "
    "(2) Akamai blocks non-browser TLS fingerprints (UA spoof alone may not be enough) — "
    "save the page in browser and run `lpw ingest --from-html /path/to/apsb.html`, "
    "or set advisory.local_index_html / fixture_dir."
)


def fetch_text(
    url: str,
    *,
    user_agent: str | None = None,
    timeout: float = 45.0,
    client: httpx.Client | None = None,
    prefer_curl: bool | None = None,
) -> FetchResult:
    """
    Fetch URL text with Chrome-like User-Agent and headers.

    Adobe/Akamai often stalls Python HTTP clients; for adobe.com we try curl
    (HTTP/1.1) first, then httpx. Respects HTTPS_PROXY / HTTP_PROXY / ALL_PROXY.
    """
    user_agent = user_agent or BROWSER_USER_AGENT
    headers = browser_headers(user_agent)
    if prefer_curl is None:
        prefer_curl = client is None and "adobe.com" in url.lower()

    errors: list[Exception] = []

    def via_curl() -> FetchResult:
        curl = shutil.which("curl")
        if not curl:
            raise RuntimeError("curl not found")
        # Force HTTP/1.1: Adobe/Akamai often returns HTTP/2 INTERNAL_ERROR to CLI clients.
        cmd = [
            curl,
            "-sL",
            "--http1.1",
            "--compressed",
            "--max-time",
            str(max(1, int(timeout))),
            "-A",
            user_agent,
            *curl_header_args(user_agent),
            "-w",
            "\n__LPW_HTTP_CODE__:%{http_code}",
            url,
        ]
        env = os.environ.copy()
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
        if proc.returncode != 0:
            err = proc.stderr.strip() or f"curl exit {proc.returncode}"
            raise RuntimeError(f"curl failed for {url}: {err}")
        body = proc.stdout
        status = 0
        if "__LPW_HTTP_CODE__:" in body:
            body, _, code = body.rpartition("__LPW_HTTP_CODE__:")
            body = body.rstrip("\n")
            try:
                status = int(code.strip())
            except ValueError:
                status = 0
        if status == 0 and not body.strip():
            raise RuntimeError(f"curl got empty response for {url} (often proxy/VPN missing in terminal)")
        return FetchResult(url=url, status_code=status or 200, text=body)

    def via_httpx() -> FetchResult:
        if client is not None:
            resp = client.get(url)
            return FetchResult(url=str(resp.url), status_code=resp.status_code, text=resp.text)
        # httpx may not negotiate brotli; drop br to avoid decode issues
        hx_headers = dict(headers)
        hx_headers["Accept-Encoding"] = "gzip, deflate"
        with httpx.Client(
            timeout=timeout,
            headers=hx_headers,
            follow_redirects=True,
            http2=False,
            trust_env=True,
        ) as c:
            resp = c.get(url)
            return FetchResult(url=str(resp.url), status_code=resp.status_code, text=resp.text)

    order = (via_curl, via_httpx) if prefer_curl else (via_httpx, via_curl)
    for fn in order:
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)
            continue
    detail = errors[-1] if errors else "unknown"
    raise RuntimeError(f"Failed to fetch {url}: {detail}. {_NETWORK_HINT}")
