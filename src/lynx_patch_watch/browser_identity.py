"""Browser-like identity for Adobe/Akamai fetches.

Ported verbatim from msw ``browser_identity.py`` (git_workspace/http_fetch
dependency). msw: src/magento_security_watcher/browser_identity.py
"""

from __future__ import annotations

# Recent Chrome on macOS — spoofed for sites that only check User-Agent / client hints.
BROWSER_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)

# Keep in sync with BROWSER_USER_AGENT major version for Sec-CH-UA.
_CHROME_MAJOR = "131"


def browser_headers(user_agent: str | None = None) -> dict[str, str]:
    """Return a Chrome-like header set (UA alone is often not enough)."""
    ua = user_agent or BROWSER_USER_AGENT
    return {
        "User-Agent": ua,
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8,"
            "application/signed-exchange;v=b3;q=0.7"
        ),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Cache-Control": "max-age=0",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Ch-Ua": f'"Google Chrome";v="{_CHROME_MAJOR}", "Chromium";v="{_CHROME_MAJOR}", "Not_A Brand";v="24"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"macOS"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
    }


def curl_header_args(user_agent: str | None = None) -> list[str]:
    """Flatten browser_headers into curl -H arguments (UA via -A separately)."""
    headers = browser_headers(user_agent)
    args: list[str] = []
    for key, value in headers.items():
        if key.lower() == "user-agent":
            continue
        # curl --compressed handles Accept-Encoding; avoid double-declaring br if unsupported
        if key.lower() == "accept-encoding":
            continue
        args.extend(["-H", f"{key}: {value}"])
    return args
