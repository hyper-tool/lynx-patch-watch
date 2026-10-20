"""IP allowlist middleware for the web dashboard.

Ported from msw ``web/middleware.py`` with the ``testclient`` bypass removed
(all pages now require authentication, so test clients must authenticate).
msw: src/magento_security_watcher/web/middleware.py
"""

from __future__ import annotations

import ipaddress
from typing import Iterable, Optional, Sequence

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response


def _parse_networks(cidrs: Sequence[str]) -> list[ipaddress._BaseNetwork]:
    nets: list[ipaddress._BaseNetwork] = []
    for raw in cidrs:
        text = (raw or "").strip()
        if not text:
            continue
        try:
            nets.append(ipaddress.ip_network(text, strict=False))
        except ValueError:
            continue
    return nets


def default_loopback_networks() -> list[ipaddress._BaseNetwork]:
    return [
        ipaddress.ip_network("127.0.0.1/32"),
        ipaddress.ip_network("::1/128"),
    ]


def resolve_client_ip(request: Request, *, trust_x_forwarded_for: bool) -> Optional[str]:
    if trust_x_forwarded_for:
        # A proxy may append its own header line rather than merge into a
        # client-sent one, so join every line before taking the last hop.
        forwarded = ",".join(request.headers.getlist("x-forwarded-for"))
        if forwarded:
            # Right-most entry is the one our (single) trusted proxy appended;
            # anything to its left is client-supplied and can be spoofed.
            last = forwarded.split(",")[-1].strip()
            if last:
                return last
    if request.client and request.client.host:
        return request.client.host
    return None


def ip_allowed(ip_str: Optional[str], networks: Iterable[ipaddress._BaseNetwork]) -> bool:
    if not ip_str:
        return False
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(addr in net for net in networks)


class IPAllowlistMiddleware(BaseHTTPMiddleware):
    """Reject requests whose client IP is outside configured CIDRs.

    Empty allowed_cidrs → loopback only.
    """

    def __init__(
        self,
        app,
        allowed_cidrs: Sequence[str] | None = None,
        *,
        trust_x_forwarded_for: bool = False,
        bypass: bool = False,
    ) -> None:
        super().__init__(app)
        self.trust_x_forwarded_for = trust_x_forwarded_for
        self.bypass = bypass
        cidrs = list(allowed_cidrs or [])
        self.networks = _parse_networks(cidrs) if cidrs else default_loopback_networks()

    async def dispatch(self, request: Request, call_next) -> Response:
        if self.bypass:
            return await call_next(request)
        client_ip = resolve_client_ip(request, trust_x_forwarded_for=self.trust_x_forwarded_for)
        if not ip_allowed(client_ip, self.networks):
            return PlainTextResponse("Forbidden: IP not allowlisted", status_code=403)
        return await call_next(request)
