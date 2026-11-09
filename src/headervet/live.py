"""Live mode: fetch real responses over stdlib http.client and audit them."""

from __future__ import annotations

import http.client
import ssl
from urllib.parse import urlparse

from .headset import HeaderBlock, HeaderSite

__all__ = ["fetch"]


def fetch(url: str, *, timeout: float = 10.0, insecure: bool = False) -> tuple[HeaderSite, str | None]:
    """GET ``url`` once (redirects are NOT followed) and build a HeaderSite.

    Returns ``(site, error)``; ``error`` is None on success. Only the stdlib
    is used, so live mode works in the same offline-capable CI container as
    the static passes (against anything it can reach).
    """
    p = urlparse(url if "://" in url else f"https://{url}")
    if p.scheme not in ("http", "https"):
        return HeaderSite(path=url), f"unsupported scheme: {p.scheme!r}"
    host = p.hostname or ""
    port = p.port or (443 if p.scheme == "https" else 80)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query

    try:
        if p.scheme == "https":
            ctx = ssl.create_default_context()
            if insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            conn: http.client.HTTPConnection = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("GET", path, headers={"User-Agent": "headervet/0.1 (audit; +https://github.com/xuange-hu/headervet)"})
        resp = conn.getresponse()
        resp.read(0)  # drain status/headers; body is out of scope
        status_line = f"HTTP/1.1 {resp.status} {resp.reason}"
        site = HeaderSite(path=url)
        block = HeaderBlock(label=status_line, line=1, origin="live")
        block.meta["scheme"] = p.scheme
        block.tls = p.scheme == "https"
        for name, value in resp.getheaders():
            if name.lower() == "set-cookie":
                block.cookies.append((value, _Val(value, 2, f"{name}: {value}")))
            else:
                block.add(name, _Val(value, 2, f"{name}: {value}"))
        site.blocks.append(block)
        conn.close()
        return site, None
    except OSError as exc:
        return HeaderSite(path=url), str(exc)


class _Val:
    """Minimal HeaderVal stand-in so live mode does not import in circles."""

    __slots__ = ("value", "line", "snippet")

    def __init__(self, value: str, line: int, snippet: str) -> None:
        self.value = value
        self.line = line
        self.snippet = snippet
