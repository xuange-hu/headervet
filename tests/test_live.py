"""Live mode against a real localhost HTTP server (no external network)."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from headervet.live import fetch


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - stdlib naming
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Set-Cookie", "sid=1; HttpOnly")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):  # silence the test output
        pass


@pytest.fixture(scope="module")
def server_url():
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}/"
    srv.shutdown()


def test_fetch_builds_a_site(server_url):
    site, err = fetch(server_url)
    assert err is None
    block = site.blocks[0]
    assert block.origin == "live"
    assert block.tls is False and block.meta["scheme"] == "http"
    assert block.first("x-frame-options").value == "DENY"


def test_live_findings_use_the_normal_engine(server_url):
    from headervet.checks import check_block

    site, _ = fetch(server_url)
    ids = set()
    for block in site.blocks:
        ids |= {f.rule.id for f in check_block(block, site.path)}
    # Plain HTTP: HSTS missing is not flagged (it belongs on TLS), but the
    # CSP/cookie hygiene findings still are.
    assert "HDV004" in ids  # no CSP
    assert "HDV001" not in ids


def test_cookie_with_httponly_only_lacks_secure_and_samesite(server_url):
    from headervet.checks import check_block

    site, _ = fetch(server_url)
    ids = set()
    for block in site.blocks:
        ids |= {f.rule.id for f in check_block(block, site.path)}
    assert "HDV022" in ids  # no SameSite
    # plain http context: Secure flag findings are not meaningful here
    assert "HDV020" not in ids


def test_fetch_connection_refused_returns_error():
    site, err = fetch("http://127.0.0.1:1", timeout=2)
    assert err is not None
    assert site.blocks == []


def test_fetch_rejects_unknown_scheme():
    _, err = fetch("ftp://example.com")
    assert err and "unsupported scheme" in err
