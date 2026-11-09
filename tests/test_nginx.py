"""nginx reader: blocks, add_header, proxy_hide_header, TLS inference."""

from __future__ import annotations

from headervet.engine import parse_any

CONF = """\
# global comment
server {
    listen 443 ssl;
    server_name a.example;
    add_header X-Frame-Options "DENY" always;
    add_header Set-Cookie "a=1" always;

    location /app {
        add_header X-Route "app" always;
    }
}

server {
    listen 80;
    server_name b.example;
    proxy_hide_header X-Powered-By;
}
"""


def test_two_server_blocks_parsed():
    site = parse_any(CONF, "nginx.conf")
    assert len(site.blocks) == 2
    assert site.blocks[0].label == "server"  # nameless server block


def test_tls_inference_from_listen():
    site = parse_any(CONF, "n.conf")
    assert site.blocks[0].tls is True
    assert site.blocks[1].tls is False


def test_add_header_and_cookies():
    site = parse_any(CONF, "n.conf")
    b = site.blocks[0]
    assert b.first("x-frame-options").value == "DENY"
    assert b.cookies[0][0] == "a=1"


def test_location_headers_recorded_separately():
    site = parse_any(CONF, "n.conf")
    loc = site.blocks[0].locations[0]
    assert loc.has("x-route")
    assert not loc.has("x-frame-options")  # the inheritance footgun, structurally visible


def test_proxy_hide_header_outside_server_still_recorded():
    site = parse_any("proxy_hide_header X-Debug;\n", "p.conf")
    assert site.blocks[0].hide_headers == [("X-Debug", 1, "proxy_hide_header X-Debug;")]


def test_comments_are_stripped_before_parsing():
    site = parse_any('server {\n  # add_header X-Fake "no";\n  add_header X-Real "yes";\n}\n', "n.conf")
    assert site.blocks[0].has("x-real")
    assert not site.blocks[0].has("x-fake")


def test_quoted_value_with_semicolons_survives():
    conf = (
        "server {\n listen 443 ssl;\n"
        " add_header Content-Security-Policy \"default-src 'self'; frame-ancestors 'none'\" always;\n"
        "}\n"
    )
    site = parse_any(conf, "n.conf")
    val = site.blocks[0].first("content-security-policy")
    assert "frame-ancestors" in val.value
