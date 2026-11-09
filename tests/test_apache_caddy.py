"""Apache and Caddy readers."""

from __future__ import annotations

from headervet.engine import parse_any

APACHE = """\
<VirtualHost *:443>
    SSLEngine on
    Header always set Strict-Transport-Security "max-age=31536000"
    Header set X-Frame-Options "DENY"
    Header add Set-Cookie "a=1"
</VirtualHost>
<VirtualHost *:80>
    Header set X-Frame-Options "SAMEORIGIN"
    Header unset X-Powered-By
</VirtualHost>
"""

CADDY = """\
example.com {
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        -X-Powered-By
    }
    header X-Content-Type-Options "nosniff"
}

http://legacy.example {
    header X-Frame-Options "DENY"
}
"""


def test_apache_vhosts_and_tls():
    site = parse_any(APACHE, "httpd.conf")
    assert len(site.blocks) == 2
    assert site.blocks[0].tls is True
    assert site.blocks[1].tls is False
    hsts = site.blocks[0].first("strict-transport-security")
    assert hsts is not None and "31536000" in hsts.value


def test_apache_header_set_add_and_unset():
    site = parse_any(APACHE, "httpd.conf")
    assert site.blocks[0].first("x-frame-options").value == "DENY"
    assert site.blocks[1].hide_headers[0][0] == "X-Powered-By"


def test_apache_global_header_gets_synthetic_block():
    site = parse_any('Header set X-Frame-Options "DENY"\n', "httpd.conf")
    assert site.blocks[0].label.startswith("server (global)")


def test_caddy_site_blocks_and_inline_headers():
    site = parse_any(CADDY, "Caddyfile")
    assert len(site.blocks) == 2
    tls = site.blocks[0]
    assert tls.tls is True
    assert tls.first("x-content-type-options") is not None
    assert tls.first("strict-transport-security") is not None


def test_caddy_minus_means_hide_and_http_prefix_is_plain():
    site = parse_any(CADDY, "Caddyfile")
    assert site.blocks[0].hide_headers[0][0] == "X-Powered-By"
    assert site.blocks[1].tls is False
