"""Pass 3: relations between configs — the reason headervet reads files."""

from __future__ import annotations

from headervet.cross import check_cross
from headervet.engine import scan


def _rules_hit(files, tmp_path):
    for name, content in files.items():
        (tmp_path / name).write_text(content, encoding="utf-8", newline="\n")
    return {f.rule.id for f in scan(tmp_path).findings}


NGINX = """\
server {
    listen 443 ssl;
    server_name a.example;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;

    location /app {
        add_header X-Route "app" always;
    }
    location /ok {
        add_header X-Route "ok" always;
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        add_header X-Content-Type-Options "nosniff" always;
    }
}
"""


def test_hdv201_location_cancels_inheritance(tmp_path):
    ids = _rules_hit({"nginx.conf": NGINX}, tmp_path)
    assert "HDV201" in ids
    result = scan(tmp_path)
    hits = [f for f in result.findings if f.rule.id == "HDV201"]
    # Only /app loses headers; /ok re-declares both.
    assert len(hits) == 1
    assert "strict-transport-security" in hits[0].detail


def test_hdv201_requires_server_level_headers(tmp_path):
    bare = "server {\n listen 443 ssl;\n location /a {\n  add_header X-Only \"1\" always;\n }\n}\n"
    ids = _rules_hit({"nginx.conf": bare}, tmp_path)
    assert "HDV201" not in ids


def test_hdv202_conflicting_values_across_files(tmp_path):
    ids = _rules_hit(
        {
            "proxy.conf": 'add_header X-Frame-Options "DENY" always;\n',
            "app.js": "res.setHeader('X-Frame-Options', 'SAMEORIGIN');\n",
        },
        tmp_path,
    )
    assert "HDV202" in ids


def test_hdv202_same_value_across_files_is_clean(tmp_path):
    ids = _rules_hit(
        {
            "proxy.conf": 'add_header X-Frame-Options "DENY" always;\n',
            "app.js": "res.setHeader('X-Frame-Options', 'DENY');\n",
        },
        tmp_path,
    )
    assert "HDV202" not in ids


def test_hdv203_proxy_hide_strips_app_header(tmp_path):
    ids = _rules_hit(
        {
            "proxy.conf": "server {\n proxy_hide_header X-Frame-Options;\n}\n",
            "app.js": "res.setHeader('X-Frame-Options', 'SAMEORIGIN');\n",
        },
        tmp_path,
    )
    assert "HDV203" in ids
    result = scan(tmp_path)
    hit = next(f for f in result.findings if f.rule.id == "HDV203")
    assert hit.path == "proxy.conf"


def test_hdv203_unrelated_header_is_clean(tmp_path):
    ids = _rules_hit(
        {
            "proxy.conf": "server {\n proxy_hide_header X-Internal-Note;\n}\n",
            "app.js": "res.setHeader('X-Frame-Options', 'SAMEORIGIN');\n",
        },
        tmp_path,
    )
    assert "HDV203" not in ids


def test_hdv204_hsts_on_plain_listener(tmp_path):
    conf = (
        "server {\n listen 80;\n"
        ' add_header Strict-Transport-Security "max-age=31536000" always;\n}\n'
        "server {\n listen 443 ssl;\n}\n"
    )
    ids = _rules_hit({"nginx.conf": conf}, tmp_path)
    assert "HDV204" in ids


def test_hdv204_not_fired_on_tls_block(tmp_path):
    conf = (
        "server {\n listen 443 ssl;\n"
        ' add_header Strict-Transport-Security "max-age=31536000" always;\n}\n'
    )
    ids = _rules_hit({"nginx.conf": conf}, tmp_path)
    assert "HDV204" not in ids


def test_cross_empty_on_no_sites():
    assert check_cross([]) == []
