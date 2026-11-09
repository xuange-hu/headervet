"""Pass 2: relations among the headers of a single response."""

from __future__ import annotations

from headervet.checks import check_block
from headervet.headset import parse_dump


def _ids(text: str):
    site = parse_dump(text, "d")
    return {f.rule.id for f in check_block(site.blocks[0], "d")}


def test_report_only_without_enforcing():
    ids = _ids("HTTP/1.1 200 OK\nContent-Security-Policy-Report-Only: default-src 'self'\n")
    assert {"HDV101"} <= ids
    assert "HDV004" not in ids  # report-only still counts as "CSP work started"


def test_report_only_with_enforcing_is_clean_of_101():
    ids = _ids(
        "HTTP/1.1 200 OK\n"
        "Content-Security-Policy: default-src 'self'\n"
        "Content-Security-Policy-Report-Only: default-src 'self'\n"
    )
    assert "HDV101" not in ids


def test_wildcard_cors_with_credentials():
    ids = _ids(
        "HTTP/1.1 200 OK\n"
        "Access-Control-Allow-Origin: *\n"
        "Access-Control-Allow-Credentials: true\n"
    )
    assert "HDV102" in ids


def test_tls_site_cookie_without_secure_is_103_not_020():
    ids = _ids(
        "HTTP/1.1 200 OK\n"
        "Strict-Transport-Security: max-age=31536000\n"
        "Set-Cookie: sid=1; HttpOnly\n"
    )
    assert "HDV103" in ids and "HDV020" not in ids


def test_xfo_with_csp_without_frame_ancestors():
    ids = _ids(
        "HTTP/1.1 200 OK\n"
        "X-Frame-Options: DENY\n"
        "Content-Security-Policy: default-src 'self'\n"
    )
    assert "HDV104" in ids


def test_object_src_unrestricted():
    ids = _ids("HTTP/1.1 200 OK\nContent-Security-Policy: default-src 'self'\n")
    assert "HDV105" in ids
    ids2 = _ids("HTTP/1.1 200 OK\nContent-Security-Policy: default-src 'none'\n")
    assert "HDV105" not in ids2


def test_object_src_explicit_none_is_clean():
    ids = _ids("HTTP/1.1 200 OK\nContent-Security-Policy: default-src 'self'; object-src 'none'\n")
    assert "HDV105" not in ids


def test_reflected_origin_with_credentials():
    # nginx placeholder arrives verbatim in a config scan; simulate via a dump
    # that carries the placeholder text (what a misconfigured template sends).
    ids = _ids(
        "HTTP/1.1 200 OK\n"
        "Access-Control-Allow-Origin: $http_origin\n"
        "Access-Control-Allow-Credentials: true\n"
    )
    assert {"HDV024", "HDV106"} <= ids
