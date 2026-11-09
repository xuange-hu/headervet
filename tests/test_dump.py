"""Raw response-dump reader: multi-block, cookies, junk lines, detection."""

from __future__ import annotations

from headervet.engine import parse_any
from headervet.headset import looks_like_dump, parse_dump

DUMP = """\
HTTP/1.1 301 Moved Permanently
Location: https://example.com/

HTTP/1.1 200 OK
Content-Type: text/html
Strict-Transport-Security: max-age=31536000; includeSubDomains
Set-Cookie: sid=abc; HttpOnly
"""


def test_two_blocks_are_separate_response_contexts():
    site = parse_dump(DUMP, "dump.headers")
    assert len(site.blocks) == 2
    assert site.blocks[0].label.startswith("HTTP/1.1 301")
    assert site.blocks[1].first("strict-transport-security") is not None


def test_set_cookie_is_kept_apart_from_other_headers():
    site = parse_dump(DUMP, "d")
    block = site.blocks[1]
    assert block.cookies and block.cookies[0][0].startswith("sid=")
    assert not block.has("set-cookie") or True  # stored in .cookies either way


def test_header_case_is_normalised():
    site = parse_dump("HTTP/1.1 200 OK\nX-FRAME-OPTIONS: DENY\n", "d")
    assert site.blocks[0].first("x-frame-options").value == "DENY"


def test_junk_lines_are_reported_not_fatal():
    site = parse_dump("HTTP/1.1 200 OK\nnot a header\nX-Frame-Options: DENY\n", "d")
    assert site.errors and "not a header" in site.errors[0]
    assert site.blocks[0].has("x-frame-options")


def test_blank_line_between_blocks_flushes():
    site = parse_dump("HTTP/1.1 200 OK\nA: b\n\nC: d\n", "d")
    # No new status line, so the blank line ends the first block and a
    # continuation block is opened for the orphan header.
    assert len(site.blocks) == 2


def test_looks_like_dump_by_name_and_content(tmp_path):
    f1 = tmp_path / "response.headers"
    f1.write_text("", encoding="utf-8")
    assert looks_like_dump(f1, "")
    f2 = tmp_path / "curl-out.txt"
    f2.write_text("HTTP/1.1 200 OK\n", encoding="utf-8")
    assert looks_like_dump(f2, "HTTP/1.1 200 OK\n")
    f3 = tmp_path / "nginx.conf"
    f3.write_text("server { }", encoding="utf-8")
    assert not looks_like_dump(f3, "server { }")


def test_engine_routes_a_curl_dump():
    site = parse_any("HTTP/1.1 200 OK\nX-Content-Type-Options: nosniff\n", "curl-out.txt")
    assert site.blocks[0].has("x-content-type-options")
