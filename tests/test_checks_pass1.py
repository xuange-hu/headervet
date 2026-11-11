"""Pass 1: single header value checks (positive and negative cases)."""

from __future__ import annotations

from headervet.checks import check_block
from headervet.headset import HeaderBlock, parse_dump

DUMP_OK = """\
HTTP/1.1 200 OK
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'self'
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=()
Cache-Control: no-store
"""


def _dump(text: str):
    site = parse_dump(text, "d")
    return site.blocks[0], site.blocks


def test_hardened_dump_is_clean():
    block, _ = _dump(DUMP_OK)
    ids = {f.rule.id for f in check_block(block, "d")}
    assert ids == set(), ids


def test_missing_hsts_on_dump():
    block, _ = _dump("HTTP/1.1 200 OK\nX-Content-Type-Options: nosniff\n")
    assert "HDV001" in {f.rule.id for f in check_block(block, "d")}


def test_hsts_max_age_too_low_and_no_subdomains():
    block, _ = _dump("HTTP/1.1 200 OK\nStrict-Transport-Security: max-age=86400\n")
    ids = {f.rule.id for f in check_block(block, "d")}
    assert {"HDV002", "HDV003"} <= ids


def test_hsts_boundary_is_inclusive():
    block, _ = _dump("HTTP/1.1 200 OK\nStrict-Transport-Security: max-age=15768000; includeSubDomains\n")
    ids = {f.rule.id for f in check_block(block, "d")}
    assert "HDV002" not in ids


def test_csp_family():
    block, _ = _dump(
        "HTTP/1.1 200 OK\n"
        "Content-Security-Policy: script-src * 'unsafe-inline' 'unsafe-eval'\n"
    )
    ids = {f.rule.id for f in check_block(block, "d")}
    assert {"HDV005", "HDV006", "HDV007", "HDV008", "HDV105"} <= ids


def test_csp_wildcard_subdomain_also_flagged():
    block, _ = _dump("HTTP/1.1 200 OK\nContent-Security-Policy: script-src *.cdn.example 'self'\n")
    assert "HDV008" in {f.rule.id for f in check_block(block, "d")}


def test_csp_script_src_overrides_default_for_inline_check():
    # default-src 'unsafe-inline' alone must flag; with a clean script-src
    # overriding it, script-src wins (script loading is script-src's job).
    block, _ = _dump(
        "HTTP/1.1 200 OK\n"
        "Content-Security-Policy: default-src 'unsafe-inline'; script-src 'self'\n"
    )
    ids = {f.rule.id for f in check_block(block, "d")}
    assert "HDV005" not in ids


def test_xcto_missing_and_wrong():
    block, _ = _dump("HTTP/1.1 200 OK\nX-Content-Type-Options: sniff\n")
    ids = {f.rule.id for f in check_block(block, "d")}
    assert "HDV010" in ids and "HDV009" not in ids


def test_no_frame_protection_and_allowfrom():
    block, _ = _dump("HTTP/1.1 200 OK\n")
    assert "HDV011" in {f.rule.id for f in check_block(block, "d")}
    block2, _ = _dump("HTTP/1.1 200 OK\nX-Frame-Options: ALLOW-FROM https://t.example\n")
    assert "HDV012" in {f.rule.id for f in check_block(block2, "d")}


def test_frame_ancestors_satisfies_011():
    block, _ = _dump("HTTP/1.1 200 OK\nContent-Security-Policy: frame-ancestors 'self'\n")
    assert "HDV011" not in {f.rule.id for f in check_block(block, "d")}


def test_referrer_policy():
    block, _ = _dump("HTTP/1.1 200 OK\nReferrer-Policy: unsafe-url\n")
    assert "HDV014" in {f.rule.id for f in check_block(block, "d")}


def test_server_version_and_fingerprints():
    block, _ = _dump(
        "HTTP/1.1 200 OK\nServer: nginx/1.24.0\nX-Powered-By: Express\n"
        "X-XSS-Protection: 1; mode=block\nExpect-CT: max-age=0\n"
    )
    ids = {f.rule.id for f in check_block(block, "d")}
    assert {"HDV016", "HDV017", "HDV018", "HDV019"} <= ids


def test_server_without_version_is_clean():
    block, _ = _dump("HTTP/1.1 200 OK\nServer: nginx\n")
    assert "HDV016" not in {f.rule.id for f in check_block(block, "d")}


def test_cookie_flags():
    block, _ = _dump("HTTP/1.1 200 OK\nSet-Cookie: sid=1; SameSite=Lax\nCache-Control: no-store\n")
    ids = {f.rule.id for f in check_block(block, "d")}
    # dump scheme defaults to https -> HDV103 (pass 2) owns missing-Secure
    assert {"HDV021", "HDV103"} <= ids and "HDV022" not in ids


def test_cookie_without_cache_control():
    block, _ = _dump("HTTP/1.1 200 OK\nSet-Cookie: sid=1; Secure; HttpOnly; SameSite=Strict\n")
    assert "HDV025" in {f.rule.id for f in check_block(block, "d")}


def test_cors_wildcard_and_reflection():
    block, _ = _dump("HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: *\n")
    assert "HDV023" in {f.rule.id for f in check_block(block, "d")}


def test_duplicate_conflicting_headers():
    block, _ = _dump(
        "HTTP/1.1 200 OK\n"
        "Strict-Transport-Security: max-age=31536000\n"
        "Strict-Transport-Security: max-age=63072000\n"
    )
    assert "HDV026" in {f.rule.id for f in check_block(block, "d")}


def test_identical_duplicates_are_not_conflicts():
    block, _ = _dump(
        "HTTP/1.1 200 OK\n"
        "Strict-Transport-Security: max-age=31536000\n"
        "Strict-Transport-Security: max-age=31536000\n"
    )
    assert "HDV026" not in {f.rule.id for f in check_block(block, "d")}


def test_plaintext_context_skips_hsts_missing():
    block = HeaderBlock(label="http", line=1, origin="live")
    block.meta["scheme"] = "http"
    block.tls = False
    assert "HDV001" not in {f.rule.id for f in check_block(block, "u")}


def test_findings_carry_snippet_and_line():
    block, _ = _dump("HTTP/1.1 200 OK\nReferrer-Policy: unsafe-url\n")
    f = next(f for f in check_block(block, "d") if f.rule.id == "HDV014")
    assert f.line == 2 and "unsafe-url" in f.snippet

def test_missing_referrer_policy_and_permissions_policy():
    block, _ = _dump("HTTP/1.1 200 OK\n")
    ids = {f.rule.id for f in check_block(block, "d")}
    assert "HDV013" in ids and "HDV015" in ids


def test_present_privacy_policies_clear_their_rules():
    block, _ = _dump(
        "HTTP/1.1 200 OK\nReferrer-Policy: strict-origin\n"
        "Permissions-Policy: camera=()\n"
    )
    ids = {f.rule.id for f in check_block(block, "d")}
    assert "HDV013" not in ids and "HDV015" not in ids
