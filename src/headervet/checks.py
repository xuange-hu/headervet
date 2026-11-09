"""Pass 1 (one header value) and pass 2 (relations within one response)."""

from __future__ import annotations

import re

from .headset import HSTS_NAME, HeaderBlock, csp_directives
from .model import Finding
from .rules import by_id

__all__ = ["check_block", "HSTS_MIN_AGE"]

HSTS_MIN_AGE = 15_768_000  # 182 days, the common minimum recommendation

_VERSIONY = re.compile(r"/\d|\d+\.\d")
# Origin reflection in config placeholders: nginx, Apache, Caddy, Express.
_ORIGIN_REFLECTION = re.compile(
    r"\$http_origin|%{origin}i|\{header\.origin\}|{>origin}|req\.headers\s*\[\s*['\"]origin|request\.headers\.origin",
    re.IGNORECASE,
)
_SERVER_BANNER = re.compile(r"nginx|apache|caddy|cloudflare|litespeed|istio-envoy|gvs?|openresty", re.IGNORECASE)


def _f(block: HeaderBlock, path: str, rid: str, line: int, snippet: str, detail: str) -> Finding:
    return Finding(
        rule=by_id(rid),  # type: ignore[arg-type]
        path=path,
        line=line,
        snippet=snippet[:200],
        detail=detail,
        site=block.label,
        block=block.label,
    )


def _first_cookie_header(block: HeaderBlock) -> tuple[str, object] | None:
    return (block.cookies[0][0], block.cookies[0][1]) if block.cookies else None


def _cookie_flag(cookie: str, flag: str) -> bool:
    return re.search(rf"(?i)(?:^|;\s*){flag}\b", cookie) is not None


def _is_tls(block: HeaderBlock) -> bool:
    if block.tls is not None:
        return block.tls
    if block.origin == "live":
        return block.meta.get("scheme", "https") != "http"
    # Configs and dumps: HSTS itself is the best TLS evidence we have.
    return block.has(HSTS_NAME)


def check_block(block: HeaderBlock, path: str) -> list[Finding]:
    out: list[Finding] = []
    tls = _is_tls(block)

    # ---- transport ------------------------------------------------------
    hsts = block.first(HSTS_NAME)
    if hsts is None:
        # Plaintext listeners are skipped: the spec ignores HSTS there, so the
        # fix belongs in the TLS block (pass 3 flags that misplacement as
        # HDV204 instead).
        if tls:
            where = "plain HTTP response" if block.meta.get("scheme") == "http" else "response"
            out.append(
                _f(block, path, "HDV001", block.line, "", f"no Strict-Transport-Security on this {where}")
            )
    else:
        m = re.search(r"(?i)max-age\s*=\s*(\d+)", hsts.value)
        if m:
            age = int(m.group(1))
            if age < HSTS_MIN_AGE:
                out.append(
                    _f(
                        block, path, "HDV002", hsts.line, hsts.snippet,
                        f"max-age={age} is under the 15768000 floor ({age / 86400:.0f} days)",
                    )
                )
        if not re.search(r"(?i)includeSubDomains", hsts.value):
            out.append(_f(block, path, "HDV003", hsts.line, hsts.snippet, "includeSubDomains missing"))

    # ---- CSP ------------------------------------------------------------
    csp_vals = block.values("content-security-policy")
    report_only = block.has("content-security-policy-report-only")
    csp = csp_vals[0] if csp_vals else None
    if csp is None and not report_only:
        out.append(_f(block, path, "HDV004", block.line, "", "no Content-Security-Policy header"))
    if csp is not None:
        dirs = csp_directives(csp.value)
        scriptish = dirs.get("script-src", dirs.get("default-src", ""))
        inline_src = dirs.get("script-src", dirs.get("default-src", ""))
        if "unsafe-inline" in inline_src:
            src_name = "script-src" if "script-src" in dirs else "default-src"
            out.append(
                _f(block, path, "HDV005", csp.line, csp.snippet, f"unsafe-inline in {src_name}")
            )
        if "unsafe-eval" in scriptish:
            src_name = "script-src" if "script-src" in dirs else "default-src"
            out.append(
                _f(block, path, "HDV006", csp.line, csp.snippet, f"unsafe-eval in {src_name}")
            )
        if "default-src" not in dirs:
            out.append(_f(block, path, "HDV007", csp.line, csp.snippet, "policy has no default-src"))
        for tok in scriptish.split():
            if tok in ("*", "http:", "data:") or tok.startswith("*."):
                out.append(
                    _f(
                        block, path, "HDV008", csp.line, csp.snippet,
                        f"script-src (or default-src fallback) allows {tok!r}",
                    )
                )
        # pass 2: object-src
        obj = dirs.get("object-src")
        if obj is None and dirs.get("default-src", "") not in ("'none'", "none"):
            out.append(
                _f(block, path, "HDV105", csp.line, csp.snippet, "object-src unrestricted (no fallback to 'none')")
            )

    # ---- hygiene --------------------------------------------------------
    xcto = block.first("x-content-type-options")
    if xcto is None:
        out.append(_f(block, path, "HDV009", block.line, "", "no X-Content-Type-Options"))
    elif xcto.value.strip().lower() != "nosniff":
        out.append(_f(block, path, "HDV010", xcto.line, xcto.snippet, f"value is {xcto.value.strip()!r}, not nosniff"))

    xfo = block.first("x-frame-options")
    frame_ancestors = None
    if csp is not None:
        frame_ancestors = csp_directives(csp.value).get("frame-ancestors")
    if xfo is None and frame_ancestors is None:
        out.append(_f(block, path, "HDV011", block.line, "", "neither X-Frame-Options nor CSP frame-ancestors"))
    if xfo is not None and xfo.value.strip().lower().startswith("allow-from"):
        out.append(_f(block, path, "HDV012", xfo.line, xfo.snippet, "ALLOW-FROM is ignored by modern browsers"))

    rp = block.first("referrer-policy")
    if rp is None:
        out.append(_f(block, path, "HDV013", block.line, "", "no Referrer-Policy"))
    elif rp.value.strip().lower() in ("unsafe-url", "no-referrer-when-downgrade"):
        out.append(_f(block, path, "HDV014", rp.line, rp.snippet, f"policy {rp.value.strip()!r} leaks full URLs"))

    if not block.has("permissions-policy"):
        out.append(_f(block, path, "HDV015", block.line, "", "no Permissions-Policy"))

    # ---- disclosure -----------------------------------------------------
    server = block.first("server")
    if server is not None and _VERSIONY.search(server.value):
        out.append(
            _f(block, path, "HDV016", server.line, server.snippet, f"Server advertises {server.value.strip()!r}")
        )
    for name in ("x-powered-by", "x-aspnet-version", "x-generator"):
        val = block.first(name)
        if val is not None:
            out.append(_f(block, path, "HDV017", val.line, val.snippet, f"{name} header disclosed"))
            break
    if block.has("x-xss-protection"):
        val = block.first("x-xss-protection")
        out.append(_f(block, path, "HDV018", val.line, val.snippet, "X-XSS-Protection is a no-op today — remove it"))
    if block.has("expect-ct"):
        val = block.first("expect-ct")
        out.append(_f(block, path, "HDV019", val.line, val.snippet, "Expect-CT is retired - remove it"))

    # ---- cookies --------------------------------------------------------
    # Secure is only meaningful on TLS responses. TLS-known-True is owned by
    # HDV103 (pass 2); TLS-known-False (plaintext) makes the flag moot. So
    # HDV020 fires only when TLS is genuinely unknown (raw dumps).
    for cookie, val in block.cookies:
        if not _cookie_flag(cookie, "Secure") and block.tls is None:
            out.append(_f(block, path, "HDV020", val.line, val.snippet, "cookie lacks Secure"))
        if not _cookie_flag(cookie, "httponly"):
            out.append(_f(block, path, "HDV021", val.line, val.snippet, "cookie lacks HttpOnly"))
        if not _cookie_flag(cookie, "samesite"):
            out.append(_f(block, path, "HDV022", val.line, val.snippet, "cookie lacks SameSite"))
    if block.cookies and not block.has("cache-control"):
        cookie0 = block.cookies[0][1]
        out.append(
            _f(block, path, "HDV025", cookie0.line, cookie0.snippet, "Set-Cookie without any Cache-Control")
        )

    # ---- CORS -----------------------------------------------------------
    acao = block.first("access-control-allow-origin")
    acac = block.first("access-control-allow-credentials")
    if acao is not None:
        v = acao.value.strip()
        if v == "*":
            out.append(_f(block, path, "HDV023", acao.line, acao.snippet, "any origin may read this response"))
        elif _ORIGIN_REFLECTION.search(v):
            out.append(
                _f(block, path, "HDV024", acao.line, acao.snippet, "origin is echoed without an allowlist")
            )
        # pass 2 relations
        creds = (acac.value.strip().lower() == "true") if acac is not None else False
        if v == "*" and creds:
            out.append(
                _f(block, path, "HDV102", acac.line, acac.snippet, "wildcard ACAO combined with credentials")
            )
        if creds and _ORIGIN_REFLECTION.search(v):
            out.append(
                _f(
                    block, path, "HDV106", acac.line, acac.snippet,
                    "reflected origin WITH credentials — any site can read authenticated responses",
                )
            )

    # ---- duplicates within one block -------------------------------------
    for name, vals in block.headers.items():
        if len(vals) > 1 and len({v.value.strip().lower() for v in vals}) > 1:
            out.append(
                _f(
                    block, path, "HDV026", vals[1].line, vals[1].snippet,
                    f"{name} set twice with different values ({vals[0].value.strip()!r} vs {vals[1].value.strip()!r})",
                )
            )

    # ---- pass 2: policy/cookie relations ---------------------------------
    if report_only and csp is None:
        ro = block.first("content-security-policy-report-only")
        out.append(
            _f(block, path, "HDV101", ro.line, ro.snippet, "only Report-Only CSP found — nothing is enforced")
        )
    if tls and block.cookies:
        for cookie, val in block.cookies:
            if not _cookie_flag(cookie, "Secure"):
                out.append(
                    _f(block, path, "HDV103", val.line, val.snippet, "site serves TLS yet this cookie lacks Secure")
                )
    if xfo is not None and csp is not None and frame_ancestors is None:
        out.append(
            _f(
                block, path, "HDV104", xfo.line, xfo.snippet,
                "CSP present but framing still relies on legacy X-Frame-Options",
            )
        )
    return out
