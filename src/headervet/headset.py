"""Header-site model and the raw response-dump reader.

A :class:`HeaderBlock` is one possible response context: a server block in
nginx, a VirtualHost in Apache, one site block in Caddy, one app file for
Express, or one ``HTTP/1.1 200 OK`` section in a captured dump. Pass-1 and
pass-2 checks run per block; pass-3 checks read blocks *and* their files
together.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["HeaderVal", "HeaderBlock", "HeaderSite", "parse_dump", "csp_directives", "HSTS_NAME"]

HSTS_NAME = "strict-transport-security"

# Header names are ASCII case-insensitive everywhere.
_CAMEL_OVERRIDES = {
    "content-security-policy",
    "content-security-policy-report-only",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "strict-transport-security",
    "x-xss-protection",
    "x-powered-by",
    "x-aspnet-version",
    "x-generator",
    "x-runtime",
    "cache-control",
    "server",
    "set-cookie",
}


def _title(name: str) -> str:
    """Canonical display form: `x-frame-options` -> `X-Frame-Options`."""
    return "-".join(part.capitalize() for part in name.split("-"))


@dataclass
class HeaderVal:
    value: str
    line: int
    snippet: str


@dataclass
class HeaderBlock:
    """One response context: label, its headers, and what we inferred."""

    label: str
    line: int
    origin: str  # nginx | apache | caddy | express | dump | live
    headers: dict[str, list[HeaderVal]] = field(default_factory=dict)
    tls: bool | None = None  # known TLS / known plain / unknown
    cookies: list[tuple[str, HeaderVal]] = field(default_factory=list)
    # nginx: declared locations with their own headers, for pass 3.
    locations: list[HeaderBlock] = field(default_factory=list)
    # nginx: proxy_hide_header entries (name, line, snippet).
    hide_headers: list[tuple[str, int, str]] = field(default_factory=list)
    meta: dict = field(default_factory=dict)

    def add(self, name: str, val: HeaderVal) -> None:
        key = name.lower()
        self.headers.setdefault(key, []).append(val)

    def first(self, name: str) -> HeaderVal | None:
        vals = self.headers.get(name.lower())
        return vals[0] if vals else None

    def values(self, name: str) -> list[HeaderVal]:
        return self.headers.get(name.lower(), [])

    def has(self, name: str) -> bool:
        return bool(self.headers.get(name.lower()))

    def set_cookie_names(self) -> list[str]:
        names: list[str] = []
        for raw, _ in self.cookies:
            names.append(raw.split("=", 1)[0].strip())
        return names


@dataclass
class HeaderSite:
    path: str  # display path (relative to scan root)
    blocks: list[HeaderBlock] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# -- CSP parsing --------------------------------------------------------------

_TOKEN_SPLIT = re.compile(r";")
_DIRECTIVE_RE = re.compile(r"^\s*([a-z-]+)\s*(.*)$")


def csp_directives(policy: str) -> dict[str, str]:
    """`script-src 'self' x.com; object-src` -> {"script-src": "'self' x.com", ...}"""
    out: dict[str, str] = {}
    for chunk in _TOKEN_SPLIT.split(policy):
        m = _DIRECTIVE_RE.match(chunk)
        if m:
            out[m.group(1)] = m.group(2).strip()
    return out


def _script_sources(dirs: dict[str, str]) -> list[str]:
    """Sources that can load scripts, honouring the default-src fallback."""
    own = dirs.get("script-src")
    if own is not None:
        return own.split()
    if "default-src" in dirs:
        return dirs["default-src"].split()
    return []


# -- raw dump -----------------------------------------------------------------

_STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+\d+", re.IGNORECASE)


def parse_dump(text: str, path: str) -> HeaderSite:
    """Parse a captured response (``headers.txt`` / ``*.headers``).

    Accepts output from `curl -sD -`, `headervet live --save`, or a pasted
    response. Each `HTTP/...` status line starts a new block so redirect
    chains are checked hop by hop.
    """
    site = HeaderSite(path=path)
    block: HeaderBlock | None = None

    def _flush() -> None:
        nonlocal block
        if block is not None and (
            block.headers
            or block.cookies
            or block.label.lower().startswith("http/")
        ):
            # A status line alone is still a response context: the "no headers
            # at all" case is exactly what HDV004/009/011/013/015 look for.
            site.blocks.append(block)
        block = None

    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip("\r")
        stripped = line.strip()
        if _STATUS_RE.match(stripped):
            _flush()
            # Dumps are assumed to be HTTPS responses: security headers are
            # only meaningful there, and the assumption is documented in the
            # rules (HDV001/HDV103 vs HDV020, which needs true "unknown").
            block = HeaderBlock(
                label=stripped or "response", line=lineno, origin="dump", tls=True
            )
            continue
        if block is None:
            if not stripped:
                continue
            # Tolerate dumps that start without a status line.
            block = HeaderBlock(label="response", line=lineno, origin="dump", tls=True)
        if not stripped:
            _flush()
            continue
        if stripped.startswith("#"):
            continue
        if ":" not in line:
            site.errors.append(f"{path}:{lineno}: not a header line: {stripped[:60]!r}")
            continue
        name, _, value = line.partition(":")
        value = value.strip()
        if name.lower() == "set-cookie":
            block.cookies.append((value, HeaderVal(value, lineno, line.strip())))
        else:
            block.add(name.strip(), HeaderVal(value, lineno, line.strip()))
    _flush()
    return site


# -- shared helpers used by the config parsers --------------------------------


def looks_like_dump(path: Path, text: str) -> bool:
    name = path.name.lower()
    if name.endswith((".headers", ".har")):
        return name.endswith(".headers")  # HAR is JSON, out of scope for now
    if name in ("headers.txt",) or name.startswith("headers"):
        return True
    return _STATUS_RE.match(text.lstrip()) is not None
