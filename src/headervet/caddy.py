"""Caddyfile reader: site blocks and header directives.

Caddy is HTTPS by default, which is why HSTS absence is cheap to flag here;
`http://`-prefixed site addresses are the plaintext exception.
"""

from __future__ import annotations

import re

from .headset import HeaderBlock, HeaderSite, HeaderVal

__all__ = ["parse_caddy"]

_SITE = re.compile(r"^\s*(?P<addr>[^\s{][^{]*?)\s*\{\s*$")
_HEADER_INLINE = re.compile(
    r"""^\s*header\s+
        (?P<name>[\w!#$%&'*+.^`|~-]+)\s+
        (?:"(?P<val1>[^"]*)"|(?P<val2>\S+))\s*$""",
    re.VERBOSE | re.IGNORECASE,
)
_HEADER_OPEN = re.compile(r"^\s*header\s*\{\s*$")
_HEADER_ENTRY = re.compile(
    r"""^\s*(?P<minus>-)?\s*
        (?P<name>[\w!#$%&'*+.^`|~-]+)\s*
        (?:"(?P<val1>[^"]*)"|(?P<val2>[^{\n]+?))?\s*$""",
    re.VERBOSE,
)
_COMMENT = re.compile(r"(^|\s)#.*$")


def _clean(val: str | None) -> str:
    return (val or "").strip()


def parse_caddy(text: str, path: str) -> HeaderSite:
    site = HeaderSite(path=path)
    current: HeaderBlock | None = None
    in_header_block = False

    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = _COMMENT.sub("", raw).strip()
        if not line:
            continue
        m = _HEADER_INLINE.match(line)
        if m and current is not None:
            val = HeaderVal(_clean(m.group("val1") or m.group("val2")), lineno, line)
            if m.group("name").lower() == "set-cookie":
                current.cookies.append((val.value, val))
            else:
                current.add(m.group("name"), val)
            continue
        if _HEADER_OPEN.match(line):
            in_header_block = True
            continue
        if in_header_block:
            if line == "}":
                in_header_block = False
                continue
            m = _HEADER_ENTRY.match(line)
            if m and current is not None:
                name = m.group("name")
                val = HeaderVal(_clean(m.group("val1") or m.group("val2")), lineno, line)
                if m.group("minus"):
                    current.hide_headers.append((name, lineno, line))
                elif name.lower() == "set-cookie":
                    current.cookies.append((val.value, val))
                elif val.value:
                    current.add(name, val)
            continue
        m = _SITE.match(line)
        if m:
            addr = m.group("addr").strip()
            plain = addr.startswith("http://")
            current = HeaderBlock(label=addr, line=lineno, origin="caddy", tls=not plain)
            site.blocks.append(current)
            continue
        if line == "}":
            current = None
    return site
