"""Apache config reader: VirtualHost blocks, Header directives, SSLEngine."""

from __future__ import annotations

import re

from .headset import HeaderBlock, HeaderSite, HeaderVal

__all__ = ["parse_apache"]

_OPEN = re.compile(r"^\s*<(\w+)([^>]*)>\s*$")
_CLOSE = re.compile(r"^\s*</\w+>\s*$")
_HEADER = re.compile(
    r"""^\s*Header\s+
        (?P<mode>set|add|always\s+set|always\s+add|append|merge|unset)\s+
        (?P<name>[\w!#$%&'*+.^`|~-]+)
        (?:\s+(?:"(?P<val1>[^"]*)"|(?P<val2>[^;\n]+?)))?\s*$""",
    re.VERBOSE | re.IGNORECASE,
)
_SSL = re.compile(r"^\s*SSLEngine\s+on\s*$", re.IGNORECASE)
_COMMENT = re.compile(r"(^|\s)#.*$")


def parse_apache(text: str, path: str) -> HeaderSite:
    site = HeaderSite(path=path)
    current: HeaderBlock | None = None

    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = _COMMENT.sub("", raw).strip()
        if not line:
            continue
        m = _OPEN.match(line)
        if m:
            tag = m.group(1).lower()
            if tag == "virtualhost":
                addr = m.group(2).strip()
                # Port in the address is the cheapest TLS signal; SSLEngine on
                # is the authoritative one and overrides below.
                tls = None
                if ":443" in addr:
                    tls = True
                elif ":80" in addr:
                    tls = False
                current = HeaderBlock(
                    label=addr or "VirtualHost", line=lineno, origin="apache", tls=tls
                )
                site.blocks.append(current)
            continue
        if _CLOSE.match(line):
            current = None
            continue
        if _SSL.match(line) and current is not None:
            current.tls = True
            continue
        m = _HEADER.match(line)
        if m:
            if current is None:
                # Header outside a VirtualHost: server-wide. Keep a synthetic
                # block so global hardening is still checked.
                current = HeaderBlock(label="server (global)", line=lineno, origin="apache")
                site.blocks.append(current)
            mode = m.group("mode").lower().split()
            name = m.group("name")
            value = m.group("val1") if m.group("val1") is not None else m.group("val2")
            val = HeaderVal((value or "").strip(), lineno, line)
            if "unset" in mode:
                current.hide_headers.append((name, lineno, line))
            elif name.lower() == "set-cookie":
                current.cookies.append((val.value, val))
            else:
                current.add(name, val)
    return site
