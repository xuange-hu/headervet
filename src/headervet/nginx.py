"""nginx config reader: server/location blocks, add_header, proxy_hide_header.

The whole point of reading nginx (rather than treating it as opaque text) is
the inheritance model: the FIRST add_header in a nested block cancels every
add_header inherited from the parent. That is recorded structurally so pass 3
can flag the routes where security headers silently vanish.
"""

from __future__ import annotations

import re

from .headset import HeaderBlock, HeaderSite, HeaderVal

__all__ = ["parse_nginx"]

_OPEN = re.compile(r"^\s*(server|location|http|if)\b(.*)\{\s*$")
_CLOSE = re.compile(r"^\s*\}\s*$")
_ADD_HEADER = re.compile(
    r"""^\s*add_header\s+
        (?P<name>[\w!#$%&'*+.^`|~-]+)\s+
        (?P<val>"(?:[^"\\]|\\.)*"|[^;]+?)
        (?P<rest>(?:\s+\w+)*)\s*;""",
    re.VERBOSE | re.IGNORECASE,
)
_HIDE = re.compile(r"^\s*proxy_hide_header\s+([\w!#$%&'*+.^`|~-]+)\s*;", re.IGNORECASE)
_LISTEN = re.compile(r"^\s*listen\s+([^;]+);", re.IGNORECASE)
_COMMENT = re.compile(r"(^|\s)#.*$")


def _strip_comment(line: str) -> str:
    return _COMMENT.sub("", line)


def _clean_val(val: str) -> str:
    val = val.strip()
    if val.startswith('"') and val.endswith('"') and len(val) >= 2:
        val = val[1:-1]
    return val


def parse_nginx(text: str, path: str) -> HeaderSite:
    site = HeaderSite(path=path)
    # Stack entries: (kind, label, line, block-or-None). `http` and `if`
    # contribute no headers of their own; `server` opens a HeaderBlock;
    # `location` opens a nested one.
    stack: list[tuple[str, str, HeaderBlock | None]] = []
    current_server: HeaderBlock | None = None

    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = _strip_comment(raw).rstrip()
        if not line.strip():
            continue
        open_m = _OPEN.match(line)
        if open_m:
            kind = open_m.group(1).lower()
            label = open_m.group(2).strip()
            if kind == "server":
                current_server = HeaderBlock(label=label or "server", line=lineno, origin="nginx")
                site.blocks.append(current_server)
                stack.append((kind, label, current_server))
            elif kind == "location" and current_server is not None:
                loc = HeaderBlock(label=f"location {label}".strip(), line=lineno, origin="nginx")
                current_server.locations.append(loc)
                stack.append((kind, label, loc))
            else:
                stack.append((kind, label, None))
            continue
        if _CLOSE.match(line):
            if stack:
                kind, _, blk = stack.pop()
                if kind == "server":
                    current_server = None
            continue

        m = _ADD_HEADER.match(line)
        if m:
            val = HeaderVal(_clean_val(m.group("val")), lineno, line.strip())
            flags = set((m.group("rest") or "").split())
            target = None
            for kind, _, blk in reversed(stack):
                if kind == "location" and blk is not None:
                    target = blk
                    break
                if kind == "server" and blk is not None:
                    target = blk
                    target.meta.setdefault("add_header_at_server", True)
                    # Headers found while inside a location belong to it; the
                    # reversed() walk above stops there first.
                    if not any(k == "location" for k, _, _ in stack):
                        break
            if target is None:
                # add_header outside any server block still ships headers —
                # keep it on a synthetic block so pass 3 can match it against
                # app configs (HDV202/HDV203 need every set to be visible).
                target = HeaderBlock(label="(global)", line=lineno, origin="nginx")
                site.blocks.append(target)
            if target is not None:
                name = m.group("name")
                if name.lower() == "set-cookie":
                    target.cookies.append((val.value, val))
                else:
                    target.add(name, val)
                if "always" in flags:
                    target.meta.setdefault("always_lines", []).append(lineno)
            continue

        m = _HIDE.match(line)
        if m:
            target = next((blk for _, _, blk in reversed(stack) if blk is not None), None)
            if target is None:
                # hide outside any server block still matters — keep it on a
                # synthetic block so pass 3 can match it against app configs.
                target = HeaderBlock(label="(global)", line=lineno, origin="nginx")
                site.blocks.append(target)
            target.hide_headers.append((m.group(1), lineno, line.strip()))
            continue

        m = _LISTEN.match(line)
        if m and current_server is not None:
            spec = m.group(1)
            if re.search(r"\bssl\b|\b443\b", spec):
                current_server.tls = True
            elif "http2" not in spec and re.search(r"^\s*\d{1,5}\b|default_server|:\d{1,5}", spec):
                current_server.tls = current_server.tls if current_server.tls else False
            current_server.meta.setdefault("listen", []).append(spec.strip())
    return site
