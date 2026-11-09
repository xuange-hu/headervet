"""Express / Node reader: res.setHeader, res.set({...}), helmet, disable()."""

from __future__ import annotations

import re

from .headset import HeaderBlock, HeaderSite, HeaderVal

__all__ = ["parse_express"]

_SET_HEADER = re.compile(
    r"""res\.setHeader\s*\(\s*
        (?P<q>["'`])(?P<name>[^"'`]+)(?P=q)\s*,\s*
        (?P<q2>["'`])(?P<val>.*?)(?P=q2)\s*\)\s*;""",
    re.VERBOSE,
)
_SET_OBJ = re.compile(r"\.set\s*\(\s*\{")
_OBJ_ENTRY = re.compile(
    r"""["']?(?P<name>[\w-]+)["']?\s*:\s*(?P<q>["'])(?P<val>[^'"]*)(?P=q)"""
)
_COOKIE = re.compile(r"\.cookie\s*\(\s*(?P<q>['\"])(?P<pair>[^'\"]*)(?P=q)")
_HELMET = re.compile(r"\bhelmet\s*\(")
_DISABLE_XPB = re.compile(r"disable\s*\(\s*['\"]x-powered-by['\"]\s*\)")


def parse_express(text: str, path: str) -> HeaderSite:
    site = HeaderSite(path=path)
    block = HeaderBlock(label="app", line=1, origin="express")
    site.blocks.append(block)

    obj_lines = _collect_set_objects(text)

    for lineno, raw in enumerate(text.splitlines(), start=1):
        for m in _SET_HEADER.finditer(raw):
            block.add(m.group("name"), HeaderVal(m.group("val"), lineno, raw.strip()))
        for m in _COOKIE.finditer(raw):
            block.cookies.append((m.group("pair"), HeaderVal(m.group("pair"), lineno, raw.strip())))
    for name, val, lineno, snippet in obj_lines:
        block.add(name, HeaderVal(val, lineno, snippet))

    if _HELMET.search(text):
        block.meta["helmet"] = True
    if _DISABLE_XPB.search(text):
        block.meta["xpowered_disabled"] = True
    return site


def _collect_set_objects(text: str) -> list[tuple[str, str, int, str]]:
    """Handle the `res.set({ 'X-Foo': 'bar', ... })` multiline form."""
    out: list[tuple[str, str, int, str]] = []
    for m in _SET_OBJ.finditer(text):
        start = m.end()
        depth = 1
        i = start
        while i < len(text) and depth:
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
            i += 1
        chunk = text[start : i - 1]
        lineno = text.count("\n", 0, m.start()) + 1
        snippet = text[m.start() : min(i, m.start() + 120)].splitlines()[0].strip()
        for em in _OBJ_ENTRY.finditer(chunk):
            line_no = lineno + chunk[: em.start()].count("\n")
            out.append((em.group("name"), em.group("val"), line_no, snippet))
    return out
