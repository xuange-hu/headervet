"""Express reader: setHeader (single + multiline object), cookies, helmet."""

from __future__ import annotations

from headervet.engine import parse_any

APP = """\
const express = require('express');
const app = express();
app.disable('x-powered-by');

app.use((req, res) => {
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-Custom', "double 'quoted' value");
  res.set({
    'X-Multi-One': 'a',
    'X-Multi-Two': 'b',
  });
  res.cookie('session', 't-108', { httpOnly: true });
});
"""


def test_set_header_single_form():
    site = parse_any(APP, "app.js")
    b = site.blocks[0]
    assert b.first("x-frame-options").value == "SAMEORIGIN"


def test_set_header_with_inner_quotes():
    site = parse_any(APP, "app.js")
    b = site.blocks[0]
    assert b.first("x-custom").value == "double 'quoted' value"


def test_set_object_multiline():
    site = parse_any(APP, "app.js")
    b = site.blocks[0]
    assert b.first("x-multi-one").value == "a"
    assert b.first("x-multi-two").value == "b"


def test_cookie_and_meta():
    site = parse_any(APP, "app.js")
    b = site.blocks[0]
    assert b.cookies and b.cookies[0][0] == "session"
    assert b.meta.get("xpowered_disabled") is True
    assert "helmet" not in b.meta


def test_helmet_detected():
    site = parse_any("app.use(helmet({\n  frameguard: false,\n}));\n", "app.js")
    assert site.blocks[0].meta.get("helmet") is True


def test_parse_any_yields_nothing_for_header_free_js():
    site = parse_any("console.log('hello');\n", "util.js")
    # Discovery skips such files before parse_any; parse_any itself just
    # refuses to invent a block.
    assert not site.blocks


def test_line_numbers_point_at_the_call():
    site = parse_any(APP, "app.js")
    val = site.blocks[0].first("x-frame-options")
    assert val.line == 6
