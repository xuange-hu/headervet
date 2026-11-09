"""The demo fixture IS the coverage claim: all 36 rules must fire on it."""

from __future__ import annotations

import tempfile
from pathlib import Path

from headervet.demo import FILES, materialize
from headervet.engine import scan
from headervet.rules import RULES

EXPECTED = set(RULES)  # 36 ids


def test_demo_trips_every_rule():
    tmp = tempfile.TemporaryDirectory(prefix="headervet-test-demo-")
    try:
        root = materialize(Path(tmp.name))
        result = scan(root)
        hit = {f.rule.id for f in result.findings}
        missing = sorted(EXPECTED - hit)
        assert not missing, f"rules no longer exercised by the demo: {missing}"
        extra = sorted(hit - EXPECTED)
        assert not extra, f"unknown rules fired: {extra}"
        assert result.worst() == "critical"
    finally:
        tmp.cleanup()


def test_demo_files_are_self_describing():
    assert "nginx.conf" in FILES and "app.js" in FILES and "response.headers" in FILES


def test_materialize_is_idempotent(tmp_path):
    materialize(tmp_path)
    mtime_first = (tmp_path / "nginx.conf").stat().st_mtime_ns
    materialize(tmp_path)
    assert (tmp_path / "nginx.conf").read_text(encoding="utf-8").startswith("# demo")
    assert (tmp_path / "nginx.conf").stat().st_mtime_ns >= mtime_first
