"""SARIF output structure and text rendering."""

from __future__ import annotations

import json

from headervet.engine import scan
from headervet.render import build_sarif, render_text


def _result(tmp_path):
    (tmp_path / "resp.headers").write_text(
        "HTTP/1.1 200 OK\nX-Content-Type-Options: sniff\nAccess-Control-Allow-Origin: *\n",
        encoding="utf-8",
    )
    return scan(tmp_path)


def test_sarif_structure(tmp_path):
    sarif = build_sarif(_result(tmp_path))
    assert sarif["$schema"].endswith("sarif-2.1.0.json")
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "headervet"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert "HDV010" in rule_ids
    res = next(r for r in run["results"] if r["ruleId"] == "HDV010")
    assert res["level"] in ("error", "warning", "note")
    loc = res["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uriBaseId"] == "%SRCROOT%"
    assert loc["region"]["startLine"] >= 1
    assert loc["region"]["snippet"]["text"].startswith("X-Content-Type-Options")


def test_sarif_is_valid_json_and_pretty(tmp_path):
    assert json.loads(json.dumps(build_sarif(_result(tmp_path))))


def test_sarif_carries_risk(tmp_path):
    result = _result(tmp_path)
    run = build_sarif(result)["runs"][0]
    from headervet.model import SEVERITY_WEIGHT

    expected = sum(SEVERITY_WEIGHT[f.rule.severity] for f in result.findings)
    expected = min(100, expected)
    assert run["properties"]["risk"] == expected


def test_render_text_evidence_first(tmp_path):
    out = render_text(_result(tmp_path), color=False)
    assert "resp.headers" in out
    assert "HDV010" in out
    assert "-> " in out
    assert "fix: " in out
    assert "summary:" in out


def test_render_text_colour_codes_only_when_asked(tmp_path):
    plain = render_text(_result(tmp_path), color=False)
    assert "\x1b[" not in plain
    painted = render_text(_result(tmp_path), color=True)
    assert "\x1b[1;31m" in painted or "\x1b[1;35m" in painted or "\x1b[33m" in painted


def test_render_empty_result(tmp_path):
    out = render_text(scan(tmp_path), color=False)
    assert "clean" in out
