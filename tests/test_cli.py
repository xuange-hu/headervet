"""CLI: scan/rules/demo/live subcommands, formats, exit codes."""

from __future__ import annotations

import json

import pytest

from headervet import __version__
from headervet.cli import build_parser, main


def test_version(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_scan_text_exit_1_on_high(tmp_path):
    (tmp_path / "resp.headers").write_text(
        "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true\n",
        encoding="utf-8",
    )
    assert main(["scan", str(tmp_path), "--fail-on", "high"]) == 1
    assert main(["scan", str(tmp_path), "--fail-on", "none"]) == 0


def test_scan_json(tmp_path, capsys):
    (tmp_path / "resp.headers").write_text(
        "HTTP/1.1 200 OK\nX-Content-Type-Options: sniff\n", encoding="utf-8"
    )
    main(["scan", str(tmp_path), "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    # severity order puts the high finding (no CSP) first
    assert payload["findings"][0]["ruleId"] == "HDV004"
    assert any(f["ruleId"] == "HDV010" for f in payload["findings"])
    hit = next(f for f in payload["findings"] if f["ruleId"] == "HDV010")
    assert hit["snippet"].startswith("X-Content-Type-Options")


def test_scan_sarif(tmp_path, capsys):
    (tmp_path / "resp.headers").write_text(
        "HTTP/1.1 200 OK\nX-Content-Type-Options: sniff\n", encoding="utf-8"
    )
    main(["scan", str(tmp_path), "--format", "sarif"])
    sarif = json.loads(capsys.readouterr().out)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "headervet"


def test_scan_missing_path_exit_2(tmp_path):
    assert main(["scan", str(tmp_path / "nope")]) == 2


def test_scan_output_file(tmp_path):
    out = tmp_path / "report.json"
    (tmp_path / "resp.headers").write_text(
        "HTTP/1.1 200 OK\nX-Content-Type-Options: sniff\n", encoding="utf-8"
    )
    main(["scan", str(tmp_path), "--format", "json", "-o", str(out)])
    assert "HDV010" in out.read_text(encoding="utf-8")


def test_rules_listing(capsys):
    main(["rules"])
    out = capsys.readouterr().out
    assert "36 rule(s)" in out
    main(["rules", "--pass", "3"])
    out = capsys.readouterr().out
    assert "HDV201" in out and "HDV001" not in out


def test_rules_json(capsys):
    main(["rules", "--json"])
    rules = json.loads(capsys.readouterr().out)
    assert len(rules) == 36


def test_demo(capsys):
    assert main(["demo"]) == 0
    out = capsys.readouterr().out
    assert "summary:" in out


def test_demo_json_counts_all_rules(capsys):
    main(["demo", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert len(payload["rules_hit"]) == 36


def test_demo_keep(tmp_path):
    keep = tmp_path / "fixture"
    main(["demo", "--keep", str(keep)])
    assert (keep / "nginx.conf").is_file()


def test_parser_accepts_live_arguments():
    args = build_parser().parse_args(["live", "example.com", "--insecure", "--timeout", "5"])
    assert args.command == "live" and args.insecure and args.timeout == 5.0


def test_live_bad_url_exit_2(capsys):
    assert main(["live", "http://127.0.0.1:1"]) == 2
