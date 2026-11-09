"""Engine: discovery, routing, filters, dedupe."""

from __future__ import annotations

from headervet.engine import discover, scan


def test_discovery_finds_all_kinds(tmp_path):
    (tmp_path / "nginx.conf").write_text("server { add_header X-A \"1\"; }", encoding="utf-8")
    (tmp_path / "Caddyfile").write_text("a.example {\n header X-B \"2\"\n}\n", encoding="utf-8")
    (tmp_path / "app.js").write_text("res.setHeader('X-C', '3');\n", encoding="utf-8")
    (tmp_path / "resp.headers").write_text("HTTP/1.1 200 OK\nX-D: 4\n", encoding="utf-8")
    (tmp_path / ".htaccess").write_text('Header set X-E "5"\n', encoding="utf-8")
    (tmp_path / "readme.md").write_text("not a config", encoding="utf-8")
    disc = discover(tmp_path)
    names = {p.name for p in disc.files()}
    assert names == {"nginx.conf", "Caddyfile", "app.js", "resp.headers", ".htaccess"}


def test_skip_dirs_are_not_walked(tmp_path):
    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "node_modules" / "pkg" / "nginx.conf").write_text("server { }", encoding="utf-8")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "x.conf").write_text("server { }", encoding="utf-8")
    (tmp_path / "keep.conf").write_text("server { add_header X-A \"1\"; }", encoding="utf-8")
    assert [p.name for p in discover(tmp_path).files()] == ["keep.conf"]


def test_single_file_scan(tmp_path):
    f = tmp_path / "nginx.conf"
    f.write_text('server {\n add_header X-A "1";\n}\n', encoding="utf-8")
    result = scan(f)
    assert result.files == ["nginx.conf"]


def test_scan_of_empty_dir(tmp_path):
    result = scan(tmp_path)
    assert result.findings == [] and result.files == []


def test_nginx_in_filename_is_not_a_config(tmp_path):
    # Regression: the old "nginx in name" heuristic picked up test fixtures
    # and docs, then "found" broken configs inside prose strings.
    (tmp_path / "test_nginx.py").write_text(
        "CONF = 'server {\\n add_header X-A \"1\";\\n}'\\n", encoding="utf-8"
    )
    result = scan(tmp_path)
    assert result.files == [] and result.findings == []


def test_ignore_rules_and_groups(tmp_path):
    (tmp_path / "resp.headers").write_text(
        "HTTP/1.1 200 OK\nX-Content-Type-Options: sniff\nReferrer-Policy: unsafe-url\n",
        encoding="utf-8",
    )
    r1 = scan(tmp_path, ignore_rules={"HDV010"})
    ids1 = {f.rule.id for f in r1.findings}
    assert "HDV010" not in ids1 and "HDV014" in ids1
    r2 = scan(tmp_path, ignore_groups={"privacy"})
    assert "HDV014" not in {f.rule.id for f in r2.findings}


def test_min_severity_filter(tmp_path):
    (tmp_path / "resp.headers").write_text(
        "HTTP/1.1 200 OK\nReferrer-Policy: unsafe-url\nX-Powered-By: PHP\n",
        encoding="utf-8",
    )
    result = scan(tmp_path, min_severity="medium", severity_rank={
        "critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0,
    })
    ids = {f.rule.id for f in result.findings}
    assert "HDV014" in ids and "HDV017" not in ids  # low dropped


def test_findings_are_deduped(tmp_path):
    (tmp_path / "nginx.conf").write_text(
        'server {\n listen 80;\n}\nserver {\n listen 80;\n}\n', encoding="utf-8"
    )
    result = scan(tmp_path)
    # Both plaintext servers are missing everything; dedupe guarantees one
    # finding per (rule, path, line, detail) — different blocks differ by line.
    keys = [(f.rule.id, f.path, f.line, f.detail) for f in result.findings]
    assert len(keys) == len(set(keys))


def test_scan_survives_binary_garbage(tmp_path):
    (tmp_path / "nginx.conf").write_bytes(b"\x00\xff\xfe\x00")
    result = scan(tmp_path)
    assert isinstance(result.findings, list)
