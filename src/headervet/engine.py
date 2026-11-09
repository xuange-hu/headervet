"""Discovery and orchestration: three passes, one result."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import apache, caddy, express, nginx
from .checks import check_block
from .cross import check_cross
from .headset import HeaderSite, looks_like_dump, parse_dump
from .model import Finding, ScanResult

__all__ = ["scan", "discover", "parse_any"]

_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "venv",
    "dist",
    "build",
    "target",
    ".tox",
    "site-packages",
}

_NGINX_HINT = re.compile(r"\b(add_header|proxy_pass|proxy_hide_header|server\s*\{|listen\s)", re.IGNORECASE)
_APACHE_HINT = re.compile(r"^\s*(<VirtualHost|Header\s+\w+|SSLEngine|ServerTokens)", re.MULTILINE | re.IGNORECASE)
_EXPRESS_HINT = re.compile(r"res\.setHeader\s*\(|res\.set\s*\(|\bhelmet\s*\(|\.cookie\s*\(")


def parse_any(text: str, path: str) -> HeaderSite:
    """Route one file to the right parser by content, not by extension."""
    if looks_like_dump(Path(path), text):
        return parse_dump(text, path)
    if "<VirtualHost" in text:
        return apache.parse_apache(text, path)
    if _NGINX_HINT.search(text):
        return nginx.parse_nginx(text, path)
    # Caddy BEFORE the Apache fallback: `header X-Foo "v"` lines satisfy the
    # Apache `Header` hint, and only a Caddyfile has site-address blocks.
    if re.search(r"^\s*[\w.*-]+(/\S*)*\s*\{", text, re.MULTILINE) and re.search(r"\bheader\b", text, re.IGNORECASE):
        return caddy.parse_caddy(text, path)
    if _APACHE_HINT.search(text):
        return apache.parse_apache(text, path)
    if _EXPRESS_HINT.search(text):
        return express.parse_express(text, path)
    return HeaderSite(path=path)  # recognised filename, unrecognised content


def _is_express(name: str, lower: str) -> bool:
    return lower.endswith((".js", ".mjs", ".cjs", ".ts"))


def _is_conf(name: str, lower: str) -> bool:
    # Deliberately no "nginx in name" heuristic: it catches test fixtures and
    # documentation (test_nginx.py) and then "finds" broken configs in prose.
    return (
        lower in ("nginx.conf", "httpd.conf", "apache2.conf", "caddyfile", ".htaccess")
        or lower.endswith(".conf")
    )


def _is_dump(name: str, lower: str) -> bool:
    return lower.endswith(".headers") or lower.startswith("headers") and lower.endswith(".txt")


@dataclass
class Discovery:
    root: Path
    configs: list[Path] = field(default_factory=list)
    dumps: list[Path] = field(default_factory=list)
    apps: list[Path] = field(default_factory=list)

    def files(self) -> list[Path]:
        return sorted(set(self.configs) | set(self.dumps) | set(self.apps))


def discover(path: Path | str) -> Discovery:
    """Find candidate files under ``path`` (or classify a single file)."""
    target = Path(path)
    disc = Discovery(root=target.parent if target.is_file() else target)
    if target.is_file():
        _classify(target, target.name.lower(), disc, peek=target.read_text(encoding="utf-8", errors="replace"))
        return disc
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
        for filename in sorted(filenames):
            full = Path(dirpath) / filename
            lower = filename.lower()
            if _is_dump(filename, lower) or _is_conf(filename, lower) or _is_express(filename, lower):
                # Cheap content sniff only for files we would otherwise reject;
                # a .js file without any header API is not an app config.
                try:
                    peek = full.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                _classify(full, lower, disc, peek=peek)
    return disc


def _classify(full: Path, lower: str, disc: Discovery, peek: str) -> None:
    if _is_dump(lower, lower):
        disc.dumps.append(full)
    elif _is_conf(lower, lower):
        disc.configs.append(full)
    elif _is_express(lower, lower) and _EXPRESS_HINT.search(peek):
        disc.apps.append(full)
    else:
        return


def _rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def scan(
    path: Path | str,
    *,
    ignore_rules: set[str] | None = None,
    ignore_groups: set[str] | None = None,
    min_severity: str | None = None,
    severity_rank: dict[str, int] | None = None,
) -> ScanResult:
    """Run all three passes over ``path``."""
    disc = discover(path)
    root = disc.root
    result = ScanResult(root=str(root))

    sites: list[HeaderSite] = []
    for file_path in disc.files():
        display = _rel(file_path, root)
        try:
            site = parse_any(_read(file_path), display)
        except OSError as exc:
            result.skipped.append(f"{display}: {exc}")
            continue
        if not site.blocks and not site.errors:
            continue  # e.g. a .js file that merely mentions helmet in a comment
        sites.append(site)
        result.files.append(display)
        result.skipped.extend(f"{display}: {err}" for err in site.errors)

    findings: list[Finding] = []
    for site in sites:
        for block in site.blocks:
            findings.extend(check_block(block, site.path))
    findings.extend(check_cross(sites))

    findings = _dedupe(findings)
    findings = _filter(findings, ignore_rules or set(), ignore_groups or set(), min_severity, severity_rank)
    result.findings = findings
    result.files = sorted(set(result.files))
    return result


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """One finding per (rule, path, line, detail)."""
    seen: set[tuple[str, str, int, str]] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.rule.id, f.path, f.line, f.detail)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _filter(
    findings: list[Finding],
    ignore_rules: set[str],
    ignore_groups: set[str],
    min_severity: str | None,
    severity_rank: dict[str, int] | None,
) -> list[Finding]:
    ignore_rules = {r.upper() for r in ignore_rules}
    out: list[Finding] = []
    for f in findings:
        if f.rule.id in ignore_rules or f.rule.group in ignore_groups:
            continue
        if (
            min_severity
            and severity_rank
            and severity_rank.get(f.rule.severity, -1) < severity_rank.get(min_severity, 0)
        ):
            continue
        out.append(f)
    return out
