"""MCP surface — optional extra, imported only when the ``mcp`` package exists.

The module stays importable without `mcp`: the ImportError is deferred to
``build_server()``, so `headervet --version` never needs the optional dependency.

Tool names are given explicitly (`@mcp.tool(name=...)`) because the decorator
otherwise registers the wrapper's function name, and a tool called
`headervet_scan_tool` is a worse prompt target than `headervet_scan`.
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any

from .checks import check_block
from .demo import materialize
from .engine import scan
from .live import fetch
from .model import SEVERITY_RANK, ScanResult
from .render import build_sarif, render_text
from .rules import RULES, all_rules, by_id

TOOLS = (
    "headervet_scan",
    "headervet_live",
    "headervet_explain",
    "headervet_rules",
    "headervet_sarif",
    "headervet_demo",
)


def _scan(path: str, min_severity: str, ignore_rules: str, ignore_groups: str):
    return scan(
        path,
        ignore_rules={r.strip() for r in ignore_rules.split(",") if r.strip()},
        ignore_groups={g.strip() for g in ignore_groups.split(",") if g.strip()},
        min_severity=min_severity if min_severity in SEVERITY_RANK else None,
        severity_rank=SEVERITY_RANK,
    )


def headervet_scan(
    path: str = ".",
    min_severity: str = "info",
    ignore_rules: str = "",
    ignore_groups: str = "",
    max_findings: int = 80,
) -> str:
    """Audit HTTP security headers in configs (nginx/Apache/Caddy/Express) and response dumps.

    Three passes: single header values, relations within one site (CORS
    wildcard + credentials, report-only CSP), and relations between configs
    (nginx add_header inheritance loss, proxy_hide_header stripping,
    conflicting values across layers). Returns JSON with per-finding
    file:line evidence.
    """
    if not os.path.exists(path):
        return json.dumps({"error": f"path not found: {path}", "tool": "headervet"}, ensure_ascii=False)
    result = _scan(path, min_severity, ignore_rules, ignore_groups)
    payload: dict[str, Any] = result.as_dict()
    payload["summary"] = render_text(result)
    total = len(result.findings)
    payload["findings"] = payload["findings"][: max(1, int(max_findings))]
    payload["truncatedFindings"] = total > max_findings
    return json.dumps(payload, indent=2, ensure_ascii=False)


def headervet_live(url: str, insecure: bool = False) -> str:
    """Fetch a URL once and audit the actual response headers it returns.

    Uses the standard library only. One request, redirects not followed —
    the redirect hop itself is often the interesting one.
    """
    site, err = fetch(url, insecure=insecure)
    if err is not None:
        return json.dumps({"error": f"{url}: {err}", "tool": "headervet"}, ensure_ascii=False)
    findings = []
    for block in site.blocks:
        findings.extend(check_block(block, site.path))
    result = ScanResult(root=site.path, findings=findings, files=[site.path])
    payload = result.as_dict()
    payload["summary"] = render_text(result)
    return json.dumps(payload, indent=2, ensure_ascii=False)


def headervet_explain(rule_id: str) -> str:
    """Explain one rule: what the pattern is, why it matters, and how to fix it."""
    rule = by_id(rule_id)
    if rule is None:
        return json.dumps(
            {"error": f"unknown rule {rule_id}", "known": sorted(RULES)},
            ensure_ascii=False,
        )
    return json.dumps(
        {**rule.as_dict(), "narrative": f"{rule.why}\n\nFix: {rule.fix}"},
        indent=2,
        ensure_ascii=False,
    )


def headervet_rules(group: str = "", pass_no: int = 0) -> str:
    """List rules, filterable by group and by pass (1=single header, 2=in-site relations, 3=cross-config)."""
    items = [r for r in all_rules() if not group or r.group == group]
    if pass_no:
        items = [r for r in items if r.pass_no == pass_no]
    return json.dumps(
        {"count": len(items), "rules": [r.as_dict() for r in items]},
        indent=2,
        ensure_ascii=False,
    )


def headervet_sarif(path: str = ".") -> str:
    """Scan and return SARIF 2.1.0, ready for GitHub code scanning."""
    if not os.path.exists(path):
        return json.dumps({"error": f"path not found: {path}"}, ensure_ascii=False)
    result = _scan(path, "info", "", "")
    return json.dumps(build_sarif(result), indent=2, ensure_ascii=False)


def headervet_demo() -> str:
    """Scan a built-in broken project that trips all rules — one call proves the tool works."""
    tmp = tempfile.TemporaryDirectory(prefix="headervet-demo-mcp-")
    try:
        root = materialize(tmp.name)
        result = scan(root)
        payload = result.as_dict()
        payload["summary"] = render_text(result)
        payload["demoPath"] = str(root)
        return json.dumps(payload, indent=2, ensure_ascii=False)
    finally:
        tmp.cleanup()


def build_server():
    """Construct the MCP server. Requires the optional `mcp` extra."""
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP(name="headervet")

    @mcp.tool(name="headervet_scan")
    def _scan_tool(
        path: str = ".",
        min_severity: str = "info",
        ignore_rules: str = "",
        ignore_groups: str = "",
        max_findings: int = 80,
    ) -> str:
        """Audit HTTP security headers in configs and response dumps (three passes)."""
        return headervet_scan(path, min_severity, ignore_rules, ignore_groups, max_findings)

    @mcp.tool(name="headervet_live")
    def _live_tool(url: str, insecure: bool = False) -> str:
        """Fetch a URL once and audit the actual response headers it returns."""
        return headervet_live(url, insecure)

    @mcp.tool(name="headervet_explain")
    def _explain_tool(rule_id: str) -> str:
        """Explain one rule: pattern, why it matters, how to fix."""
        return headervet_explain(rule_id)

    @mcp.tool(name="headervet_rules")
    def _rules_tool(group: str = "", pass_no: int = 0) -> str:
        """List all rules, filterable by group and pass."""
        return headervet_rules(group, pass_no)

    @mcp.tool(name="headervet_sarif")
    def _sarif_tool(path: str = ".") -> str:
        """Scan and return SARIF 2.1.0 for GitHub code scanning."""
        return headervet_sarif(path)

    @mcp.tool(name="headervet_demo")
    def _demo_tool() -> str:
        """Scan a built-in broken project that trips all 36 rules."""
        return headervet_demo()

    return mcp


def tool_manifest() -> list[dict[str, str]]:
    return [
        {"name": "headervet_scan", "description": headervet_scan.__doc__ or ""},
        {"name": "headervet_live", "description": headervet_live.__doc__ or ""},
        {"name": "headervet_explain", "description": headervet_explain.__doc__ or ""},
        {"name": "headervet_rules", "description": headervet_rules.__doc__ or ""},
        {"name": "headervet_sarif", "description": headervet_sarif.__doc__ or ""},
        {"name": "headervet_demo", "description": headervet_demo.__doc__ or ""},
    ]


def main() -> None:
    build_server().run()


if __name__ == "__main__":  # pragma: no cover
    main()
