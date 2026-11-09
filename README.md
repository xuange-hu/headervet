# headervet

[![CI](https://github.com/xuange-hu/headervet/actions/workflows/ci.yml/badge.svg)](https://github.com/xuange-hu/headervet/actions/workflows/ci.yml)
![tests-130%20passing](https://img.shields.io/badge/tests-130%20passing-brightgreen)
![dependencies-0](https://img.shields.io/badge/dependencies-0-blue)
![license-MIT](https://img.shields.io/badge/license-MIT-lightgrey)

**HTTP security header audit with the line numbers that prove each finding.**
Reads nginx, Apache, Caddy and Express configs *and* raw response dumps *and*
live URLs — 36 rules, zero dependencies, SARIF for CI, MCP server.

中文文档：[README_CN.md](README_CN.md)

```bash
uvx --from "git+https://github.com/xuange-hu/headervet" headervet demo
```

## Why another header checker

Online scanners (securityheaders.com and friends) grade **one response**.
That misses the two failure modes that actually ship:

1. **The proxy undoes the app.** The Express app sets `X-Frame-Options`;
   the nginx edge has `proxy_hide_header X-Frame-Options` — a scanner that
   tested the app directly reports green while production sends nothing.
2. **nginx add_header inheritance.** The first `add_header` in a `location`
   block cancels *every* header inherited from the `server` block. The routes
   that needed one extra header silently lose all the security ones.

headervet reads the configs the way the request path does:

| Pass | Reads | Catches |
|---|---|---|
| 1 | one header value | missing HSTS/CSP/XCTO/XFO/RP/PP, weak HSTS, `unsafe-inline`, wildcard CORS, cookie flags, version disclosure |
| 2 | one response together | report-only-only CSP, CORS `*` + credentials, TLS site with `Secure`-less cookies, XFO doing CSP's job |
| 3 | configs together | location-level header loss (HDV201), conflicting values across layers (HDV202), `proxy_hide_header` stripping (HDV203), HSTS on a plaintext listener (HDV204) |

Every finding carries `file:line`, the offending snippet, and the fix.

## 3-step start

```bash
pip install "headervet @ git+https://github.com/xuange-hu/headervet"

# 1. the built-in broken project — proves the tool works in 5 seconds
headervet demo

# 2. audit configs in your repo (nginx/Apache/Caddy/Express, dumps)
headervet scan .

# 3. audit a live URL (stdlib http.client, no requests dependency)
headervet live https://example.com
```

Expected `demo` output (72 findings, all 36 rules exercised):

```
nginx.conf
   9  HDV002  medium   p1 transport
        | add_header Strict-Transport-Security "max-age=86400" always;
        -> max-age=86400 is under the 15768000 floor (1 days)
        fix: Raise max-age to at least 15768000 (182 days); ...
```

## What it reads

| Input | How it's found | Parses |
|---|---|---|
| nginx | `*.conf`, `*nginx*` | `server`/`location` blocks, `add_header`, `proxy_hide_header`, `listen ... ssl` |
| Apache | `*.conf`, `.htaccess` | `<VirtualHost>`, `Header set/add/unset`, `SSLEngine` |
| Caddy | `Caddyfile` | site blocks, `header` (inline + block), `-Name` removal |
| Express/Node | `*.js/*.mjs/*.ts` | `res.setHeader`, `res.set({...})`, `res.cookie`, `helmet()`, `disable('x-powered-by')` |
| Response dumps | `*.headers`, `headers*.txt` | `curl -sD -` style dumps, multiple hops per file |
| Live | CLI `live` subcommand | one GET, no redirects — the redirect hop is often the finding |

## CI gate + SARIF

```yaml
- name: header audit
  run: |
    pip install "headervet @ git+https://github.com/xuange-hu/headervet"
    headervet scan . --fail-on high --format sarif -o headervet.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: headervet.sarif
```

Exit codes: `0` clean, `1` findings at/above `--fail-on`, `2` usage or
unreachable URL.

## MCP server (Claude Code / Cursor / Cline)

```bash
uvx --from "git+https://github.com/xuange-hu/headervet[mcp]" headervet-mcp
```

Six tools: `headervet_scan`, `headervet_live`, `headervet_explain`,
`headervet_rules`, `headervet_sarif`, `headervet_demo`.

## Rules

`headervet rules` prints all 36 with severity, pass and group.
Highlights:

| ID | Sev | What |
|---|---|---|
| HDV004 | high | no Content-Security-Policy |
| HDV005 | high | CSP `unsafe-inline` |
| HDV008 | high | script-src wildcard / `http:` / `data:` |
| HDV024 | high | CORS reflects the request origin |
| HDV102 | critical | CORS `*` + credentials |
| HDV106 | critical | reflected origin + credentials |
| HDV103 | medium | TLS site, cookie without `Secure` |
| HDV201 | high | nginx location `add_header` cancels inherited headers |
| HDV203 | high | `proxy_hide_header` strips a header the app sets |
| HDV204 | medium | HSTS declared on a plaintext listener |

Full list with why/fix: `headervet rules --json` or `headervet explain HDV201`.

## Design notes

- **Zero dependencies.** The audit runs in the same slim container that
  deploys the proxy it audits; `live` mode is stdlib `http.client`.
- **Deterministic.** No LLM, no scoring model — the same input yields the
  same findings, so CI gates stay trustworthy.
- **Evidence-first.** Every finding: path, line, snippet, detail, fix.
  If a line number is wrong, the test suite notices.
- **Coverage is executable.** `headervet demo` trips all 36 rules;
  `tests/test_demo.py` fails if a rule stops firing.

## Status

v0.1.0 — 36 rules, 130 tests, ruff clean, CI on 3.10–3.13.
Roadmap: HAR input, `more_set_headers` (OpenResty), Traefik labels,
CSP hash computation, per-route frame-ancestors coverage.

## License

MIT
