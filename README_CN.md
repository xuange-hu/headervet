# headervet

[![CI](https://github.com/xuange-hu/headervet/actions/workflows/ci.yml/badge.svg)](https://github.com/xuange-hu/headervet/actions/workflows/ci.yml)
![tests-132%20passing](https://img.shields.io/badge/tests-132%20passing-brightgreen)
![dependencies-0](https://img.shields.io/badge/dependencies-0-blue)
![license-MIT](https://img.shields.io/badge/license-MIT-lightgrey)

**带行号证据的 HTTP 安全响应头审计器。**
nginx / Apache / Caddy / Express 配置、原始响应 dump、在线 URL 三种输入——
36 条规则、零依赖、SARIF、MCP server。

English: [README.md](README.md)

```bash
uvx --from "git+https://github.com/xuange-hu/headervet" headervet demo
```

## 为什么还要一个响应头检查器

在线扫描器（securityheaders.com 之类）只给**一个响应**打分。真正在线上出事的
两种情况它都看不见：

1. **代理把应用干的事撤了。** Express 设了 `X-Frame-Options`，nginx 边缘写了
   `proxy_hide_header X-Frame-Options`——直接测应用的扫描器报绿，生产上一个字都没有。
2. **nginx add_header 继承陷阱。** `location` 块里出现第一个 `add_header` 时，
   从 `server` 块继承的**所有**头全部失效。恰恰是那些需要多加一个头的路由，
   把安全头全弄丢了。

headervet 按请求路径的方式读配置：

| 遍 | 读什么 | 抓什么 |
|---|---|---|
| 1 | 单个头的值 | 缺 HSTS/CSP/XCTO/XFO/RP/PP、HSTS 过短、`unsafe-inline`、通配 CORS、cookie 标志、版本泄露 |
| 2 | 一个响应的头之间的关系 | 只有 Report-Only 的 CSP、CORS `*` + credentials、TLS 站给不加密 cookie、XFO 顶替 CSP 的活 |
| 3 | 配置之间的关系 | location 级丢头（HDV201）、跨层值冲突（HDV202）、`proxy_hide_header` 剥头（HDV203）、HSTS 写在明文监听上（HDV204） |

每条结论都带 `文件:行号`、原文片段和修复方法。

## 三步上手

```bash
pip install "headervet @ git+https://github.com/xuange-hu/headervet"

# 1. 内置的坏工程——5 秒证明工具是活的
headervet demo

# 2. 扫仓库里的配置（nginx/Apache/Caddy/Express、dump）
headervet scan .

# 3. 扫一个在线 URL（标准库 http.client，不装 requests）
headervet live https://example.com
```

`demo` 预期输出（72 条结论，36/36 规则全部命中）：

```
nginx.conf
   9  HDV002  medium   p1 transport
        | add_header Strict-Transport-Security "max-age=86400" always;
        -> max-age=86400 is under the 15768000 floor (1 days)
        fix: Raise max-age to at least 15768000 (182 days); ...
```

## 认哪些输入

| 输入 | 怎么找到 | 解析什么 |
|---|---|---|
| nginx | `*.conf`、`*nginx*` | `server`/`location` 块、`add_header`、`proxy_hide_header`、`listen ... ssl` |
| Apache | `*.conf`、`.htaccess` | `<VirtualHost>`、`Header set/add/unset`、`SSLEngine` |
| Caddy | `Caddyfile` | 站点块、`header`（行内 + 块）、`-Name` 删除 |
| Express/Node | `*.js/*.mjs/*.ts` | `res.setHeader`、`res.set({...})`、`res.cookie`、`helmet()`、`disable('x-powered-by')` |
| 响应 dump | `*.headers`、`headers*.txt` | `curl -sD -` 风格，一个文件里多跳各自成块 |
| 在线 | CLI `live` 子命令 | 单次 GET、不跟随跳转——跳转那一跳本身往往就是结论 |

## CI 门禁 + SARIF

```yaml
- name: header audit
  run: |
    pip install "headervet @ git+https://github.com/xuange-hu/headervet"
    headervet scan . --fail-on high --format sarif -o headervet.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: headervet.sarif
```

退出码：`0` 干净，`1` 有 `--fail-on` 及以上的结论，`2` 用法错误或 URL 不可达。

## MCP server（Claude Code / Cursor / Cline）

```bash
uvx --from "git+https://github.com/xuange-hu/headervet[mcp]" headervet-mcp
```

六个工具：`headervet_scan`、`headervet_live`、`headervet_explain`、
`headervet_rules`、`headervet_sarif`、`headervet_demo`。

## 规则

`headervet rules` 打印全部 36 条（严重度 / 遍 / 分组）。重点：

| ID | 级别 | 内容 |
|---|---|---|
| HDV004 | high | 没有 Content-Security-Policy |
| HDV005 | high | CSP `unsafe-inline` |
| HDV008 | high | script-src 通配 / `http:` / `data:` |
| HDV024 | high | CORS 回显请求 Origin 无白名单 |
| HDV102 | critical | CORS `*` + credentials |
| HDV106 | critical | 回显 Origin + credentials |
| HDV103 | medium | TLS 站的 cookie 缺 `Secure` |
| HDV201 | high | nginx location `add_header` 取消继承的头 |
| HDV203 | high | `proxy_hide_header` 剥掉应用设的头 |
| HDV204 | medium | HSTS 写在明文监听上 |

完整清单：`headervet rules --json` 或 `headervet explain HDV201`。

## 设计要点

- **零依赖。** 审计跑在与部署目标同一容器里；`live` 模式用标准库 `http.client`。
- **确定性。** 无 LLM、无打分模型——同一输入永远同一结论，CI 门禁才可信。
- **证据优先。** 每条结论：路径、行号、片段、说明、修法。行号错了测试会抓住。
- **覆盖即可执行。** `headervet demo` 命中全部 36 条规则；哪条失灵
  `tests/test_demo.py` 就红。

## 状态

v0.1.0 — 36 规则、130 测试、ruff 全绿、CI 覆盖 3.10–3.13。
路线图：HAR 输入、`more_set_headers`（OpenResty）、Traefik labels、
CSP hash 计算、逐路由 frame-ancestors 覆盖分析。

## 许可

MIT
