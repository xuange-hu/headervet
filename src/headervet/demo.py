"""Zero-setup demo: a deliberately broken header config set that trips all rules.

The fixtures below are the executable definition of "covered". If a rule stops
firing here, ``tests/test_demo.py`` fails, so the coverage claim in the README
cannot rot the way prose does.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

__all__ = ["FILES", "materialize", "demo_dir"]

FILES: dict[str, str] = {
    "nginx.conf": """\
# demo: deliberately broken nginx header configuration
server {
    listen 443 ssl;
    server_name shop.example;

    add_header Strict-Transport-Security "max-age=86400" always;
    add_header Content-Security-Policy "script-src * 'unsafe-inline' 'unsafe-eval'" always;
    add_header X-Content-Type-Options "sniff" always;
    add_header Referrer-Policy "unsafe-url" always;
    add_header Set-Cookie "sid=abc; HttpOnly" always;
    add_header Access-Control-Allow-Origin "*" always;
    add_header Access-Control-Allow-Credentials "true" always;

    location /app {
        add_header X-Debug-Route "app" always;
        proxy_pass http://backend;
    }
}

server {
    listen 443 ssl;
    server_name minimal.example;
    # No headers at all — the "fresh deploy" special.
}

server {
    listen 80;
    server_name redirect.example;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    return 301 https://shop.example$request_uri;
}

server {
    listen 443 ssl;
    server_name api.example;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Access-Control-Allow-Origin "$http_origin" always;
    add_header Access-Control-Allow-Credentials "true" always;
    add_header X-Frame-Options "DENY" always;
}
""",
    "proxy.conf": """\
# demo: the edge proxy that quietly undoes the app's work
server {
    listen 443 ssl;
    server_name edge.example;
    proxy_hide_header X-Frame-Options;
    location / {
        proxy_pass http://app:3000;
    }
}
""",
    "app.js": """\
// demo: express app whose header story contradicts the proxy
const express = require('express');
const app = express();

app.use((req, res) => {
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Content-Security-Policy', "default-src 'self' 'unsafe-inline'");
  res.cookie('session', 't-108', { path: '/' });
  res.send('ok');
});
""",
    "response.headers": """\
HTTP/1.1 200 OK
Server: nginx/1.24.0
X-Powered-By: Express
X-XSS-Protection: 1; mode=block
Expect-CT: max-age=0, report-uri="https://report.example"
X-Frame-Options: ALLOW-FROM https://trusted.example
Strict-Transport-Security: max-age=31536000
Strict-Transport-Security: max-age=63072000
Content-Security-Policy-Report-Only: default-src 'self'

""",
    "README.md": "# demo project\n\nDeliberately broken; run `headervet demo`.\n",
}


def materialize(target: Path | str) -> Path:
    """Write the fixture project into ``target`` and return the path."""
    root = Path(target)
    root.mkdir(parents=True, exist_ok=True)
    for name, content in FILES.items():
        dest = root / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8", newline="\n")
    return root


def demo_dir() -> tempfile.TemporaryDirectory:
    """A temporary directory holding the fixture project."""
    tmp = tempfile.TemporaryDirectory(prefix="headervet-demo-")
    materialize(Path(tmp.name))
    return tmp
