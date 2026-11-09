"""Pass 3: relations between configs — the part single-response scanners miss."""

from __future__ import annotations

from .headset import HeaderSite
from .model import Finding
from .rules import by_id

__all__ = ["check_cross"]

_SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
)


def _f(path: str, rid: str, line: int, snippet: str, detail: str, site: str) -> Finding:
    return Finding(rule=by_id(rid), path=path, line=line, snippet=snippet[:200], detail=detail, site=site, block=site)  # type: ignore[arg-type]


def check_cross(sites: list[HeaderSite]) -> list[Finding]:
    out: list[Finding] = []

    # HDV201: nginx location-level add_header cancels inherited server headers.
    for site in sites:
        for block in site.blocks:
            if block.origin != "nginx":
                continue
            server_names = {n for n in block.headers if n != "set-cookie"}
            if not server_names:
                continue
            for loc in block.locations:
                if not loc.headers:
                    continue  # inheritance is only cancelled by an add_header here
                missing = sorted(n for n in server_names if n not in loc.headers)
                if missing:
                    out.append(
                        _f(
                            site.path, "HDV201", loc.line,
                            f"location {loc.label}",
                            f"first add_header here cancels {len(missing)} inherited header(s): "
                            + ", ".join(missing),
                            block.label,
                        )
                    )

    # HDV202: the same header with different values in different files.
    # set-cookie is excluded: multiple cookies are normal.
    by_name: dict[str, dict[str, tuple[str, int, str, str]]] = {}
    for site in sites:
        for block in site.blocks:
            for name, vals in block.headers.items():
                if name == "set-cookie":
                    continue
                for v in vals:
                    key = v.value.strip().lower()
                    by_name.setdefault(name, {}).setdefault(key, (site.path, v.line, v.snippet, block.label))
    for name, variants in by_name.items():
        if len(variants) < 2:
            continue
        ordered = sorted(variants.values(), key=lambda t: (t[0], t[1]))
        first_path, _, first_snip, first_site = ordered[0]
        for path, line, snippet, site_label in ordered[1:]:
            out.append(
                _f(
                    path, "HDV202", line, snippet,
                    f"{name} conflicts with {first_path} ({first_site!r}: {first_snip[:80]!r})",
                    site_label,
                )
            )

    # HDV203: proxy_hide_header / Header unset / `-Name` strips a header
    # that another config sets.
    stripped: dict[str, tuple[str, int, str, str]] = {}
    for site in sites:
        for block in site.blocks:
            for name, line, snippet in block.hide_headers:
                stripped.setdefault(name.lower(), (site.path, line, snippet, block.label))
    if stripped:
        for site in sites:
            for block in site.blocks:
                for name in list(block.headers):
                    hit = stripped.get(name)
                    if hit is None:
                        continue
                    src_path, _, _, _ = hit
                    if src_path == site.path and block.origin != "nginx":
                        continue  # same-file hide+set is usually deliberate
                    val = block.first(name)
                    out.append(
                        _f(
                            src_path, "HDV203", hit[1], hit[2],
                            f"strips {name}, which {site.path} sets ({val.snippet[:80]!r})",
                            hit[3],
                        )
                    )

    # HDV204: HSTS declared on a listener that serves plain HTTP.
    for site in sites:
        for block in site.blocks:
            hsts = block.first("strict-transport-security")
            if hsts is None or block.tls is not False:
                continue
            out.append(
                _f(
                    site.path, "HDV204", hsts.line, hsts.snippet,
                    "HSTS on a plaintext listener is ignored by every browser (spec: secure responses only)",
                    block.label,
                )
            )
    return out
