"""The rule registry.

Rule ids are stable and the pass number is part of the contract:
pass 1 reads a single header value, pass 2 reads the headers of one site
together, pass 3 reads the relation between configs. online scanners
(securityheaders.com) stop at pass 1 — the expensive mistakes live in 2 and 3.
"""

from __future__ import annotations

from .model import Rule

__all__ = ["RULES", "all_rules", "by_id", "groups"]


def _r(rid, title, severity, group, why, fix, pass_no=1, cwe="") -> Rule:
    return Rule(
        id=rid,
        title=title,
        severity=severity,
        group=group,
        why=why,
        fix=fix,
        pass_no=pass_no,
        cwe=cwe,
    )


_RULE_LIST = [
    # -- pass 1: one header value on its own -------------------------------
    _r(
        "HDV001",
        "No HSTS observed",
        "medium",
        "transport",
        "Without Strict-Transport-Security a user who types the bare hostname "
        "gets one HTTP request before the redirect — and that request can be "
        "intercepted, or the redirect can be replaced by a lookalike site.",
        "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` "
        "on every HTTPS response.",
        cwe="CWE-319",
    ),
    _r(
        "HDV002",
        "HSTS max-age is too short",
        "medium",
        "transport",
        "A max-age below ~6 months means the protection lapses for returning "
        "visitors long before stale bookmarks and old links stop circulating.",
        "Raise max-age to at least 15768000 (182 days); 31536000 once you are "
        "confident every subdomain is HTTPS.",
    ),
    _r(
        "HDV003",
        "HSTS does not cover subdomains",
        "low",
        "transport",
        "Without includeSubDomains, http://admin.example.com is still fair "
        "game on the first request — and attackers pick the subdomain you "
        "forgot.",
        "Append `; includeSubDomains` once every subdomain serves HTTPS.",
    ),
    _r(
        "HDV004",
        "No Content-Security-Policy",
        "high",
        "csp",
        "CSP is the one control that turns an injection bug into a non-event: "
        "without it, every XSS in the app executes with full page authority.",
        "Start with a report-only policy, then enforce a default-src based "
        "policy.",
        cwe="CWE-693",
    ),
    _r(
        "HDV005",
        "CSP allows unsafe-inline",
        "high",
        "csp",
        "unsafe-inline in script-src re-enables exactly the inline script "
        "injection CSP exists to stop; style-src unsafe-inline is milder but "
        "usually cargo-culted rather than needed.",
        "Move inline scripts/handlers into files or use nonces/hashes; drop "
        "unsafe-inline from script-src.",
        cwe="CWE-79",
    ),
    _r(
        "HDV006",
        "CSP allows unsafe-eval",
        "medium",
        "csp",
        "unsafe-eval lets an attacker turn any injection primitive into code "
        "execution via eval/new Function, which most frameworks never need in "
        "production.",
        "Remove unsafe-eval; if a bundled dependency requires it, pin and "
        "review that dependency.",
    ),
    _r(
        "HDV007",
        "CSP has no default-src",
        "low",
        "csp",
        "Directives fall back to default-src. Without it, a policy that only "
        "lists script-src silently allows everything else: images, frames, "
        "connect endpoints.",
        "Start the policy with `default-src 'self'` and add directives only "
        "to relax it deliberately.",
    ),
    _r(
        "HDV008",
        "CSP script-src allows wildcard or insecure scheme",
        "high",
        "csp",
        "`*`, `http:` or `data:` in script-src means any origin (or any "
        "HTTP-injected script) satisfies the policy — the allowlist becomes "
        "decoration.",
        "Pin exact hosts, prefer https:// origins, and drop data: URLs for "
        "scripts.",
        cwe="CWE-79",
    ),
    _r(
        "HDV009",
        "No X-Content-Type-Options",
        "medium",
        "hygiene",
        "Without nosniff, browsers may interpret an uploaded .jpg or a "
        "user-controlled text response as JavaScript — MIME confusion is a "
        "classic stored-XSS delivery channel.",
        "Send `X-Content-Type-Options: nosniff` on every response.",
    ),
    _r(
        "HDV010",
        "X-Content-Type-Options is not nosniff",
        "low",
        "hygiene",
        "The header has exactly one meaningful value. Anything else is either "
        "ignored by browsers or evidence that two layers both tried to set "
        "it.",
        "Set the value to exactly `nosniff`, and set it in one place only.",
    ),
    _r(
        "HDV011",
        "No clickjacking protection",
        "medium",
        "clickjacking",
        "Neither X-Frame-Options nor CSP frame-ancestors is present, so any "
        "site can frame this one: UI redress attacks on the payment or admin "
        "flow become trivial.",
        "Prefer CSP `frame-ancestors 'self'` (or 'none'); X-Frame-Options: "
        "DENY as a belt-and-braces fallback.",
        cwe="CWE-1021",
    ),
    _r(
        "HDV012",
        "X-Frame-Options ALLOW-FROM is obsolete",
        "low",
        "clickjacking",
        "ALLOW-FROM was never shipped by Chrome or Safari and is ignored by "
        "every modern browser — it silently degrades to no protection.",
        "Use CSP `frame-ancestors <uri>` instead.",
    ),
    _r(
        "HDV013",
        "No Referrer-Policy",
        "low",
        "privacy",
        "The default referrer leaks full URLs — including tokens in query "
        "strings — to every third-party resource the page loads.",
        "Send `Referrer-Policy: strict-origin-when-cross-origin` (or "
        "no-referrer for sensitive apps).",
    ),
    _r(
        "HDV014",
        "Referrer-Policy leaks full URLs",
        "medium",
        "privacy",
        "unsafe-url and no-referrer-when-downgrade intentionally send the "
        "complete URL cross-origin, path and query string included.",
        "Use strict-origin-when-cross-origin or stricter.",
        cwe="CWE-200",
    ),
    _r(
        "HDV015",
        "No Permissions-Policy",
        "info",
        "privacy",
        "Embedded iframes and third-party scripts can request camera, "
        "microphone or geolocation unless the site explicitly opts out.",
        "Send `Permissions-Policy: camera=(), microphone=(), geolocation=()` "
        "and grant features per-frame only where needed.",
    ),
    _r(
        "HDV016",
        "Server header discloses a version",
        "low",
        "disclosure",
        "A version in `Server:` (or similar) turns recon into copy-paste: an "
        "attacker looks up the known CVEs for exactly that build.",
        "Remove the version (`server_tokens off;` in nginx) or the whole "
        "header.",
        cwe="CWE-200",
    ),
    _r(
        "HDV017",
        "Framework fingerprint disclosed",
        "low",
        "disclosure",
        "X-Powered-By and friends advertise the runtime stack. It is cheap "
        "recon for free and helps nobody legitimate.",
        "Remove it (`app.disable('x-powered-by')`, `expose_php=Off`, "
        "`RemoveServerHeader` in ASP.NET).",
        cwe="CWE-200",
    ),
    _r(
        "HDV018",
        "X-XSS-Protection is set",
        "low",
        "legacy",
        "The auditor it once enabled was removed from all browsers years "
        "ago; the header does nothing today and its `1; mode=block` variant "
        "enabled an XSS-auditor XS-Leak while it still existed.",
        "Delete the header.",
    ),
    _r(
        "HDV019",
        "Expect-CT is set",
        "info",
        "legacy",
        "Expect-CT was retired: Certificate Transparency is enforced "
        "unconditionally for all certificates issued after April 2018.",
        "Delete the header.",
    ),
    _r(
        "HDV020",
        "Cookie without Secure",
        "medium",
        "cookies",
        "A session cookie without Secure rides along on any http:// request "
        "to the host — one image tag on a captive-portal page and it is in "
        "the clear.",
        "Set `Secure` (and prefer the __Host- prefix when the cookie is "
        "host-scoped).",
        cwe="CWE-614",
    ),
    _r(
        "HDV021",
        "Cookie without HttpOnly",
        "medium",
        "cookies",
        "Without HttpOnly, document.read in any injected script exfiltrates "
        "the session cookie — the difference between XSS and account "
        "takeover.",
        "Set `HttpOnly` on every cookie the server does not intentionally "
        "expose to JS.",
        cwe="CWE-1004",
    ),
    _r(
        "HDV022",
        "Cookie without SameSite",
        "low",
        "cookies",
        "Without SameSite the cookie follows the legacy default and stays "
        "usable as a CSRF payload on cross-site POSTs in some browsers.",
        "Set `SameSite=Lax` (or Strict for state-changing flows).",
    ),
    _r(
        "HDV023",
        "CORS allows any origin",
        "low",
        "cors",
        "`Access-Control-Allow-Origin: *` lets any web page read the "
        "response. Harmless for public data, critical the moment auth "
        "cookies or intranet reachability are involved.",
        "Echo an explicit allowlist of origins instead of *.",
    ),
    _r(
        "HDV024",
        "CORS reflects the request origin",
        "high",
        "cors",
        "The config echoes whatever Origin the request carries "
        "($http_origin / %{Origin}i) with no allowlist. Every origin is "
        "therefore allowed, including attacker.example, while looking like "
        "a 'configured' CORS policy in review.",
        "Match Origin against a fixed allowlist before echoing it, or do "
        "not echo at all.",
        cwe="CWE-942",
    ),
    _r(
        "HDV025",
        "Set-Cookie response without Cache-Control",
        "low",
        "cache",
        "Shared caches may store and replay a response that carries session "
        "material unless Cache-Control explicitly forbids it.",
        "Send `Cache-Control: no-store` whenever Set-Cookie is present.",
    ),
    _r(
        "HDV026",
        "Header set twice with conflicting values",
        "medium",
        "hygiene",
        "The same header appears with different values in one response. "
        "Browsers either join them (CSP: both must pass, so the stricter "
        "one wins but the intent is gone) or drop the pair (XFO: invalid).",
        "Set each header exactly once; find the second layer that also "
        "sets it.",
    ),
    # -- pass 2: relations within one site's headers ------------------------
    _r(
        "HDV101",
        "CSP is report-only with no enforcing policy",
        "medium",
        "csp",
        "Content-Security-Policy-Report-Only never blocks anything. If it is "
        "the only CSP header, the site ships without enforcement — often "
        "because the report-only phase was never closed out.",
        "Finish the rollout: send the enforcing `Content-Security-Policy` "
        "(keep the report-only one alongside while tuning).",
        pass_no=2,
    ),
    _r(
        "HDV102",
        "CORS wildcard together with credentials",
        "critical",
        "cors",
        "`Access-Control-Allow-Origin: *` combined with "
        "`Access-Control-Allow-Credentials: true`. Browsers refuse this "
        "exact pair, but non-browser clients, older gateways and "
        "hand-rolled CORS middlewares act on it — and the config documents "
        "an intent the author never should have had.",
        "Echo the concrete origin from an allowlist; never combine * with "
        "credentials.",
        pass_no=2,
        cwe="CWE-942",
    ),
    _r(
        "HDV103",
        "HTTPS site serves cookies without Secure",
        "medium",
        "cookies",
        "The site clearly runs on TLS (HSTS present), so the missing Secure "
        "flag on its cookies is a one-word fix away — and until then each "
        "cookie survives one plaintext request.",
        "Add Secure to every Set-Cookie on the TLS site.",
        pass_no=2,
        cwe="CWE-614",
    ),
    _r(
        "HDV104",
        "X-Frame-Options set but CSP omits frame-ancestors",
        "info",
        "clickjacking",
        "The site carries a CSP yet relies on the legacy XFO for framing. "
        "XFO cannot allowlist per-page and is ignored by the directive that "
        "replaced it.",
        "Move framing policy into CSP frame-ancestors and drop XFO once "
        "coverage is confirmed.",
        pass_no=2,
    ),
    _r(
        "HDV105",
        "CSP leaves object-src unrestricted",
        "low",
        "csp",
        "object-src without a fallback to default-src 'none' still permits "
        "legacy plug-in content and some sandbox-escape gadgets.",
        "Add `object-src 'none'` (flash/java objects are long dead).",
        pass_no=2,
    ),
    _r(
        "HDV106",
        "CORS reflects the origin and allows credentials",
        "critical",
        "cors",
        "The reflected-origin policy (HDV024) is combined with "
        "Access-Control-Allow-Credentials: true — this is the full "
        "any-site-can-read-with-cookies configuration. unlike the wildcard "
        "pair, browsers do NOT block this one.",
        "Echo only origins from an explicit allowlist; require credentials "
        "to be a deliberate per-origin decision.",
        pass_no=2,
        cwe="CWE-942",
    ),
    # -- pass 3: relations between configs ----------------------------------
    _r(
        "HDV201",
        "location add_header cancels inherited server headers",
        "high",
        "inheritance",
        "nginx add_header inheritance is all-or-nothing: the first "
        "add_header in a location block removes EVERY header inherited from "
        "the server block. Security headers silently disappear for exactly "
        "the routes that needed their own header — no error, no warning.",
        "Re-declare the security headers inside the location, or move them "
        "into an include used by both levels.",
        pass_no=3,
    ),
    _r(
        "HDV202",
        "Same header, different values across layers",
        "medium",
        "consistency",
        "Two configs set the same header to different values. Depending on "
        "browser, the values are joined (CSP becomes the intersection) or "
        "the pair is rejected outright — the behaviour nobody configured.",
        "Pick one owner per header; delete the duplicate from the other "
        "layer.",
        pass_no=3,
    ),
    _r(
        "HDV203",
        "proxy_hide_header strips a security header",
        "high",
        "consistency",
        "The proxy explicitly hides a header that another config sets "
        "(typically an app-level X-Frame-Options or CSP). The app ships "
        "protection the edge removes — every online scanner that tested the "
        "app directly reported green.",
        "Remove the proxy_hide_header entry, or confirm the proxy sets its "
        "own replacement.",
        pass_no=3,
    ),
    _r(
        "HDV204",
        "HSTS declared on a plaintext listener",
        "medium",
        "transport",
        "The Strict-Transport-Security header is added on a server block "
        "that serves plain HTTP. The spec requires browsers to IGNORE HSTS "
        "on non-secure responses, so this line protects nobody — while "
        "making the config look compliant.",
        "Move the HSTS add_header into the TLS (listen ... ssl / SSLEngine "
        "on) server block.",
        pass_no=3,
    ),
]

RULES: dict[str, Rule] = {r.id: r for r in _RULE_LIST}


def all_rules() -> list[Rule]:
    return list(_RULE_LIST)


def by_id(rule_id: str) -> Rule | None:
    return RULES.get(rule_id.upper())


def groups() -> list[str]:
    seen: list[str] = []
    for rule in _RULE_LIST:
        if rule.group not in seen:
            seen.append(rule.group)
    return seen
