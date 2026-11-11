# Security policy

## Scope

`headervet` reads untrusted input in three shapes: server configuration
files, captured response dumps, and live URLs it is pointed at. The parsers
and the HTTP client are both part of the attack surface.

What is in scope:

- a config, dump or response that crashes the scanner, hangs it, or makes it
  allocate without bound;
- a file that makes the tool report *fewer* findings than it should (a
  parsing bug that silently skips a server block is a security bug, not a
  quality issue);
- SSRF-class behavior: a URL argument that makes the tool connect somewhere
  other than the host:port the operator named (redirect handling, DNS
  rebinding, proxy environment variables);
- a finding wrong enough to make a reader remove a header that was
  protecting them;
- response bodies or headers written to disk outside the requested output
  path.

What is not in scope:

- rules that fire on a header value you consider acceptable - open an issue;
- the absence of a header check you would like (a PR with a sample response
  is welcome);
- vulnerabilities on the target being scanned (report them to that target's
  operator).

## Reporting

Open a private security advisory on GitHub (`Security` -> `Advisories` ->
`New draft advisory`). Include the offending bytes or a minimal reproducer.

Expect an initial response within a week. This is a single-maintainer
project, not a product with an SLA.

## Supported versions

The latest release. Old releases will be told to upgrade rather than
patched.
