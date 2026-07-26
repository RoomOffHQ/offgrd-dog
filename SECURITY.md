# Security Policy

## Reporting a vulnerability

Please do **not** open a public GitHub issue for security
vulnerabilities. Instead:

- Open a [GitHub Security Advisory](../../security/advisories/new) on
  this repository (preferred — keeps the report private until a fix
  ships), or
- Email the maintainers at **security@offgrd-dog.example** (placeholder
  — update once the project has a real domain/contact) with a
  description of the issue, steps to reproduce, and its potential
  impact.

We'll acknowledge your report within 5 business days and aim to have a
fix or mitigation plan within 30 days for confirmed vulnerabilities,
depending on severity.

## Scope

Given what OffGrd Dog does, these are especially high-priority:

- Anything that lets an unprivileged process influence or crash
  OffGrd Dog's kernel-mode component (once it exists).
- Anything that lets OffGrd Dog itself be used as an attack vector
  (e.g. a malicious plugin escaping its sandbox, a crafted event log
  triggering memory unsafety in a parser).
- Supply-chain issues (a compromised dependency, a broken build
  reproducibility guarantee).
- Privilege escalation via OffGrd Dog running with elevated rights.

## Supported versions

Pre-1.0: only the latest commit on `main` is supported. A real support
matrix will be published once there's a first tagged release.
