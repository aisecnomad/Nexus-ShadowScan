---
title: Security
---

This page is [SECURITY.md](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/SECURITY.md), included in the documentation site.

--8<-- "SECURITY.md"

## Scan-process isolation

Authenticated Git clones keep their origin-scoped authorization header in a
temporary mode-0600 config file inside a mode-0700 directory, not in the
child's environment or command line. The scanner removes it when the clone
ends or is terminated. Another process with the same UID can still read it
while the clone runs; use a dedicated per-scan UID or disposable container.
Forced process termination or a host crash can prevent cleanup.

Plugin workers receive a per-plugin derived identity key, not the scan's
identity key. This is key separation, not a sandbox: allowlisted plugins and
installed packages remain trusted code with scanner privileges.

LLM triage requires explicit `allow_custom_base_url: true` before sending an
API key to an HTTPS origin other than the provider's default. This consent
does not bypass private-origin restrictions or TLS validation.
