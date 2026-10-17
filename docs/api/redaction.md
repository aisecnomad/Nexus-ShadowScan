# Redaction

The redaction module sanitizes finding evidence and report values before they leave
ShadowScan's internal representation. Its job is to ensure that credentials, tokens and
other sensitive values captured during scanning never appear in a report, log, cache entry
or diagnostic output — regardless of which output format is selected.

## Design principles

- **Sanitize before shortening**: once a credential is truncated, its recognizable structure
  may be lost and the redaction pass cannot identify it. All redaction happens on the full
  value before any truncation.
- **Independent of signature settings**: disabling secret *discovery* must never disable
  *redaction*. Redaction runs unconditionally on every finding.
- **Modular passes**: the redaction logic is split across `redaction_formats`,
  `redaction_statements`, `redaction_assignments`, `redaction_calls`, `redaction_commands`
  and `redaction_markup`. This module is their single public face; patch here, not in a
  submodule, so changes propagate to every module that imports a name from here.

## What gets redacted

| Category | Examples |
|----------|---------|
| Token formats | API keys (`sk-...`), bearer tokens, JWTs, OAuth client secrets |
| URLs with credentials | `https://user:<password>@host/` |
| Assignment statements | `API_KEY = "sk-..."`, `token: "eyJ..."` in code or YAML |
| Command arguments | `--token=sk-...`, `-p password123` |
| Markup attributes | `value="Bearer ey..."` in HTML/XML |

## Sanitization limit

`SanitizationLimitError` is raised when a finding's evidence is too large or too deeply nested
to sanitize safely. Findings that hit the limit are excluded from all output formats and
recorded as a warning.

::: shadowscan.utils.redaction
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
