# Redaction

The redaction module withholds credentials from evidence, findings, connector diagnostics and
report values, replacing each withheld value with the `REDACTED` marker, `[REDACTED]`. Its
helpers do not depend on signature settings: disabling secret discovery never disables
redaction. Redaction recognizes credential formats and credential names; it is best-effort, so
treat scan output as sensitive (see the [threat model](../security/threat-model.md#residual-risks)).

## Entry points

- `sanitize(value)` returns a sanitized JSON-like copy, keeping nonsecret fields and types.
  Environment variable values are withheld whatever their name, argv pairs such as
  `["--token", "<value>"]` are recognized, and a credential found in one field is also removed
  from the other fields of the same object. `Finding` and `Evidence` call it on their reportable
  fields when they are created and again before every export.
- `sanitize_text(text)` redacts one string.
- `sanitize_excerpt(value, limit=200)` redacts the whole text before shortening it, because
  shortening first can cut a credential away from what identifies it. Text past the safety
  limits becomes `[REDACTED]`. `sanitize_text_excerpt` does the same for a provider record's
  text field, returns `None` for an absent one and raises `TypeError` for any other value that is
  not text, so the connector rejects the record as malformed and its coverage is incomplete.
- `credential_id(value)` returns a keyed pseudonym, `credential:hmac-sha256:<digest>`, that is
  stable only within the active key scope.
- `policy_token()` identifies the rules and limits in force. A finding's verified-clean digest
  is keyed by it, so a replaced rule is applied on the next pass.

## Passes

This module drives the passes in the `redaction_*` modules beside it, except
`redaction_entropy`, which neither `sanitize()` nor `sanitize_text()` runs. `redaction_rules`
holds the shared marker, sensitive names, limits and value tests.

| Module | Withholds |
|--------|-----------|
| `redaction_formats` | Credentials recognizable by format wherever they appear (prefixed provider tokens, JWTs, PEM private keys, authorization schemes), and a URL's userinfo, credential-bearing webhook path and sensitive query fields |
| `redaction_statements` | Complete assignment statements under sensitive names in source code, delimited with Python's tokenizer; nothing is evaluated |
| `redaction_assignments` | `name=value` and `name: value` pairs under sensitive names, mapping expressions and indented YAML blocks under sensitive keys, opaque literals given to names whose last word names a credential, and literal defaults of credentials read from the environment |
| `redaction_calls` | Values paired with a literal credential key in a call, credential literals passed to credential-named callees, and the password of a literal user/password pair |
| `redaction_commands` | Credential option values on command lines and in request headers, a login's `-p` value, passwords echoed into `--password-stdin`, and values set by `dotnet user-secrets set`, `aws configure set`, `ENV`, `setx` and `#define` |
| `redaction_markup` | Values named by XML elements, key/value attributes and name/value records |
| `redaction_entropy` | Random-looking quoted literals in evidence snippets, as a last resort; `Evidence` applies it to its `snippet` |

Patch and replace rules through `shadowscan.utils.redaction`, never through a `redaction_*`
module. A name set here is replaced in every module that binds it; a name set on one
`redaction_*` module changes only that module, and the other passes keep the object they
imported.

## Safety limits

`SanitizationLimitError`, a `ValueError`, is raised when a value exceeds the sanitizer's size,
nesting or work limits, and by `Finding.sanitize()` when redaction would rewrite the fields that
identify a finding. A finding that raises it is never published partially sanitized: the
engine omits it and records the error `finding omitted: sanitization safety limit exceeded`,
which marks the scan incomplete, so it exits 3. A finding that fails after merging, or after
scoring, is counted in an `engine.postprocess` error, with the same effect. Reporters let the error
propagate instead of writing a partly checked report (see [Reporters](reporters.md#sanitization)).

::: shadowscan.utils.redaction
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
