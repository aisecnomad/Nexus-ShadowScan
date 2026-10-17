# LLM triage

LLM triage is an **opt-in, advisory** second opinion. When enabled, the engine sends a compact
redacted summary of each selected finding to a configured language model and stores the reply
under `metadata.llm_triage`. The reply is purely advisory: it never changes a finding's kind,
confidence, risk, shadow status or the scan's completeness flag.

## Enabling triage

```yaml
options:
  llm_triage:
    enabled: true
    model: gpt-4o          # any model supported by the configured client
    budget_seconds: 60     # stop after this many seconds (default: 10% of scan timeout)
    min_risk: high         # only triage findings at this level or above
```

## What leaves the machine

For each triaged finding, ShadowScan sends: title, surface, kind, connector, resource type,
technology names, capabilities, tags, heuristic risk level, confidence, shadow status and up
to twelve evidence signals with their descriptions.

The following are **never sent**: resource IDs, owner names, accounts, file paths, code
snippets and credential-looking strings. Host, user, path and file names that appear in the
title or evidence descriptions are replaced with `[withheld]` before transmission.

## Bounded execution

One triage run is bounded in two ways:

- **Time**: stops at `budget_seconds`, or earlier if the scan deadline is near (the engine
  reserves at least 5 s for report writing).
- **Failures**: stops after three consecutive failed requests; findings not reached are
  recorded as skipped, not as errors.

A failed or malformed reply is recorded as a warning on the `engine.llm-triage` entry and
does not affect any finding.

::: shadowscan.triage
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
