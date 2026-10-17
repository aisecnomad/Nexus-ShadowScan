# LLM triage

LLM triage is an **opt-in, advisory** second opinion. When `options.llm_triage.enabled` is
true, the engine sends a compact, redacted summary of each selected finding to the configured
model, one request per finding, and stores the reply under `metadata.llm_triage`. The reply
never changes a finding's kind, confidence, risk, shadow status or the scan's completeness.
The [LLM triage guide](../operations/llm-triage.md) covers operation in more detail.

## Enabling triage

```yaml
options:
  llm_triage:
    enabled: true
    provider: anthropic        # or openai
    model: <model-id>          # required when enabled; there is no default
    api_key_env: ANTHROPIC_API_KEY  # the default for anthropic; a key in the file is refused
    min_level: medium          # lowest risk level triaged (default medium)
    max_findings: 25           # 1 to 500, highest score first (default 25)
    timeout_seconds: 30        # HTTP client timeout, 1 to 300 (default 30)
    budget_seconds: 300        # whole run, 1 to 3600 (default 300)
```

## What leaves the machine

For each triaged finding, ShadowScan sends its title, surface, kind, connector, resource type,
technology and model-provider names, capabilities, tags, heuristic risk level, confidence,
shadow status and up to twelve evidence signals with their descriptions.

Resource IDs, owners, accounts, regions, evidence locations and code snippets are not sent as
fields. Their values, and the host, user, path and file names a connector records, are
replaced by `[withheld]` wherever they appear in the title or an evidence description (a value
of one or two characters only where it stands as a whole word). A pattern pass then withholds
the e-mail and IP addresses it recognizes in that text; it is a backstop, not a guarantee.
Every value has already passed the report sanitizer. Other free text can still name a
product, repository or app.

## Bounded execution

One triage run is bounded in two ways:

- **Time**: requests stop once `budget_seconds` have passed. Under a job deadline (in a CLI
  scan, `--job-deadline-seconds` or `options.job_deadline_seconds`; in a library scan, the
  `job_deadline` passed to `Engine.run`) the engine ends triage earlier, so that the report can
  still be written: 10% of `job_deadline_seconds` before the deadline, at least 5 s and at most
  60 s. When that point has already passed, triage is skipped.
- **Failures**: a run stops after three consecutive failed requests.

Selected findings that a run does not reach get `metadata.llm_triage.status: skipped`. A failed
request or a reply outside the verdict contract gives the finding `status: failed` or
`status: unparseable`. These outcomes are counted in warnings on the `engine.llm-triage`
entry, as is a configuration problem such as an unset API key variable; triage never marks the
scan incomplete.

::: shadowscan.triage
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
