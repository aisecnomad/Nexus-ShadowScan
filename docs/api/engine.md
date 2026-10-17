# Engine

The engine is the scan orchestrator. `Engine` takes a [`ScanConfig`](config.md), runs the
selected connectors concurrently, then post-processes their findings. `Engine.run` returns a
[`ScanResult`](models.md) holding the findings, a `ScanStats` entry for each connector and for
engine stages (`engine.*` entries such as `engine.inventory` or `engine.llm-triage`), and the
collection scope that `diff` compares.

```python
from shadowscan.config import ScanConfig
from shadowscan.engine import Engine

config = ScanConfig.from_yaml("shadowscan.yaml")
result = Engine(config).run()
print(len(result.findings), "findings; complete:", result.complete)
```

## Execution model

Connectors run on a pool of `options.parallel` worker threads (default 4). An approved
third-party plugin runs in its own worker process unless `options.plugin_execution` is
`thread`. Each job looks up its connector class once, on its worker; a failed lookup, such as
an unknown connector name, is recorded as an error on that connector while the others still
run. `run(only=[...])` narrows the scan to connector names or labels; a selector that matches
no enabled connector stops the run before collection with an incomplete result.

Each connector has a completion deadline, `options.connector_timeout_seconds` (default 120 s),
that starts when its worker begins. While the default is in effect, a connector with a large
input may raise its own deadline, to at most 1800 s. On expiry a connector on a worker thread
is cancelled cooperatively: the findings it had already produced are kept (in an incremental
scan split by repository, only those of the repository in progress), its late result is
discarded and its entry is marked incomplete. A plugin worker process is terminated instead,
and its results are discarded. The id of a connector whose worker thread is still running, for
example blocked in an SDK call, is listed in `Engine.abandoned_workers`.
`options.job_deadline_seconds` is the CLI's process deadline, not an engine one: the expiry
the CLI passes as `run(job_deadline=...)` only ends LLM triage early enough to write the
report, and does not bound collection.

A connector error, timeout or limit makes `result.complete` false, which the CLI reports as
exit 3.

## Post-collection pipeline

After collection, the engine applies these stages in order:

1. **Merge**: findings with the same id (one object observed twice by a connector) are merged.
   Lists such as evidence, frameworks, capabilities and tags are unioned, the first
   observation takes precedence for owner and metadata, and the earliest `first_seen` and
   latest `last_seen` survive.
2. **Correlation**: findings from different connectors or surfaces whose identifiers are equal
   in a verified shared scope are linked (`metadata.related`); similar names, and equal
   identifiers whose shared scope cannot be verified, only become review candidates
   (`metadata.related_candidates`).
3. **Runtime correlation**: code findings with frameworks get `metadata.runtime_activity`,
   which counts gateway telemetry only through operator-configured caller and scope bindings;
   without one its status is `unknown`.
4. **Lifecycle correlation**: endpoint findings are linked to running-process findings for the
   same tool on the same device (`metadata.lifecycle`); `metadata.lifecycle_observation`
   describes the recency of that observation within the scan window.
5. **MCP registry matching**: MCP server findings are matched against the snapshots pinned in
   `options.mcp_registries` (`metadata.mcp_registry`).
6. **Registry reconciliation**: vendor registry records are compared with the observed findings
   (`metadata.registry_reconciliation`).
7. **Inventory, autonomy, governance and risk**: each finding is matched against the sanctioned
   inventory (inventory files and the approved records of `options.trusted_registries`):
   `shadow` is true when no entry approves it and null when there is no inventory. It then gets
   its `metadata.autonomy` interval when its kind has one, a `metadata.declared_governance`
   block when the Capability Card that approved it declares governance facts, and its risk
   score.
8. **Filter and order**: findings below `options.min_confidence` are dropped (vendor registry
   records are kept) and the rest are sorted by risk score.
9. **LLM triage**: only when `options.llm_triage.enabled` is true; see [LLM triage](triage.md).

A finding that exceeds the sanitization safety limit is omitted and recorded as an error, on
its connector during collection or on the `engine.postprocess` entry after merging or
scoring; either way the scan is incomplete.

## Identity key

Gateway caller, scope and source pseudonyms and credential pseudonyms are keyed with a random
key for each scan, so findings whose IDs derive from them (`metadata.identity_scope: run`)
cannot be matched across reports. Set `SHADOWSCAN_IDENTITY_KEY` to at least 32 secret bytes,
encoded as `hex:<value>` or `base64:<value>`, to use one stable key instead
(`identity_scope: keyed`). The key is read only from the environment, never from the
configuration, and never reaches a log, report, cache or record export. A set value that is
ambiguous, cannot be decoded or decodes to fewer than 32 bytes stops the scan with a
`SetupError` (CLI exit 1).

::: shadowscan.engine
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
