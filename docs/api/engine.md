# Engine

The engine is the scan orchestrator. It receives a [`ScanConfig`](config.md), resolves and
instantiates the requested connectors, runs them concurrently in a thread pool, then drives
the post-collection pipeline: merging duplicate findings, lifecycle and runtime correlation,
registry reconciliation, autonomy classification, declared governance, risk scoring and LLM
triage. The final [`ScanResult`](models.md) holds all findings and the `ScanStats` that
describe coverage and completeness.

## Execution model

Each connector runs in its own thread. The engine tracks a per-job deadline and a scan-wide
wall-clock deadline (`options.timeout`); a connector that exceeds either is cancelled
cooperatively and its partial results are discarded, leaving the scan marked `incomplete` with
exit code 3.

Connector classes are resolved once before any thread is started. A class-lookup failure
(unknown connector name, missing plugin) is recorded as an error and excluded from execution;
all other connectors still run.

## Post-collection pipeline

After all connector threads finish, the engine applies the following stages in order:

1. **Deduplication** — findings with the same identity seen by the same connector in the same
   run are merged (evidence and technologies union; earliest `first_seen` / latest `last_seen`
   survive).
2. **Lifecycle correlation** — endpoint and process findings get a `metadata.lifecycle_observation`
   assessment based on process timestamps and the scan's observation window.
3. **Runtime correlation** — runtime findings are linked to endpoint findings for the same tool on
   the same device.
4. **Registry reconciliation** — every finding is compared against the sanctioned inventory;
   unregistered findings are marked shadow.
5. **MCP enrichment** — MCP server findings are enriched with provenance from approved registry
   snapshots.
6. **Autonomy classification** — each finding receives a `metadata.autonomy` interval on the
   L0–L5 scale.
7. **Declared governance** — findings matched to a Capability Card carry the card's governance
   block.
8. **Risk scoring** — each finding gets an explainable risk score and a level (critical / high /
   medium / low).
9. **LLM triage** — when `options.llm_triage.enabled` is true, the engine sends a compact
   redacted summary of the highest-risk findings to the configured model and stores the reply
   as advisory metadata.

## Identity key

By default, finding IDs and gateway pseudonyms use a random key per scan, so IDs are not
comparable across runs. Set `SHADOWSCAN_IDENTITY_KEY` to a stable secret (at least 32 bytes,
encoded as `hex:<value>` or `base64:<value>`) to make IDs stable and linkable across scans.
The key never appears in any report, cache entry or diagnostic output.

::: shadowscan.engine
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
