# Correlation

Lifecycle correlation preserves configured/installed/running **observations** for
the same tool on an exactly matching device. These are not canonical agent
identities. Neither a shared tool signature nor a PID identifies a persistent
agent across devices, restarts or PID reuse.

`metadata.lifecycle_observation` supplies a non-scoring assessment for endpoint
and process findings, including findings with no runtime counterpart. The engine
passes the scan's actual start/end observation window and runtime collection
status (`not-collected`, `export-only`, `collected` or `incomplete`). Explicit
process observation times distinguish `observed-in-window`, `historical`, and
`unknown`; missing or future times never establish current execution. Embedding
callers may pass `observation_window` and `runtime_coverage` to
`correlate_lifecycle`; without a valid window, recency remains unknown. Replaying
the same observations and window is deterministic.
Collection status describes connector runs, not visibility into every device
or continuous coverage of that window. Process creation timestamps do not
substitute for an explicit observation time. Samples are capped at 50, with a
truncation flag and full count; recency considers all available observations.
When the confidence threshold or an output cap omits a process finding, the
engine clears its `finding_id` from the samples in
`metadata.lifecycle_observation` (and the copy in
`metadata.lifecycle.observation`) and drops it from
`metadata.lifecycle.related`, as it prunes `metadata.related`; the sample's
`observed_at` stays because the recorded observation established it.

An old process export may retain the legacy `observed-running` tag and the
historically observed `running` state, but its assessment reads `historical`.
The tag is not a current-execution claim. Existing explicit risk policies that
weight this tag retain their behavior; the assessment adds no evidence weight,
confidence or risk score. Snapshot coverage is not continuous surveillance:
even a successfully collected empty inventory does not prove inactivity.
Unknown or incomplete coverage never produces `ZOMBIE`, `GHOST`, or sanction
status. Governance approval remains separate from activity and source provenance.

::: shadowscan.correlation
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
