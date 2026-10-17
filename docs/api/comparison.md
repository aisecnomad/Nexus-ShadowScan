# Comparison

The comparison module implements `shadowscan diff`: comparing a current scan against a baseline
to identify what changed. It is deliberately **conservative**: a finding disappearing from a
report is only evidence of resolution when the two scans are comparable.

## Collection-scope provenance

Before labelling any change as "resolved" or "new", the module checks that both scans covered
the same collection scope:

- **Same connectors** with the same configuration.
- **Same detection settings** (signature packs, min-confidence threshold).
- **Stable finding IDs** — a change in how a finding's identity is computed (e.g. a signature
  renaming a resource) makes IDs incomparable and marks the comparison incomplete.

Scope hashes identify inputs by content hash, not by name or timestamp. A file changing — even
silently, without a connector re-run — is what comparisons measure.

## Drift classes

Each detected change is labelled with a drift class and whether it is **adverse** (widens what
the agent can do, or weakens how it is governed):

| Class | Adverse? | Description |
|-------|----------|-------------|
| `new` | Yes | Finding appeared in the current scan but not the baseline |
| `resolved` | No | Finding present in baseline but absent in current (when scope is comparable) |
| `risk-escalated` | Yes | Same finding, higher risk level in current scan |
| `risk-reduced` | No | Same finding, lower risk level in current scan |
| `shadow-gained` | Yes | Finding became shadow (lost its registration) |
| `shadow-lost` | No | Finding moved from shadow to registered |
| `autonomy-widened` | Yes | Autonomy interval's ceiling rose or floor fell |

## Baseline pinning

A baseline can be pinned by the SHA-256 of its JSON report file, and can expire after a
configurable number of days. An expired or undatable baseline makes the comparison incomplete
rather than hiding the staleness.

::: shadowscan.comparison
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
