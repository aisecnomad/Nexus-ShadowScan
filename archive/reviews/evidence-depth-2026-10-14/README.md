# Bounded evidence implementation and validation — 2026-10-14

> **Author-written, AI-assisted offline evidence. Not an independent review and
> not measured precision.** The maintainer wrote this record with an AI
> assistant while implementing the change it describes (pull request #220). No
> second person verified it, and it is not live tenant acceptance. The
> regression comparison below runs on the author-written ShadowBench estate, so
> its figures describe that frozen corpus only: they do not estimate production
> precision, recall or complete estate coverage.

The change extends the existing connector contracts without creating a
parallel `scanners/` architecture or introducing runtime dependencies.

## What this record keeps

The full before/after reports were **not committed**. The original pull request
carried about 2.4 MB of generated output: `before/` and `after/` directories
(`metrics.json`, `runs.json`, `result.json`, the generated estate configuration,
the scanner `report.json` and the run's stdout/stderr) and a Git bundle of the
tested source. Their before and after scores were identical apart from
timestamps and durations. The integration carry kept only what this record
needs to be checked and reproduced:

- `provenance.json`: revisions, environment, corpus and freeze hashes, and the
  SHA-256 of every original artifact, including the omitted reports and bundle.
  A reproduction can be compared against those hashes.
- `validation.json` and `coverage-summary.json`: the author's local test,
  coverage and gate results for the tested source.
- `dependencies.txt`: the shared installed packages.
- `scanner-before.txt`, `scanner-after.txt`, `tools-before.json` and
  `tools-after.json`: the wrapper and tool-file snapshots the reproduction
  below uses. Their absolute paths are from the author's scratch workspace;
  replace them with your own.

Everything here describes the source tested on 2026-10-14, not the integrated
code. The integration carry changed several behaviours after review (see
[What the integration carry changed](#what-the-integration-carry-changed)), so
these results are history, not a description of the current scanner.

## Revisions

- Baseline scanner: `8fdd67b484d40dcc9ff35e8f10a1e3e6d864e477`.
- Candidate scanner source: `5de0867f9cc9ee06ff83d78cab8195ca0ea86174`.
- Published source: `84b57a4d7503a3f3fa9efc09194bf9f36217680a`. GitHub API
  publication changes commit metadata; its tree exactly matches the tested
  source tree `0f0f20a2eb5f23bc53e77f7cd70e236b43dc23c5`, so checking out the
  published commit reproduces the tested source without the omitted bundle.
- Shared scorer and adapter: `de05c5321bccbbf1a5f0ed75bfad05895fe5fdca`
  from PR #199, clean checkout for both runs. Its correction prevents absent or
  incomplete tool runs from earning true negatives. The candidate does not
  incorporate that PR's unrelated harness changes.
- Corpus and all 139 frozen artifact files: unchanged baseline checkout.

Only ShadowScan ran. Other tools emitted by the scorer are unscored and are not
comparative results. Both selected runs finished successfully and completely;
neither freeze check reported drift. Both scanners still report package version
0.1.2: the commit, not that version string, identifies the implemented source.
Gateway credential identifiers are scan-local, so raw report IDs are not a
cross-run identity comparison. The fixed harness scores the same entity anchors
and expected facts on both sides. Recorded durations are not a performance study.

## Regression comparison on the author-written ShadowBench estate (not production precision)

The frozen corpus contains 137 entities: 87 positives, 27 controls and 23 near
misses across nine surfaces. It has 104 expected surface/fact observations. The
scores below are the harness's arithmetic on that author-written corpus.

| Score on the author-written estate | Before | After |
|---|---:|---:|
| Entity true positives | 83 | 83 |
| Entity false positives | 8 | 8 |
| Entity false negatives | 4 | 4 |
| Entity true negatives | 42 | 42 |
| Entity precision on this corpus | 91.21% | 91.21% |
| Entity recall on this corpus | 95.40% | 95.40% |
| Entity F1 on this corpus | 93.26% | 93.26% |
| Fact TP / FP / FN | 99 / 9 / 5 | 99 / 9 / 5 |
| Fact F1 on this corpus | 93.40% | 93.40% |
| Scanner findings | 110 | 110 |
| Entity positives/negatives unscored | 0 / 0 | 0 / 0 |

The comparison shows no change on this unchanged corpus, and it is no evidence
of an accuracy gain. The new graph, lineage, lifecycle and JA4 metadata do not
add scoring weight. Optional live process inspection and model-header
inspection are off in this estate run; their behavior is exercised separately
by synthetic connector fixtures. New fixtures are not inserted into the frozen
labels to manufacture an improvement. The remaining eight false positives and
four false negatives are not claimed fixed by this implementation. No
450-fixture or commercial-ranking claim applies.

## Implemented scope

| Area | Implementation | Evidence and boundary |
|---|---|---|
| Low-code graphs (#205) | Shared `lowcode/graph.py`; n8n, Flowise and Dify adapters | Exact node identifiers, typed edges, bounded cycle-safe paths, disconnected/disabled/decoy controls. Declared paths do not prove execution or data exfiltration. |
| Lockfiles (#206) | `code/lockfiles.py` and filesystem integration | uv, Poetry, pnpm and Cargo inventory; dependency relationships only where provable. Peer/workspace ambiguity stays unknown. No package manager runs. |
| Cloud lineage (#207) | `cloud/aws_lineage.py` and AWS connector | Exported invocation/STS records, exact scoped session joins, compatible creation/expiration times and up to eight ancestry hops. Missing events remain unlinked; LookupEvents does not establish invocation-data-event coverage. |
| Lifecycle (#208) | `correlation.py` plus scan-window context | Non-scoring observation recency, coverage scope and limitations. No inactivity, ghost, zombie, canonical-agent or approval inference from absent telemetry. |
| Temporal DNS (#209) | `network/logs.py` | Same-client/context attribution within timestamp/TTL bounds, contradiction and truncation handling. No cross-client or future-answer attribution. |
| JA4 (#211) | Existing Zeek JSON/TSV log ingestion | Validated bounded fingerprint metadata only. No capture, external lookup or fingerprint-based agency score. |
| Runtime inspection (#212) | Existing `runtime/processes.py` | Opt-in maps, FD-link and allowlisted environment-key inspection with PID identity/race checks and budgets. No `/proc/*/mem`, target-FD open, environment values or root escalation. |
| Binary/model inspection (#213) | `code/model_artifacts.py` | Opt-in bounded GGUF, safetensors, ONNX envelope and PyInstaller tail/TOC inventory. No payload deserialization, execution, extraction or decompression. |
| MCP descriptions (#214) | `endpoint/runtime.py` using static instruction helper | Direct candidates carry rule/line metadata, no raw description excerpts. No JSON-RPC server launch or tool call. |
| SKILL.md (#215) | `code/skill_audit.py` and filesystem integration | Bounded static English instruction candidates, quotation/prohibition controls and explicit incomplete analysis. Heuristics cannot certify arbitrary instructions as safe. |

Connector guides, the generated reference, trust-boundary documentation and
production migration notes accompany the source. No exporter is reimplemented:
the existing CycloneDX and SARIF exporters remain in place. Opt-in live forward
DNS (#210), canonical entities, live MCP probing and packet capture are outside
this implementation.

## What the integration carry changed

Review of #220 found regressions against the baseline, and the integration
carry fixed them before merging. The comparison above predates these fixes,
and the bundled evaluation corpora give the same predictions with them. The
carried code:

- keeps the baseline MCP tool-poisoning rules and adds the description audit
  as additional, zero-weight signal;
- reports a lockfile it cannot inventory against that lockfile with a fixed
  reason, and marks the scan incomplete only when no manifest beside it
  declares the dependencies;
- still classifies a live process whose command line exceeds 64 KiB, from its
  leading complete arguments;
- groups flows per connection with bounded time buckets, and withholds flow
  attribution only for the client an incomplete record names;
- keeps the n8n connector's and the export reader's baseline AI-node
  inventory, and keeps a workflow finding when its graph is malformed;
- bounds CloudTrail lineage as partial metadata without marking the scan
  incomplete, and states that live collection never links lineage;
- prunes lifecycle observation links to findings the report omits.

`docs/production.md` describes the carried behaviour and its rollout impact.

## Additional observed behavior

These observations are from the tested source on the 8fdd67b baseline. The
separate bundled README demo changed from 133 to 132 findings, with 129 to 128
shadow findings and 63 to 62 high-risk findings. Its fixtures are unchanged.
The removed `.60` client finding previously borrowed the `.33` client's ChatGPT
DNS answer after expiry. Cursor's confidence changes from 0.8 to 0.5 because its
flow is 26 seconds beyond the DNS TTL and has no linked TLS SNI; DNS-only evidence
remains. The `.33` client retains its fresh flow and loses its expired flow.
Existing and new temporal regression tests cover these cases.

Cross-review during implementation also found and fixed pnpm peer-version
unions, unsupported lockfile versions, n8n attachment/order confusion, graph
budgets before projection, contradictory DNS/JA4 records, mixed-sensor cadence,
inconsistent STS/IAM role names, and runtime inspection denial/budget cases
that suppressed independently readable command-line detections. Actual PID
changes still suppress attribution.

## Reproduction

The omitted reports can be regenerated. Create separate clean checkouts of the
baseline (`8fdd67b`), the published candidate (`84b57a4d`, whose tree equals the
tested source) and the harness (`de05c53`). Install the repository's locked
dependencies into one environment used for both scanner runs and the harness.
The retained wrappers show how to prepend the selected scanner checkout to
`sys.path` before invoking `shadowscan.cli.main`; replace their absolute paths
with your own. Create matching tool files containing
`{"tools":{"shadowscan":{"bin":"/absolute/path/to/wrapper"}}}`.

From the harness checkout, run each scanner with the same baseline corpus,
estate and freeze (substitute `before` and `after` and the associated tool file):

```bash
python -m tools.shadowbench estate run \
  --corpus /absolute/baseline/benchmarks/shadowbench/estate/corpus.json \
  --estate /absolute/baseline/benchmarks/shadowbench/estate/artifacts \
  --freeze /absolute/baseline/benchmarks/shadowbench/estate/FREEZE.json \
  --tools /absolute/tools-before.json --out /absolute/before \
  --workers 1 --timeout 180 --only shadowscan
python -m tools.shadowbench estate score \
  --corpus /absolute/baseline/benchmarks/shadowbench/estate/corpus.json \
  --estate /absolute/baseline/benchmarks/shadowbench/estate/artifacts \
  --freeze /absolute/baseline/benchmarks/shadowbench/estate/FREEZE.json \
  --runs /absolute/before/runs.json --out /absolute/before/metrics.json
```

Compare the regenerated `metrics.json` scores with the table above. Timestamps,
durations and scan-local identifiers differ between runs, so the artifact
hashes in `provenance.json` match only byte-identical output.

Runs did not enable network access or live tenant collection. Focused harness
verification passed 165 tests; two separate `--as-user nobody` tests could not
run successfully because this container maps only UID/GID 0 and rejects chown
to `nobody` with EINVAL. Neither benchmark run uses `--as-user`.

## Validation

These are the author's local results for the tested source. Validation used
Python 3.12 with all pinned cloud SDKs in that environment. Lint, formatting,
mypy, signature and mapping validation, repository policy, all nine evaluation
corpora, secret checks, dependency audit (environment and all four lockfiles),
`pip check`, and strict MkDocs build passed. The connector reference was
regenerated and the CLI connector listing verified.

- Full run with eight workers and coverage: **17,568 passed, 8 skipped,
  3 expected failures, 1 failure**. The sole failure was the unchanged CSV
  `test_neutralising_a_long_whitespace_run_is_linear` wall-clock guard: one
  CRLF input took 1.43 seconds against its one-second limit. Its implementation
  and limit were not changed. CPU contention is a possible explanation, not a
  demonstrated product defect or an excuse to omit the failed result.
- The entire CSV injection module then passed **40/40 tests**, both untraced
  and in an isolated run with the same coverage instrumentation. Coverage from
  the isolated run was appended; no test was disabled or marked xfail.
- Combined line/branch coverage: **94.29%**. The per-connector gate passed all
  **80 nonempty modules**; the lowest was `cloud/kubernetes.py` at **76.29%**.
- An earlier full run on the same source, before installing optional cloud SDKs,
  passed **17,458 tests** with 108 skips and 3 expected failures. Installing the
  locked SDKs enabled the cloud tests and resolved the OCI coverage shortfall.

`validation.json` and `coverage-summary.json` preserve these results. This is
not an unqualified clean full-profile suite claim; the hosted CI full-suite run
must confirm the timing-sensitive case in its supported environment.

The hosted Python matrix, wheel/container checks, live deployment canaries and
independent human review are separate gates. These author-written synthetic
fixtures do not establish production precision or complete estate coverage.
