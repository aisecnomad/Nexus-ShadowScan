# Bounded evidence implementation and validation — 2026-10-14

This is an implementation record and AI-assisted review, not independent human
signoff or live tenant acceptance. The change extends the existing connector
contracts without creating a parallel `scanners/` architecture or introducing
runtime dependencies.

## Revisions and artifacts

- Baseline scanner: `8fdd67b484d40dcc9ff35e8f10a1e3e6d864e477`.
- Candidate scanner source: `5de0867f9cc9ee06ff83d78cab8195ca0ea86174`.
- Published source: `84b57a4d7503a3f3fa9efc09194bf9f36217680a`. GitHub API
  publication changes commit metadata; its tree exactly matches the tested
  source tree `0f0f20a2eb5f23bc53e77f7cd70e236b43dc23c5`. The original two local
  implementation commits are retained in `source-tested.bundle` (requires the
  baseline commit), preserving the precise tested revision and sign-offs.
- Shared scorer and adapter: `de05c5321bccbbf1a5f0ed75bfad05895fe5fdca`
  from PR #199, clean checkout for both runs. Its correction prevents absent or
  incomplete tool runs from earning true negatives. The candidate does not
  incorporate that PR's unrelated harness changes.
- Corpus and all 139 frozen artifact files: unchanged baseline checkout.
- `before/` and `after/` contain the original `metrics.json`, `runs.json`,
  generated configuration, normalized results, stdout/stderr, and scanner report.
  Stderr is losslessly gzip-compressed to preserve the CLI's trailing whitespace;
  use `gzip -dc 0.stderr.txt.gz` to inspect its original bytes.
- `provenance.json` records revisions, environment, corpus/freeze hashes and
  artifact hashes; `dependencies.txt` records the shared installed packages.
  Wrapper snapshots and tool configurations are retained alongside them.

Only ShadowScan ran. Other tools emitted by the scorer are unscored and are not
comparative results. Both selected runs finished successfully and completely;
neither freeze check reported drift. Both scanners still report package version
0.1.2: the commit, not that version string, identifies the implemented source.
Gateway credential identifiers are scan-local, so raw report IDs are not a
cross-run identity comparison. The fixed harness scores the same entity anchors
and expected facts on both sides. Recorded durations are not a performance study.

## Measured regression result

The frozen corpus contains 137 entities: 87 positives, 27 controls and 23 near
misses across nine surfaces. It has 104 expected surface/fact observations.

| Metric | Before | After |
|---|---:|---:|
| Entity true positives | 83 | 83 |
| Entity false positives | 8 | 8 |
| Entity false negatives | 4 | 4 |
| Entity true negatives | 42 | 42 |
| Entity precision | 91.21% | 91.21% |
| Entity recall | 95.40% | 95.40% |
| Entity F1 | 93.26% | 93.26% |
| Fact TP / FP / FN | 99 / 9 / 5 | 99 / 9 / 5 |
| Fact F1 | 93.40% | 93.40% |
| Scanner findings | 110 | 110 |
| Entity positives/negatives unscored | 0 / 0 | 0 / 0 |

There is no measured accuracy gain on this unchanged corpus. The new graph,
lineage, lifecycle and JA4 metadata do not add scoring weight. Optional live
process inspection and model-header inspection are off in this estate run;
their behavior is exercised separately by synthetic connector fixtures. New
fixtures are not inserted into the frozen labels to manufacture an improvement.
The remaining eight false positives and four false negatives are not claimed
fixed by this implementation. No 450-fixture or commercial-ranking claim applies.

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
| MCP descriptions (#214) | `endpoint/runtime.py` using static instruction helper | Ordinary URLs/tool references no longer imply poisoning. Direct candidates carry rule/line metadata, no raw description excerpts. No JSON-RPC server launch or tool call. |
| SKILL.md (#215) | `code/skill_audit.py` and filesystem integration | Bounded static English instruction candidates, quotation/prohibition controls and explicit incomplete analysis. Heuristics cannot certify arbitrary instructions as safe. |

Connector guides, the generated reference, trust-boundary documentation,
production migration notes and changelog accompany the source. No exporter is
reimplemented: the existing CycloneDX and SARIF exporters remain in place.
Opt-in live forward DNS (#210), canonical entities, live MCP probing and packet
capture are outside this implementation.

## Additional observed behavior

The separate bundled README demo changes from 133 to 132 findings, with 129 to
128 shadow findings and 63 to 62 high-risk findings. Its fixtures are unchanged.
The removed `.60` client finding previously borrowed the `.33` client's ChatGPT
DNS answer after expiry. Cursor's confidence changes from 0.8 to 0.5 because its
flow is 26 seconds beyond the DNS TTL and has no linked TLS SNI; DNS-only evidence
remains. The `.33` client retains its fresh flow and loses its expired flow.
Existing and new temporal regression tests cover these cases.

Cross-review also found and fixed pnpm peer-version unions, unsupported lockfile
versions, n8n attachment/order confusion, graph budgets before projection,
contradictory DNS/JA4 records, mixed-sensor cadence, inconsistent STS/IAM role
names, and runtime inspection denial/budget cases that suppressed independently
readable command-line detections. Actual PID changes still suppress attribution.

## Reproduction

Create separate clean checkouts of baseline, candidate and harness. The published
source has the identical candidate tree. Alternatively, after fetching the
baseline, restore the original candidate with
`git fetch /absolute/source-tested.bundle tested-evidence-source`.
Install the
repository's locked dependencies into one environment used for both scanner
runs and the harness. The retained wrappers show how to prepend the selected
scanner checkout to `sys.path` before invoking `shadowscan.cli.main`; replace
their absolute paths with your own. Create matching tool files containing
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

Runs did not enable network access or live tenant collection. Focused harness
verification passed 165 tests; two separate `--as-user nobody` tests could not
run successfully because this container maps only UID/GID 0 and rejects chown
to `nobody` with EINVAL. Neither measured benchmark run uses `--as-user`.

## Validation

Validation uses Python 3.12 with all pinned cloud SDKs in this environment. Lint, formatting, mypy,
signature and mapping validation, repository policy, all nine evaluation
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
