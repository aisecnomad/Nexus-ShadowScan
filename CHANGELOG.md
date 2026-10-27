# Changelog

One summary per release. Detailed implementation history is maintained in the
[engineering log](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/engineering-log.md);
[release notes](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/RELEASE_NOTES.md)
explain operator migrations. Earlier per-change entries are preserved in the
[change-history archive](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/history/changelog-detail.md).

## Unreleased

- Dependabot #323, #324 and #325 are carried with regenerated hash locks.
  setuptools 84.2.1 replaces 84.0.0 as the build backend and in the CI lock
  (GHSA-xmj3-9gf7-h52w made `pip-audit` fail on `main`), ruff 0.17.2 moves
  with its pre-commit hook, seven other reviewed CI pins and the docs lock's
  platformdirs follow, and the workflows move to setup-python 7.1.0, CodeQL
  Action 4.39.1 and gh-action-pypi-publish 1.14.3. The worker image moves to
  the `wolfi-base` index that ships brotli 1.2.1-r1; the previous index's
  libbrotli 1.2.0-r6 failed the container scan. Both image stages now run
  `apk upgrade --available`: the base image pins its packages in
  `/etc/apk/world`, so a plain upgrade held them at the vulnerable versions.
  virtualenv 21.14.13 (from #324) also fixes GHSA-cx6f-vjhg-g3cc in the CI
  lock, which Scorecard reports and #326 proposed alone.
  The CI lock is resolved with uv 0.13.4: 0.11.32 vendors a CA bundle that
  trusts the compromised emSign ECC root (GHSA-hq85-5cpj-mr62).

- The 0.1.4 publication is recorded (tag `v0.1.4` on `94fda063`, the PyPI
  upload and the GitHub release of 2026-10-23).

- The five precision findings of the #320 head review are carried: the
  `gateway.logs` reason coverage is scoped to its provider-error,
  pagination and envelope-shape diagnostics, the wheel-digest guidance
  names the build-process umask, the deviation record names #318 and #319
  as the merged pull requests, the 0.1.3 redaction gap is scoped to keys
  the redaction does not withhold, and the v0.1.3 deviation note is marked
  as the maintainer's own record.

- The 0.1.4 release's review and its deviations from the publishing runbook
  and `AGENTS.md` are recorded; the 0.1.4 release notes, changelog summary
  and rollout guide are corrected against 0.1.3, and the publishing
  runbook's step 6 names the production run's artifact and rebuilds the
  wheel from an archive of the tag under `umask 022`, with the tag's own
  build-backend lock.

## 0.1.4 — 2026-10-23

- The 0.1.3 publication is recorded (tag `v0.1.3` on `aee3c984`, the PyPI
  upload and the GitHub release of 2026-10-22), the publishing runbook
  explains PyPI's change-of-provenance warning on 0.1.3 and how a later
  rename avoids one, and a test tolerates a child process that exits between
  its liveness check and the cleanup kill.

- Offline inputs are counted under explicit incomplete reasons: the shared
  offline readers, directory walk and export loader, the export writer and
  the provider-error, pagination and envelope-shape diagnostics of
  `gateway.logs`' own JSON exports name each diagnostic's category
  (corrupt, undecodable, malformed or empty input `unparsed-input`,
  captured provider errors `upstream-error`, uncollected pages and missing,
  vanished, unsupported or special files `unscanned-input`, refused links
  `unresolved-link`, permission errors `access-denied`, files over the
  per-file cap `oversize-file`, other limits `analysis-limit`) where 0.1.3
  classified their text, counting many as `other`, some as
  `unresolved-link`, `oversize-file` or `unscanned-input`, and most of
  those from `network.logs` as `upstream-error`. Whether a scan is
  incomplete, and its exit code, are unchanged; `ConnectorError` takes an
  optional `reason`, and a repository ratchet keeps reason-less diagnostic
  sites from growing.

- Google AI services reached through Private Service Connect
  (`aiplatform-ENDPOINT.p.googleapis.com`, optionally led by a location such
  as `us-central1-`) or a regional service endpoint
  (`aiplatform.REGION.rep.googleapis.com`) are AI destinations wherever
  signature hosts are matched, including network and gateway logs and code
  and low-code scans; the eBPF host rule and the MCP tool-description check
  (`tool-poisoning`), which already recognized the global Private Service
  Connect form, recognize the location-led and regional forms too.

- When a connector's deadline expires, its partial report keeps a finding
  whose metadata holds a scalar subclass (an `IntEnum`, a numpy `float64`,
  a pandas `Timestamp` or `NaT`), which 0.1.3 omitted. The sanitize pass
  stores such a value as its standard type, or as its text when it cannot
  be rebuilt exactly, and that text is redacted, where 0.1.3 wrote a
  `date`, `datetime`, `time`, `timedelta`, `Decimal` or `UUID` subclass to
  the JSON report through its own `__str__`, unredacted, under keys the
  redaction does not withhold (a value under a sensitive key or in `env`
  was withheld in 0.1.3 too).

## 0.1.3 — 2026-10-22

- The README, which is the PyPI description, reads correctly on the frozen
  release page: it names no planned date or latest version, states the Python
  and platform requirements, loads its images from a pinned commit, and opens
  with install, a first scan and the offline demo's output. Several claims were
  corrected, and the package summary, keywords and classifiers were tightened.

- A blocked container scan names each blocking vulnerability (package, installed and
  fixed version) as a check annotation, so the pull request page shows why without the job log.

- Repository hygiene: workflows run on a pinned `ubuntu-24.04` image, and
  configuration left behind for benchmark paths that moved to the Nexus
  ShadowBench companion is removed.

- The `benchmark-suite` companion pin moves to Nexus-ShadowBench `1ce0eee`
  (documentation, an amendment ledger, a hardened code-surface fetch, certifi
  2026.10.19 and a CI dependency audit); no benchmark evidence changed.

- Prose and comments that name a credential-typed call without closing it
  (`ClientSession(` in Markdown) no longer fail a scan closed: such a call is
  read to its end within a per-text work budget, and the text from it to the
  end of the file is withheld from excerpts, so the text before it keeps its
  excerpts; the credential-call lexer crosses inert text in runs, 1.66x
  faster with identical output.

- Local scans start faster: built-in signature patterns compile on first use,
  outside each input's matching budget (credential patterns in the linear form
  the matcher runs), and `import shadowscan.cli` no longer loads `requests`,
  `urllib3` or `ssl` for a local `shadowscan code` run.

- A Python consumer whose unrelated imports lie past the dispatch inventory
  is no longer incomplete: a dispatcher's verdict is resolved only for the
  module a selected tool call reaches. Only consumers that import a model
  provider's SDK (any of the 38 `category: provider` signatures) are queued
  for nested dispatch, not those importing `platform.litellm` alone, so
  litellm's own tree no longer fills the 16 MiB queue.

- JSON is decided by its structure, not its bytes: a data file with a
  repeated key (a provider catalog, an editor grammar) is one budgeted gap
  when no reading of the key holds an MCP server table, a JSON Schema
  that describes an `mcp_servers` field is not a server table, and an
  oversize JSON file of up to 4 MiB is parsed to decide whether it is
  blinding. A file without a repeated key is parsed once, text that opens
  more than 100,000 containers stays undecided, and manifests, lockfiles
  and agent configuration still fail closed.

- Fewer false exit 3s from unparsed input: a Continue `uses:` block reference
  is an MCP server finding, an empty manifest or MCP configuration is a note,
  and unrendered template source (a file other than Python source under a
  `{{cookiecutter...}}` directory, or one that parses once its Jinja
  placeholders are filled in) is
  one partial gap charged to the coverage budget instead of failing the scan.

- Notebooks complete more often: more IPython syntax is read as IPython runs
  it (`% pip install`, `files = !ls`, backslash-continued magics, graph-query
  cell magics), notebooks made large by saved images are read for credentials
  without their base64 output data, a notebook in which only some tutorial
  cells do not parse is one budgeted gap, and repeated model-identifier
  literals count once toward the per-file bound.

- Large real modules are analyzed in full: the Python syntax-tree bound rises
  from 50,000 to 200,000 nodes (`max_ast_nodes`), bound source calls from 512
  to 2,048 and tool-loop flow steps to 800,000. Excerpt redaction runs under
  an allowance of its own, so a file whose detection finished in its budget
  no longer times out redacting its excerpts, and skill files are audited up
  to 512 KiB.

- The automatic `code.filesystem` deadline also scales with the bytes the
  scan will analyse (one default per 12 MB of source, per 240 MB of other
  read data such as supported lockfiles), not only with the entry count, and
  the walk stops early enough to leave time for binding and finding emission.
  Set an explicit deadline for untrusted repositories.

- An in-tree symbolic link that stands for agent configuration
  (`.agents/skills -> ../.claude/skills`, a lowercase `agents.md` linked to a
  README) is read at its link path instead of failing the scan: the link is
  never followed; its target is opened by its real path below the root and
  reported under the link path. A link the walk does not follow is described
  by what its target was found to be. Links out of the tree, to excluded
  targets, inside their own target, or naming a file but pointing at a
  directory still fail closed. A file read at its link path is judged by the
  link's own name, and a credential in it is reported at both paths.

- Release-evidence attachment now finds the maintainer's draft release, which
  `releases/tags/{tag}` never returns; the TestPyPI smoke test runs outside the
  checkout so it exercises the installed wheel.

- Preserve notebook import binding when a multiline string contains magic-like
  command text; keep string-span protection isolated to each code cell, and do
  not let quotes in shell or magic lines open Python strings.

certifi 2026.10.19 removes the `emSign ECC Root CA - G3` root, whose revoked
intermediates had compromised keys (GHSA-6q48-6c7w-9gw2), from every lock.
The worker image starts from the 2026-10-20 `chainguard/wolfi-base` digest, whose
`ca-certificates-bundle` 20260909-r3 fixes CVE-2026-111943; the previous digest's
r2 failed the container vulnerability gate on every pull request.

The weekly discovery-benchmark gate compares against the companion results
directory its workflow names (`BASELINE_RUN`, currently `2026-10-09`), so a
later results directory can no longer become the baseline by sorting last.

Expired connectors share one five-second allowance for preparing partial findings,
so repeated overruns cannot each delay the report for another five seconds.
Native eBPF sensor names no longer imply an AI destination; wrapped Hubble
destination enrichment and service-specific Google AI Private Service Connect
names are retained.

Host inventory preserves Jan and LM Studio Windows install-directory context
and no longer treats relative home-like or traversal paths as home model stores.

Malformed GCP list responses, pagination limits, invalid Okta grants and conflicting
Entra permission labels now record explicit incomplete categories, independent of
resource names or diagnostic wording.

The optional live DNS snapshot enhancement now has a scoped design and
acceptance plan; an explicit regression guards the offline network boundary.
Live DNS collection and snapshot replay remain unimplemented (#210).

Current source adds bounded staged-file hooks, readiness and remediation guidance,
offline terminal triage, a candidate public API contract, a pinned benchmark
companion and verified release attachments. Signature loading uses faster native
event parsing when available while retaining bounded Python construction.
Other changes include evidence-based app attribution and executable-tool provenance,
structural workload inventory, per-root coverage budgets and clearer incomplete
scan diagnostics, bounded credential handling, refreshed dependency locks,
reproducible benchmark tooling and repository hygiene. These changes are not
published or tagged; install a reviewed commit. Detection was tuned using the
2026-10-11 ShadowBench estate errors, including Wudpecker and Tactiq name/domain
rules (benchmark-derived), so later runs on that estate are in-sample.

Correlation group disclosures now stay within verified scope partitions and
reflect only retained findings. YAML integrity defects preserve generic image
inventory while keeping scans incomplete, and ordinary reference URLs alone no
longer flag MCP tool poisoning. Dispatch proof caching remains bounded and
respects import shadowing; scan summaries share incomplete-reason aggregation.
A diff-scoped scan under Git older than 2.45 names that requirement instead of
asking whether the ref is valid, the example Falco rules emit the namespace,
pod and process name the eBPF reader needs, and the release and migration notes cover the
attribution, correlation-group and dependency-floor changes.
The sample Dockerfile uses a digest-pinned Node 22 image and an integrity-locked
CLI dependency graph, with package lifecycle scripts disabled.
Report readers
accept a newer scanner's slug-shaped coverage-gap reason instead of refusing
the report; forged values stay refused and the write path stays strict.
Automatic filesystem deadlines can reach the existing 30-minute ceiling;
media recognition, notebook automagic handling and tool-cache exclusions reduce
avoidable gaps while retaining coverage accounting and analysis limits.
Credential matching avoids repeated work inside long failed identifiers while
preserving long valid assignments and existing quotas.

## 0.1.2 — 2026-10-08

Correct the production publication gate to query the fully qualified release tag
and verify it resolves to the reviewed commit. Preserve immutable prior tags and
TestPyPI rehearsal evidence.

## 0.1.1 — 2026-10-08

Initial release preparation: nine-surface AI discovery, inventory reconciliation,
security-sensitive output handling, CI gates and Trusted Publishing. See the
archived change history for individual hardening changes and known limits.
