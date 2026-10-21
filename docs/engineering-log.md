---
title: Engineering log
---

# Engineering log

The detailed record of every change, one dated entry per change, newest first.
It was `CHANGELOG.md` until October 2026; that file now summarises each release
and points here, and `RELEASE_NOTES.md` says what changes on upgrade
for people who install and operate ShadowScan. Entries name the pull request
they came from where one exists, and say what was deliberately not carried.
Counts and figures quoted in an entry are those of its date.

## 0.1.3 — 2026-11-20

### Blocking container vulnerabilities named as check annotations (October 21)

`container-security` failed on `main` from 08:01 UTC with no Dockerfile or
lock change, and the check-run annotations said only "Process completed with
exit code 1": the verifier prints the blocking findings to the job log, and
the retained artifact holds them, neither of which a reader without log or
artifact access can open. `python -m tools.container.verify annotations` now
runs after a failed scan step, before the evidence upload, and prints one
`::error` workflow command per blocking finding from the written
`container-evidence.json` (vulnerability, severity, package type and name,
installed and fixed version, status), at most ten, the last counting the
rest. Field text keeps the verifier's printable-ASCII bound and is escaped
with the workflow-command encoding, so report text can neither end the title
nor start a command; a job that failed before the manifest exists names
nothing, and a duplicate key in the manifest is refused. Its first run named
CVE-2026-111943 (HIGH) in Wolfi `ca-certificates-bundle` 20260909-r2, fixed in
20260909-r3, which the pinned base image's package set did not yet carry; the
`bundle` command's stderr contract (no line starts with `::`) is unchanged.
### Repository hygiene after the companion move (October 21)

- `.gitattributes`, `.editorconfig`, `.gitignore`, `.pre-commit-config.yaml`
  and the repository consistency tests still named benchmark corpora, artifacts,
  results and harnesses that moved to the pinned `benchmark-suite/` companion,
  and two tests that no longer exist. No tracked file matched those entries; they
  are removed. The former-name and Markdown checks now cover `benchmarks/README.md`,
  the only remaining file there, which passes.
- Every workflow job runs on `ubuntu-24.04` instead of `ubuntu-latest`, which
  GitHub is moving to a newer Ubuntu release, so a runner image change is a
  reviewed edit. The macOS test leg keeps `macos-latest` until its current image
  is confirmed.
- The evaluation corpora that `make evaluate` names in its reports no longer use
  the former project name. No digest binds those names.
- `GOVERNANCE.md` still said the 2026-10-10 bypass actors applied until removed;
  it now cites the 2026-10-18 readback, which lists none, as
  `docs/operations/merge-policy.md` already did.
- Wording: `make test-fast` excludes the slow timed sweeps; the pull request
  template matches CONTRIBUTING on when to write `Fixes #NNN`; the #284
  adaptation names that pull request as closed, unmerged and unreviewed; ADR 005
  records that its #107 precondition was satisfied by #123; and
  `.github/dependabot.yml` says why the companion gitlink and the fixture
  manifests are not tracked.
### Companion pin to Nexus-ShadowBench 1ce0eee (October 21)

- `benchmark-suite` moves from `e027b98` to `1ce0eee`, which adds the
  companion's documentation and standards, an append-only `AMENDMENTS.json`
  ledger for migrated harness code (aisecnomad/Nexus-ShadowBench#2), a
  code-surface `fetch` that delegates to the hardened cases fetcher, certifi
  2026.10.19 with a CI `pip-audit` step, and errata for stale statements in
  preserved files.
- `tools/benchmark_evidence.json` was regenerated with
  `tools.benchmark_suite.extract`. Only `companion_modules.tools.verify_migration`
  changed (its SHA-256); the migration manifest digest and every metrics and
  corpus digest are unchanged, so no published number moves.
- The benchmark-section permalinks in `README.md` and the product guide name
  the new pin, as the consistency test requires; the linked reports are
  byte-identical at both commits. Checkouts the old companion `fetch` made
  should be fetched again.
### Unclosed credential calls and a faster call lexer (October 21)

- The 8,192-step call bound could not tell an argument list that never
  closes from one that is merely long. Prose and comments that name a
  credential-typed call without closing it reached the bound, and every
  excerpt of the file was withheld (a sanitization-limit gap). A call past
  the bound that would fail closed is now read again to its end; all such
  reads in one text share `_CALL_EXTENSION_PER_CHAR` work units per
  character, so they stay linear in its length, and a call past that budget
  still fails closed.
- The lexer crosses runs of characters that cannot open or close a string,
  comment or bracket in one step, charged their length. A run is matched no
  further than the step after the bound and the shared work bound: an
  earlier draft let a run cross a whole text, so 200 unclosed calls over a
  960 KB tail each scanned to its end (quadratic), which
  `test_reading_past_the_step_bound_stays_linear` caught. Over 4,500 corpus
  and adversarial texts the output and exceptions are identical to the
  per-character lexer, in 17.9 s against 29.7 s.
- Review found a fail-open in the extension: with the shared budget nearly
  spent, an extended reading could stop before the step-bound reading had,
  and it replaced that reading. A call pairing a credential key with a
  value (`setdefault(default=..., key="OPENAI_API_KEY", ...)`) was then
  judged on the shorter reading, which no longer held the key, and the
  value reached the excerpt where main fails closed. An extension that
  stops for length is now discarded, and the call keeps its step-bound
  reading and fails closed. A differential fuzz (8,000 texts, step bound 64,
  extension budgets 0-8 per character, a credential-shaped value) found 781
  values the old extension emitted and main withheld, and none after the
  fix. The lexer also skips the run pattern at a character that cannot start
  a run, which brings delimiter-dense text back to main's cost.
### Faster local start: deferred pattern compilation, no HTTP stack on import (October 21)

- Every process compiled all ~1,600 built-in patterns with the bounded engine
  (0.3-0.45 s of CPU on the measured runner, about half of a staged
  pre-commit scan) before reading a file. Built-in packs, which
  `python -m shadowscan.signatures.validate` compiles and checks in full
  before release, now defer each pattern to its first use
  (`signatures.budget.DeferredPattern`); the compile time is credited back to
  the input whose matching first needs it, so no input's budget pays for it.
  Organization packs are still compiled and checked when they load. A
  credential pattern is deferred in the linear assignment form `compile`
  runs (`Signal.bounded_patterns`); deferring the pack source instead made
  `test_generic_credential_patterns_bound_hostile_identifier_work` time out.
- `import shadowscan.cli` loaded `requests`, `urllib3`, `charset_normalizer`,
  `http.client` and `ssl` (97 modules) through `config -> triage ->
  utils.http`. The scope and policy helpers a local scan needs move to
  `utils.http_scope`; `tests/unit/test_startup_imports.py` pins that a local
  scan imports none of them.
### Dispatch verdicts resolved only where a selected call reaches (October 21)

- The dispatch inventory was consulted for every imported name a consumer
  held, so an unrelated import past the inventory's cut raised
  `DispatchLimitError` and left the consumer incomplete. Verdicts are now
  resolved inside `_selected_dispatcher`, after the call-shape and
  import-ordering checks: a limit is raised only for a module a selected
  (function name, arguments) call actually reaches. Limits are not cached and
  still fail closed; every numeric bound is unchanged.
- The nested re-export and dispatch queue admitted any consumer importing a
  provider or `platform.litellm` signature. litellm's requests never reach
  `provider_tool_loop_lines`, the only reader of the nested dispatch verdict,
  so scanning BerriAI/litellm filled the scan-wide 16 MiB queue with
  consumers that cannot use it. The predicate keeps
  `signature.category == "provider"` (all 38 provider signatures, wider than
  the OpenAI and Anthropic requests that reader binds) and drops the litellm
  clause. It reads the consumer's own imports: an aliased provider import
  counts, and a consumer that reaches a provider client only through a local
  re-export did not count before this change either.
  `test_only_provider_consumers_add_nested_dispatch_deferral` now expects a
  litellm-only consumer not to be queued.
### MCP structure in JSON: repeated keys, schemas, oversize files (October 21)

- BerriAI/litellm's `provider_endpoints_support.json` lists one provider
  twice. A JSON file the integrity checks refuse for a repeated key is now
  parsed under every reading (first value kept, last value kept, repeated
  objects merged; `mcp_config.json_readings_declare_mcp`). When none holds
  an MCP server table, a plain data file's integrity gaps are charged to the
  coverage budget (`TreeWalker.budget_defects`) and it is not treated as MCP
  configuration. A repeated key that hides a table from any reading still
  fails, and so does one in a manifest or lockfile (npm keeps the last of
  two `dependencies` keys, hiding the first from a reader that keeps it) or
  in agent configuration. continuedev/continue's F# TextMate grammar is the
  same case.
- litellm's 1.86 MB `proxy/_lazy_openapi_snapshot.json` was a blinding
  oversize gap because its bytes name `mcp_servers`: an OpenAPI schema
  field. The server-table walk no longer takes a field of a JSON Schema
  object's `properties` whose value holds schema keywords only for a server
  table (a value with any other key, a server name included, still is), and
  an oversize JSON file of up to 4 MiB whose bytes name a key is parsed to
  decide by its structure; one that does not parse stays blinding.
- openai/openai-agents-python's 1.15 MB
  `tests/fixtures/released_api_contract.json` nests past the server-table
  walk's 12 levels, so the structural check could not rule a table out.
  `json_readings_declare_mcp` walks every level and entry of every reading
  (`mcp_server_holders(..., exhaustive=True)`); every caller bounds the text
  by size first and the walk visits each container once, so its cost is
  linear (0.08 s for the contract). A table at any depth is still found.
- Review found the structural check's resource envelope too wide: three
  full `json.loads` passes, two through pure-Python hooks, over up to
  8 MiB, plus exhaustive walks of all three documents, peaked at hundreds
  of MiB and tens of seconds on container-dense JSON, and `json.loads`
  cannot be interrupted, so a handful of such files could exhaust the
  connector deadline or OOM a small CI container. `json_readings` now
  bounds the containers a parse could build before parsing anything, by the
  text's `{` and `[` characters (string contents included, so the count
  only overstates): text past 100,000 (`_MAX_JSON_CONTAINERS`) is
  undecided, so its gap keeps the byte check's answer (fails closed, never
  budgeted). A reading drops a repeated key's other values, so a parsed
  document's containers would miss what another reading rebuilds; the text
  bound covers every reading. Within the bound the text is parsed once,
  with a hook that records whether any object repeats a key: without a
  repeat that one reading is every reading, and the extra readings are
  built only over a repeat. `_MCP_STRUCTURE_BYTES` drops from 8 MiB to
  4 MiB; the motivating snapshots are 1.15 and 1.86 MB. Regression tests
  pin the single-reading fast path, the bound's undecided answer end to
  end, and its time envelope.
- Review follow-ups. An independent review found four gaps in the first
  version, each now a regression test: an exported n8n workflow with one
  harmless repeated key lost its agent finding (a data file is now budgeted
  only when the structured detectors find nothing in any reading); Go's
  decoder merges repeated objects, so a table neither first-wins nor
  last-wins sees was hidden (a third, merged reading is walked); an oversize
  `McpServers` or `mcp-servers` key, which the byte check matched without
  regard to case, became a budgeted gap (a variant spelling now leaves the
  answer undecided, so the gap stays blinding); and a server named like a
  schema keyword (`default`, `type`) under a schema's `properties` was taken
  for a field description (a field schema's keywords must now hold values
  of the types they take).

### Unparsed-input triage and unrendered template source (October 21)

- Three misjudgements made ordinary repositories exit 3. A Continue
  `mcpServers` block reference (`{uses, with?, override?}`, Continue's own
  schema) was an input defect; it is now an `mcp-server` finding whose
  `override` is projected as the server's fields
  (`docs/production-migrations.md`). An empty or whitespace-only manifest,
  agent manifest or MCP configuration fails its parser without hiding a byte;
  it is a file note, which strict accounting still counts. Under
  `--profile ci` a directory whose manifest names its project with template
  syntax is judged a template, as one whose manifest does not parse.
- microsoft/autogen exited 3 on
  `python/templates/new-package/{{cookiecutter.package_name}}/pyproject.toml`,
  whose `{%- if cookiecutter.depends_on_core -%}` block is not TOML. A file
  that does not parse under a directory whose name holds template syntax is
  now one partial gap charged to the coverage budget at a whole entry.
- crewAIInc/crewAI exited 3 on six templates `crewai create` renders, kept
  under ordinary names (`templates/crew/crew.py` declares
  `class {{crew_name}}():`, `templates/crew/pyproject.toml` a
  `{{folder_name}} = ...` key). A Python, TOML or JSON file that fails its
  parser, holds Jinja placeholders or tags, and parses once each placeholder
  is replaced by a stand-in and each one-line tag is dropped is now
  unrendered template source too (`connectors/code/template_source.py`). The
  file scanner records the verdict against the path
  (`TreeWalker.budget_defects`) and the walker charges the gap. A file broken
  in any other way still fails; agent configuration, strict accounting and
  MCP configuration found by structure keep the gap, and a tree of templates
  exhausts the budget. The scanner analyzes the rendering itself: a
  templated manifest's dependencies are inventoried from it and a templated
  module is bound from it (crewAI's `crew.py` is then an agent), so a
  placeholder added to a deployed file cannot hide what surrounds it.
- Review follow-ups. An independent review found that the first version
  budgeted every gap of a file under a template-named directory, a repeated
  JSON key under `deploy/${env}/` included, and that adding `{{ x }}` to a
  deployed `pyproject.toml` dropped its dependency findings while the scan
  completed. The directory rule and the content rule now explain only parse
  failures (`_discounted_gap(defect="parse")`, a registry scoped by kind),
  and the rendering is analyzed as above.
- A second review found that a placeholder or tag span could cross string
  delimiters and swallow structure: a root `package.json` whose
  `dependencies` (with a JSON5 trailing comma) sat between `"{%` and `%}"`
  on one line rendered as valid JSON without them, so a scan main reports
  incomplete completed with no findings. A placeholder now holds a Jinja
  expression without quotes, separators, brackets, `=`, `:`, `;` or `#`, and
  a tag must be a whole line with no `%}` before its end. The same seven
  corpus files are recognized as before. The directory rule also budgeted
  any parse failure under `${env}/`, so a module of newer Python syntax
  there completed; it now needs Jinja syntax in the directory name and in
  the file's own text (`TreeWalker.note_template_syntax`).

### Release readiness review (October 21)

- `tools/release/assets.py` looked up the release with `releases/tags/{tag}`,
  which GitHub serves for published releases only, so the documented flow of
  attaching evidence to a draft before publishing it failed with a 404. It now
  finds the one release naming the tag in the release listing, which includes
  drafts for a token with push access, rereads it by ID and refuses an absent
  or ambiguous match. The test double served drafts by tag, which hid the
  defect; it now behaves like the API, and the old lookup fails six tests.
- The TestPyPI smoke test in `docs/operations/publishing.md` ran
  the `python -m shadowscan.signatures.validate` and
  `python -m shadowscan.mappings.validate` checks from the checkout, which imports the source tree
  ahead of the installed wheel. It now leaves the checkout first, as
  `release.yml` and CI already do.
- Dating the 0.1.3 headings ahead of publication had moved the repository
  consistency checks' history boundary to the top of each log, so the 0.1.3
  release notes, changelog and engineering-log sections were no longer checked
  for stale counts or the former repository name. The newest section, dated or
  `## Unreleased`, is now treated as current; contributor guidance names that
  section instead of `## Unreleased`.
- The README, product guide and security policy say 0.1.3 is planned for
  TestPyPI and then PyPI on 2026-11-20 and that 0.1.2 remains the latest
  published release. The README is the PyPI project description, so its wording
  stays accurate on the 0.1.3 project page after publication.

### Repository hygiene after the 0.1.3 candidate (October 21)

- The publishing runbook gains step 8, "Record the publication": the list of
  files that still describe 0.1.3 as prepared rather than published (README
  and product-guide release state and PyPI Python-range note, the
  installation guide, the connectors release-status table, the OpenSSF
  criteria rows, the reviewer packet, roadmap, security policy, the dated
  release headings and the consistency-test pins), to be updated in one
  reviewed change on the day of the tag and upload. Opening the next
  candidate becomes step 9. Neither PyPI nor TestPyPI serves 0.1.3 at the
  time of this entry; nothing was tagged or uploaded.
- `CONTRIBUTING.md` says why a branch is brought up to date locally with
  `git merge --signoff`: GitHub's **Update branch** button and other web-flow
  merges carry no trailer and fail the DCO check (the `CI gate` went red on
  #286 for that reason on October 21), and the repository does not offer the
  button. It also records that a clean merge of `main` keeps a pull request's
  approvals while a conflict-resolving merge dismisses them, as observed while
  #285, #283, #286 and #289 were merged in sequence.
- `codespell` 2.4.3 runs as a pinned pre-commit hook with its skips and
  accepted words in `pyproject.toml`. A sweep of the prose, comments and
  shipped code found no misspelling; every hit was an identifier, a regex
  stem, a file suffix or a deliberate foreign-language placeholder, and the
  accepted-word list names each of them with its reason. The hook is not a
  CI gate: adding it there would need the tool in the hash-locked CI set.
- The consistency test that pins the in-sample benchmark disclosure read only
  the newest changelog section, so opening the next candidate's `## Unreleased`
  section (runbook step 9) would have failed it. It now reads from the newest
  heading through the 0.1.3 section, where the disclosure stays.
- Repository state, not tracked files: the labels `github_actions` (unused)
  and `javascript` (one closed Dependabot pull request) were deleted because
  `.github/labels.yml` does not declare them and the label workflow never
  deletes. An inventory of the 255 remote branches found 112 whose pull
  request merged, 90 whose pull request closed unmerged and 52 without a
  pull request; their deletion, turning on deletion of merged branches, and
  the non-provider-pattern and validity-check options of secret scanning are
  maintainer actions and were not performed.

### Lock the sample Dockerfile's CLI dependency graph (October 20)

The post-merge Scorecard report still found an unpinned global npm installation
in the synthetic support-bot Dockerfile. A separate manifest and lock now pin
Claude Code 2.1.304 and all eight native optional packages to registry SHA-512
integrities. The fixture uses `npm ci` with lifecycle scripts disabled and a
verified Node 22-slim image digest to satisfy the package's engine requirement.
The dependency remains detectable without implying that an agent is running.
No fixture image or CLI was executed, and no production dependency changed.
The [alert triage record](operations/security-alert-triage.md#october-20-fixture-pinning-follow-up)
preserves the prior dispositions and distinguishes this correction from a
measured Scorecard result.

### Publication hygiene: diff-base diagnosis, Falco example fields and upgrade notes (October 20)

- `shadowscan code --diff-base` reported every non-zero `git diff` exit as "is
  REF a valid ref?". The hardened metadata prefix passes `--no-lazy-fetch` so
  that Git older than 2.45 fails closed, and such a Git exits 129 (usage error)
  before reading any ref; with Git 2.43, `--diff-base HEAD~1` asked whether
  `HEAD~1` was valid. Status 129 now names the Git 2.45 requirement; a bad ref
  (128) keeps the ref hint. The full-scan fallback and its warning are
  unchanged. A regression test stubs both statuses and needs no Git.
- The connector guide says `examples/ebpf/` holds Falco rules "that emit the
  fields above", including `k8s.ns.name` and `k8s.pod.name`, but neither rule
  referenced them. Falco fills `output_fields` only from the template, and the
  reader builds each finding's resource as namespace/pod/process, so alerts
  from the example lost both and every pod's `python3` merged into one
  finding. Both rules now emit them; a regression test parses the example and
  fails on the previous version.
- The execution rule also omitted `proc.name`, the reader's only process-name
  field, while emitting `proc.cmdline`, which it does not read. An alert from
  that template for `ollama serve` therefore produced no matching finding.
  The template now emits `proc.name`; a regression builds an alert using only
  the template's selected fields and verifies the expected workload resource.
  The test fails before the change. This is an offline reader-contract check,
  not a live Falco deployment test.
- `RELEASE_NOTES.md` and `docs/production-migrations.md` did not describe
  several operator-visible changes: name-only app attribution, the
  `related_groups`/`related_truncation` contract (only `production.md` and
  `architecture.md` did, without #280's scope salting), Python dispatch and
  imported-tool agents, workload-bound Kubernetes attribution, the raised
  dependency floors, oci's new native `python-pkcs11` dependency and the
  aiohttp advisories. Both now do.
- Swept and found clean, with no change: all nine evaluation gates; every
  hash lock audited; `pre-commit run --all-files`; strict docs with every page
  in the navigation; relative links and anchors in all tracked Markdown; the 26
  external GitHub repositories the docs cite; codespell over documentation and
  shipped code; workflow permissions, injection-prone expressions and
  checkout credentials; wheel and sdist contents and metadata; the pinned
  benchmark-suite submodule commit. About 90 external links on other hosts
  could not be reached from the sweep environment and remain unverified.

### Base image refresh for CVE-2026-111943 (October 21)

- `container-security` failed on `main` from 08:01 UTC on October 21 with no
  Dockerfile or lock change: Trivy reported CVE-2026-111943 (HIGH) in
  `wolfi:ca-certificates-bundle` 20260909-r2, fixed in 20260909-r3, so the
  `CI gate` of every open pull request was red. #306's annotation named it.
- Both `FROM` lines move from `sha256:824f77df…` to the `chainguard/wolfi-base:latest`
  image index `sha256:81211e15a86ea1d5357f284482af45730c51de45eaf10ad9ce205d6bfc2df323`
  (pushed 2026-10-20 17:20 UTC). Its amd64 manifest's apk database lists
  `ca-certificates-bundle` 20260909-r3, read from the registry layers without
  running the image. No ignore or severity change was added; the gate is unchanged.
- The python-3.12 3.12.15-r0 pins stay, as their comment requires. The entry sits
  beside the certifi CA advisory rather than at the top of the section so it
  does not conflict with the open pull requests that insert there.

### certifi CA bundle advisory (October 20)

certifi 2026.10.19 replaces 2026.7.22 in the runtime, CI and docs locks. Earlier
bundles trust `emSign ECC Root CA - G3`; eight eMudhra intermediates chaining to it
had compromised private keys and were revoked, so an on-path holder of one could
present a valid-looking certificate for any connector endpoint
(GHSA-6q48-6c7w-9gw2). The advisory was published after `main`'s last audit and
made every lock fail `pip-audit`. Both hashes match PyPI's published wheel and
sdist; no other pin changed.

### Explicit discovery-benchmark baseline (October 20)

- `.github/workflows/benchmark.yml` took its regression baseline as the
  results directory under the companion's
  `benchmarks/shadow-ai-discovery/results/` that sorted last. Any later
  directory there (another tool's run, a re-score or an independent
  submission) would have become the baseline as soon as the
  `benchmark-suite` pin moved to include it, and a directory without
  `metrics.json` or `runs.json` would have broken the gate. The job now names
  its baseline in `BASELINE_RUN` (`2026-10-09`), fails with an error when that
  directory lacks either file, and prints a notice when a later directory
  exists but is not used.
- Behaviour is unchanged at the current pin, where `2026-10-09` is the newest
  directory. The shell logic was exercised against a copy of the companion's
  results tree for the pinned case, a newer directory and a missing baseline;
  the workflow itself was not dispatched.
- Moving the baseline is now a reviewed one-line change that says why. The
  committed `2026-10-09` run is in-sample for ShadowScan; the gate measures
  regression, not accuracy.

### Native eBPF metadata and service-specific Google endpoints (October 20)

- A native Tetragon, Tracee or Hubble record's top-level `hostname` is now
  treated as sensor/log-shipper metadata, like Falco's, instead of a connected
  destination. Bare Hubble flows still reserve `destination` for their endpoint
  map, but a wrapped flow can retain a separately enriched top-level string
  destination. Before/after regressions reproduce all four earlier mistakes.
- Google AI destinations now recognize the documented service-specific
  `SERVICE-ENDPOINT.p.googleapis.com` form, limited to the existing GCP AI
  service names and one DNS label. Tests cover every listed AI service,
  non-AI services and prefix/length boundaries, plus an offline combined
  native-enrichment fixture. No resolver is called; observed names do not
  prove private routing or agency.
- Source for the DNS form: Google's
  [Private Service Connect endpoint guide](https://docs.cloud.google.com/vpc/docs/configure-private-service-connect-apis#use_an_endpoint),
  checked October 20. No live eBPF deployment or cloud tenant was exercised.

### Shared surrender allowance across expired connectors (October 20)

- The supervisor now shares its five-second allowance for copying and sanitizing
  partial findings across every expired connector in a scan (#264), instead of
  restarting the allowance for each job. The allowance counts time spent in
  surrender, rather than time waiting for other jobs. Findings left after the
  allowance is spent are omitted with an explicit timeout diagnostic; the scan
  remains incomplete. Cancellation stays cooperative and a single preparation
  already in progress is not interrupted, so this is not a hard wall-clock cap.
- A deterministic regression with two overrun jobs and one second of simulated
  preparation per finding failed before the fix (ten seconds) and now stops
  after the shared five seconds, with both omissions counted.
- Rechecked the earlier scalar follow-up: exact standard-library `date`,
  `datetime`, `time`, `timedelta`, `Decimal` and `UUID` metadata leaves are already
  retained. New regressions cover each. Arbitrary subclasses remain refused
  on surrender because dispatching their methods would run worker-controlled
  code on the supervisor; existing tests verify omissions are reported and
  such methods are never called. This is advisory coding-agent verification,
  not independent human review or live tenant acceptance.

### Host inventory path precision follow-ups (October 20)

- Reproduced #264's Windows context omission with a Jan inventory row naming
  its install directory and a bundled `lms.exe` path inside LM Studio's Windows
  install directory. The endpoint catalog now names `AppData/Local/Programs/Jan`,
  `AppData/Local/Programs/LM Studio` and `Program Files/LM Studio` as product
  contexts. Bare Jan and unrelated `lms.exe` remain filtered. The Jan
  [troubleshooting guide](https://docs.jan.ai/desktop/troubleshooting) names its
  Windows install path; LM Studio's own [issue tracker report](https://github.com/lmstudio-ai/lmstudio-bug-tracker/issues/1860)
  records its per-user install directory, and [another report](https://github.com/lmstudio-ai/lmstudio-bug-tracker/issues/914)
  records the system install directory. These are path-format evidence, not a
  live Windows acceptance run.
- Model-store home anchoring retains the original path separator and drive
  context: relative `home/u`, `Users/u`, `root`, `var/root`, drive-relative paths,
  named-tilde text and traversal components no longer establish a home-directory
  shortcut. Integration review also reproduced two traversal paths that escaped
  the home shortcut but still matched the layout fallback because a later file
  had a model suffix; traversal now withholds model-store attribution there too.
  Exact symbolic home prefixes and absolute Unix/Windows homes remain
  recognized; no variable expansion, account lookup or filesystem read occurs.
- Ten newly added cases failed before these fixes and pass afterwards, and an
  offline export fixture exercises collection and analysis together. This is
  coding-agent verification, not independent human review or live tenant acceptance.

### Explicit categories for cloud-list and identity input defects (October 20)

GCP list validation now names `unparsed-input` for malformed response shapes,
unreachable-location fields, item arrays and pagination tokens; exhausted page
budgets name `analysis-limit`. Empty responses, provider error envelopes and
valid unavailable-location reports remain `upstream-error`. These categories
come from the failure branch rather than the URL or project name embedded in
the message. A project called `timeout-project` or `permission-403-project`
can no longer turn these events into a timeout or access denial. Invalid Okta
grants and conflicting Entra role labels name `unparsed-input`, avoiding the
fallback classifier's interpretation of the word `permission` as access denial.

Regression cases fail on the prior source and verify retained identity evidence,
unchanged incomplete status, once-only conflict diagnostics and categories across
ordinary and misleading project names. This is a focused correction for #264;
other connectors still use the diagnostic-text fallback and are not claimed to
have completed the explicit-reason migration. No live provider was contacted.

### DNS snapshot proposal and offline boundary regression (October 20)

Recorded the remaining #210 enhancement as a concrete proposal with a separate
explicit-opt-in collector, strict versioned snapshot and deterministic local
replay. The acceptance plan specifies TTL and exact-vantage checks, ambiguous
and conflicting evidence, bounded collection/replay, cancellation and no
synthetic client-contact or agent claims. Resolver transport/dependency and
artifact interface remain review decisions; no live collector, resolver option
or egress was added. The network guide links the proposal. An explicit test
guards resolver calls and packet sends during ordinary offline network scans;
the existing hermetic DNS fixture alone would have hidden a resolver call.
The proposal stays open; these tests do not claim live DNS acceptance.

### Forward-compatible coverage-gap reasons in report readers (October 20)

- `validate_coverage_summary` no longer refuses a report whose published
  coverage gap carries a reason category this version does not know (#264):
  a newer scanner's category is accepted when it has the exact shape of this
  version's own categories, a short lowercase slug (`[a-z0-9][a-z0-9-]{0,31}`),
  so `diff` and `merge` can still compare and republish the report, and a
  newer consumer of the republished report keeps the category verbatim. Every
  previously refused forged value (control characters, path-shaped text,
  non-strings, uppercase, overlong) is still refused, and this version's own
  records stay strict: `CoverageGap` rejects an unknown reason at creation.
  Regression tests cover acceptance, the preserved slug, the still-strict
  write path and the still-refused forgeries.

### Repository scan completion and bounded processing (October 20)

Adapted selected changes from the closed, unmerged
[PR #284](https://github.com/aisecnomad/Nexus-ShadowScan/pull/284), which had no recorded review, onto the
existing staged-scan and readiness workflows. The filesystem probe counts up to
180,000 entries within its unchanged one-second bound and proposes at most
1800 seconds at the 120-second default. The existing rate of 12,000 entries per
default budget, engine ceiling and treatment of explicit timeouts are unchanged.
This removes the earlier 200-second estimate ceiling; it does not establish a
measured throughput or promise that every repository finishes.

Recognized media and font headers can identify binary artifacts selected only
by a broad file glob. Source and agent-instruction names still record binary
coverage gaps. Hypothesis's `.hypothesis` example database joins the documented
default tool-cache exclusions; disabling those exclusions restores its scope.
Supported IPython package-manager automagic is normalized within a single-line
notebook cell, while unknown forms and malformed multiline cells remain gaps.
Review follow-up preserves string and comment spans for explicit magics and
shell commands as well: command-looking lines inside a multiline string cannot
remove its closing quotes or discard executable import binding. String spans
are computed separately per cell, so one unfinished cell cannot mask another.

Generic credential-assignment matching avoids repeated regex work inside long
failed identifiers while preserving long valid assignments, match spans and
order, quotas and incomplete-scan semantics. Only the exact supported grammar
receives the optimization; other custom patterns retain their original behavior.
Required-literal hints still derive from the declared pattern. The signature
pack's declared patterns and the bounded native-event YAML parser are unchanged.

The [incomplete-scan guide](getting-started/incomplete-scans.md) links readiness
checks, private reports, reason categories and scope-aware remediation. No
coverage budget, file-size, parser, sanitizer or credential quota is relaxed.
The existing preflight schema continues to report that no scan ran.

### Local scan usability, companion benchmarks and release evidence (October 20)

Added `shadowscan code --quick` for bounded scans of exact staged Git blobs,
without working-tree substitutions, hooks, filters or network access. The
reported scope cannot establish repository-wide absence or resolve baseline
findings. Links, conflicts, submodules and unread or over-budget staged content
fail closed. Temporary or alternate Git indexes are refused before any Git
read; the hook requires `git add` followed by plain `git commit`. The incremental
cache does not reuse working-tree results for staged content. `--preflight` reports readiness in its own schema and explicitly
states that no scan ran; an explicitly supplied empty signature index is now
honored rather than replaced by a full signature load.

Incomplete exits suggest category-specific remediation without echoing source
content. The existing per-root coverage budget and parser/redaction bounds are
unchanged. A normal small application completes; deliberately adversarial
redaction/parser fixtures still make the unrestricted scanner checkout
incomplete. The documented self-scan configuration declares those exclusions.
The requested 500 ms cold-scan target remains unmet; measured results and the
scope limitations are documented in the local pre-commit guide.
Optional native signature-pack event parsing reduces a seven-process quick-scan
median from 835 ms to 616 ms on the same local fixture. Python composition and
construction retain all resource and duplicate-key checks, with the original
parser as fallback. Six additional offline application/library examples
complete under the unchanged defaults; they do not establish field reliability.

Added offline terminal report browsing with literal, sanitized display, bounded
input and unchanged incomplete status across filtering. The proposed 1.0 public
Python facade and CLI/report contracts have behavioral regressions; the package
remains alpha pending independent review and acceptance gates.

The README is below 300 lines and the changelog summarizes releases. Detailed
examples, detection matrices, benchmark disclosures and prior change entries
remain on the documentation site with their consistency checks. The existing
STRIDE threat model now includes a trust-boundary diagram; the dated September
hardening log is published as historical, AI-assisted evidence.

Benchmark corpora, harnesses, recorded results and their tests move to a public
companion pinned by a Git submodule. Original bytes, Git blobs, modes and source
revision are retained in a migration manifest. Core evaluation stays local;
a required CI job validates and tests the exact companion pin. All 28 existing
harness function-complexity ceilings are retained in a separate parent ratchet,
with no increases. The documented self-scan excludes that separately tested
companion, so it also completes in an ordinary uninitialized checkout; the
local benchmark guide remains in scope. Historical results retain their original source/tool
provenance and are not new runs.

The release workflow can attach original Sigstore provenance/SBOM bundles and
checksummed assets to an existing maintainer-created release after protected
production publication. It verifies source, workflow, run, tag and asset digests,
refuses mismatched existing assets and never creates a release or tag. A
read-only weekly connector inventory tracks actual registry declarations,
dependency locks, permission references and failure guidance. The sample
Dockerfile uses a verified multi-platform image digest; the benchmark npm
installer already uses its reviewed lock. The runtime lock carries the same
aiohttp 3.14.5 advisory fix as the existing dependency/bug-fix PR.

### Correlation disclosure privacy, manifest-defect inventory retention and MCP URL precision (October 20)

Fixes for #268, #267 and #214, each found by an earlier coding-agent review
and deliberately deferred from the integrations that recorded them.

- Large-exact-group truncation disclosures no longer carry the unsalted
  `sha256([kind, value])` token or a member count that spans scope partitions
  (#268). The `identifier_group_id` and `group_size` a member discloses are
  now those of its own exact-scope partition and equal its `related_groups`
  token, so per-tenant report slices cannot be joined on an identifier-equality
  assertion the link policy refuses across conflicting or unverified scopes; a
  member outside an exact partition keeps the omission disclosure alone.
- Report pruning recomputes `related_groups` member counts and
  `related_truncation` group sizes over retained findings and drops a
  membership or token that fewer than two retained findings back (#268), the
  rule `related`/`related_details`/`related_candidates` already followed: a
  report must not link to, or count, findings it omits.
- `PythonDispatches` memoizes dispatch verdicts per (module, symbol) instead
  of re-walking a helper module's functions for every consumer (#268). A newly
  observed local root or a colliding module copy invalidates the affected
  cache entries, so import shadowing still vetoes a previously proven verdict;
  budget errors are never cached and still raise.
  Follow-up review bounds verdict caching to functions in the bounded AST
  inventory: arbitrary missing import names cannot grow it, and a lookup before
  a helper's source arrives cannot cache a false verdict against that helper.
- A YAML integrity defect (for example one duplicated mapping key, which a
  deployer may still accept last-wins) no longer erases a compose/Kubernetes
  file's generic image inventory (#267). The structural `kubernetes_workload`
  attribution stays withheld and the parse defect is still reported, so the
  scan's incompleteness accounting is unchanged; resource-limit failures still
  fail the whole file.
- An ordinary reference URL alone no longer raises the MCP `tool-poisoning`
  tag (#214). The URL is retained as separately explained zero-weight
  `instruction:external-url` evidence; a model-provider API host, instruction
  wording, tool references, hidden characters, content rules and audit
  indicators raise the tag as before, anywhere in the same 64 KiB window.
- `ScanResult.summary()` and the engine's split-run aggregation share one
  incomplete-reason merge helper (`merged_incomplete_reasons`), the #264
  refactor item, so the two counts cannot drift. No behavior change.

### Two CPython 3.11 serial-run test flakes no longer depend on GC timing (October 19)

- The macOS 3.11 leg failed twice on #266's final head, each time on a
  different pre-existing test, then passed on the same commit. The commits
  after the last green head do not touch either path, and a per-test probe
  found no leaked threads, processes, signal handlers, GC settings or
  finalizer garbage from the new tests.
- `test_json_agent_cards_are_bounded_and_strict[deeply-nested]`: on CPython
  3.11 the C JSON scanner shares the recursion counter with Python frames,
  and the cyclic GC runs synchronously on allocation. A collection within
  the last few levels of the 50,000-bracket descent can run another test's
  finalizer with no stack left. pytest's unraisable hook then overflows in
  `traceback.format_exception` and reports "Failed to process unraisable
  exception", although `parse_json_card` still returns `invalid`. The test
  now collects first and pauses the GC around the parse. A probe that plants
  one finalizer-bearing cycle and sweeps the gen0 threshold across the
  descent fails 14 of 225 alignments with the old body and 0 with the new
  one; 3.12 defers collections out of the descent and never failed.
- The three `noncode_ranges` linear-time tests: `process_time` charges a full
  collection over the session heap to whichever call it lands in. One run
  measured 105x against the 64x bound, where normal runs measure 12-23x. The
  tests now take the fastest of three samples with the GC paused. The bound
  is unchanged and still rejects a quadratic scan, which a mutation check
  measured at 121x.

### Dependabot #270-#274 carried with regenerated hash locks; aiohttp advisories patched (October 19)

- Dependabot raised the `pyproject.toml` floors and `requirements-ci-constraints.txt`
  pins but cannot refresh the hash locks. #270, #271 and #274 failed CI ("CI lock
  drifted from its reviewed direct constraints", "pre-commit ruff version differs
  from the CI pin", and #271's hash-locked install). #273 passed CI while leaving
  `requirements.lock` below its own new floors: boto3 1.43.101 against `>=1.43.114`,
  google-auth 2.58.0 against `>=2.62.0`, azure-identity 1.25.3 against `>=1.26.0`
  and oci 2.187.0 against `>=2.188.0`. No test compares the runtime lock with the
  extras' floors, so the hash-locked production install would not have satisfied
  the package's declared requirements.
- `requirements.lock` is regenerated with pip-compile 7.5.3. `-P` pins exactly the
  reviewed versions: PyJWT 2.15.1, regex 2026.9.29, boto3 1.43.114 (botocore
  1.43.115), google-auth 2.62.0, azure-identity 1.26.0 and oci 2.188.0. oci 2.188.0
  adds a hard dependency on python-pkcs11 0.9.4 (with asn1crypto 1.5.1). It
  publishes wheels for CPython 3.11-3.14 on manylinux x86_64/aarch64 and macOS
  universal2, and all 37 artifact hashes are locked. ShadowScan does not import it.
- `requirements-ci.lock` is regenerated with uv 0.11.32 from the constraints:
  ruff 0.17.1, pre-commit 4.7.0, hypothesis 6.170.0, ast-serialize 0.13.0, filelock
  4.2.0, platformdirs 4.13.3, pluggy 1.7.0, python-discovery 1.6.3 and virtualenv
  21.14.8. The ruff pre-commit hook moves to `38bfb07c0c64c304f47eb52090f8288150c77730`,
  the commit that tag v0.17.1 resolves to. The mypy hook's PyJWT follows the runtime
  lock, and the docs lock's platformdirs follows the CI pin, so the combined
  `make install` stays resolvable.
- aiohttp 3.14.4 (pulled in by oci) fixes GHSA-2g87-pp6c-29x5 (unbounded
  memory/CPU on crafted requests), GHSA-494j-54xm-rwp3 (Secure cookie sent over
  plaintext) and GHSA-5wr8-gcqf-gqf3 (keepalive timeout not applied before the first
  bytes). They were published after `main`'s last audit and made the runtime lock
  fail `pip-audit`.
- #272: codeql-action 4.39.0, ast-github-action 2.3.46 and scorecard-action
  2.5.0. Each SHA was checked against its release tag with `git ls-remote`.
- #275's readability edits to the README are kept: a separate fail-closed
  paragraph, "uses the same Python API" and a clause comma. Its removals of the
  coverage-budget, self-scan and "an incomplete scan never reads as clean"
  guarantees are not.
- Verified on CPython 3.12. Every lock installs under `--require-hashes
  --only-binary=:all:`, alone and combined. `pip check` passes with the package
  installed against the runtime lock. `pip-audit` reports nothing for all five
  locks. The full suite, ruff 0.17.1 lint and format, mypy, the signature and
  mapping validators, the policy tests, the secrets gate and the strict docs build
  all pass.

### Frozen cdxgen benchmark installations (October 18)

- Replace the top-level-only npm install pin with committed private package and
  integrity-bearing lock manifests. New installations use `npm ci` with lifecycle
  scripts disabled and strict Node 22/npm 10 engine checks in their isolated tool
  directory. Python and Go benchmark-tool builds still execute third-party code.
- Retain cdxgen 12.8.5 and narrowly override its vulnerable Undici 7.28.0 pin to
  [7.29.1](https://github.com/nodejs/undici/releases/tag/v7.29.1); the currently
  published cdxgen 12.8.6 retains the affected pin. The patched lock's npm audit
  reports no known vulnerabilities as of this change. This is a new installation
  graph, not evidence about the graph used for the historical benchmark.
- Each successful new installation writes its manifest/lock SHA-256 digests,
  tool and runtime versions, override and lifecycle policy to an install receipt.
  Failures after replacement begins cannot retain an old success receipt. Tests cover frozen
  input handling, integrity-pinned registry artifacts and receipt failure paths.
  Future freezes include the helper and both npm manifests. Historical results,
  manifests and freeze records are unchanged.

### Imported-tool integration regressions (October 18)

- A source-proven local Python dispatcher still needs an unshadowed,
  unconditional module import before its call. Reading a helper's implementation
  cannot make an import in another function, a conditional import or a later
  import available at that call. Scan-level regressions cover those cases with
  an indexed synthetic helper, plus direct and aliased module-import positives.
- JavaScript path mappings retain their wildcard template until the import
  supplies its path components. Parent-path normalization follows substitution,
  so `@/deep/file` mapped through `./*/../tools` selects `deep/tools`, not the
  unrelated root `tools` module. Positive and negative controls swap the two
  modules' executable definitions; substituted paths escaping the project remain
  unresolved. Resolution budgets and confined source reads are unchanged.
- These are offline regression checks; scanned fixture source is never executed
  and they do not establish field accuracy or independent human review.

### App-name corroboration, executable-tool provenance and Kubernetes image attribution (October 18)

- Identity and SaaS app assessments treat every display-name, publisher and
  description match as provisional, including custom signature packs. Same-product
  non-name evidence must establish a vendor before the name can corroborate it.
  Ordinary scopes and installation or machine-grant records cannot promote an
  unattributed app above possible confidence. Auth0 metadata and JWT hints follow
  the same name-attribution rule; independent token and permission evidence remains.
  The regression controls include unrelated Claude and Sora application names,
  genuine domains/client identifiers/scopes, repeated aliases, custom packs and an
  unrelated vendor's domain. Source and endpoint matching retain their own policy.
- Python provider-loop analysis follows first-choice aliases and imported
  model-selected dispatch interfaces when their returned results and matching
  call identifiers feed the same history. Closed local helper parameters can
  retain SDK provenance from agreeing constructed-client call sites; annotations
  alone cannot create that provenance. Static dispatch recognition does not observe
  the imported callback's implementation, external effects or runtime execution.
- JavaScript executable tools can resolve through supported local named exports
  and re-exports in the same project, using relative imports or explicit root
  TypeScript/JavaScript path mappings. The resolver consumes confined, already-read
  source snapshots with fixed limits. Unknown packages, missing alias configuration,
  ambiguous resolution, shadowed names and tools without an executable callback
  cannot establish executable-tool provenance. Budget failures remain incomplete.
  Rejected or ambiguous compiler mappings cannot erase a possible override of
  the SDK itself; configured base directories and observed local package/source
  collisions are checked for both consumers and tool definitions.
- Kubernetes image attribution requires a recognized workload structure at the
  image's own declaration. Compose and Dockerfile images keep their product-specific
  infrastructure evidence. The authored n8n attribution case now explicitly expects
  that valid `platform.n8n` infrastructure finding as well as its agent, while
  continuing to forbid `cloud.kubernetes-agent-workloads`; no source or target
  label was changed to hide the Kubernetes error.
  Explicit YAML fields override inherited merge defaults. Quoted template text
  does not disable valid workload context, and only an actually unparsed template
  is withheld; unrelated integrity defects and resource limits remain incomplete.
- Three authored current-idiom controls add relative and explicitly configured
  imported tools plus an imported schema with no executable callback. The existing
  sample with an unconfigured `@/` alias retains its input and positive target; it
  stays a documented unresolved-provenance gap. The realistic tutorial credential
  remains reported: prose calling a realistic credential an example is not evidence
  that it is harmless. Existing public and independent corpus labels are unchanged.
  These are regression checks, not independent field-accuracy or live-tenant
  acceptance evidence.
- The README's offline-demo table is refreshed from the unchanged demo inputs.
  Name-only app hints no longer inherit vendor capabilities, so its risk-level
  totals and highest-risk rows change while the finding count stays unchanged.

### Exact correlation groups, local tool dispatch and evaluation correctness (October 18)

- Exact identifier groups above 25 observations retain deterministic compact
  `related_groups` memberships instead of disappearing. Small groups retain
  their bounded pairwise links; exact edges omitted by the peer cap retain
  two-member memberships. `related_truncation` explains expansion limits.
  Conflicting or unverifiable scopes never gain exact links. Large compatible
  partial scopes are not merged transitively. This does not change approval,
  runtime assurance or risk policy.
- Provider tool-loop analysis tracks the first response choice through a local
  alias and accepts a typed SDK client parameter only with a matching constructed
  client at agreeing visible call sites. An imported dispatcher whose local
  source the scan has read must prove the dispatch in that source; a local
  source that proves nothing vetoes the interface shape, while modules the scan
  cannot read stay on the unconditional module-level import rule above. The
  response-selected name, arguments, result and feedback history remain
  connected. Source is never executed.
- AI SDK generation can resolve stable named imports of explicitly exported
  executable tools from already-read local modules. Ambiguous paths, unconfigured
  aliases, SDK path remapping, mutation and schema-only tools remain unresolved,
  as do scopes whose module-resolution configuration is unknown, inherited or
  able to shadow the SDK itself. The imported-tool
  corpus now includes an explicit tsconfig path mapping that was absent from
  the original fixture, with a negative regression preserving the no-config case.
- n8n image evidence belongs to its dedicated platform signature; the generic
  Kubernetes workload signature applies to an image only inside a parsed
  workload PodSpec, so Compose and Dockerfile images no longer duplicate it.
  The attribution fixture now explicitly expects its valid n8n infrastructure
  finding alongside the workflow agent, retaining its forbidden Kubernetes
  assertion.
- Evaluation prints target classification, labeled assertions and completeness
  beside binary metrics. Incomplete cases are unscored and force evaluation and
  acceptance failure even with a known-gap waiver. `all_cases_correct` is
  separate from the waiver-policy gate. These remain author-written regression
  cases, not independent or field accuracy evidence.

### SARIF notifications name their connector once; the docs show how one scan gives both the JSON ledger and SARIF (October 18)

- A SARIF run's `toolExecutionNotifications` prefixed each diagnostic with its
  connector, and connectors name themselves in their own diagnostics, so the
  text read `code.filesystem: code.filesystem: ...`. The table and Markdown
  reports already drop the repeat with `without_connector_prefix`; SARIF now
  uses it too.
- `docs/scanning.md` told a reader who needs the coverage ledger beside a
  SARIF log to write a JSON report "of the same scan as well", which one
  run cannot do: a run writes one format. It now shows the way that needs one
  scan, writing the JSON report and rendering SARIF from it with
  `shadowscan merge report.json --format sarif`. That log has the scan's
  results and notifications, plus one saying the source report is incomplete
  when it was, and `merge` exits 3 as the scan did.
### The credential oracle's slow rows run with a budget that coverage tracing cannot exhaust (October 18)

- The CI run of this branch failed on the Linux 3.11 leg, the coverage-traced
  one. Two `tests/unit/test_credential_oracle.py` rows,
  `r1p.4-ts-1500-get-chains` and `r1p.4-ts-12531-ors`, read `incomplete`
  instead of `complete`: their inputs are 1,500 and 12,531 lines, and under
  coverage tracing (several times slower) the default matching budget of 2
  CPU seconds per 256 KiB ran out, so the scan reported itself incomplete,
  which is the scanner failing closed, not a credential defect. The rows
  passed untraced and alone. The oracle's `mode="slow"` scan rows now run with
  `scan_timeout: 60`: they measure what the pipeline reports on a scan that
  completes, and the budget has its own tests. Reproduced locally: the rows
  fail under `--cov` on 3.11 and pass with the budget.
- The other two legs that failed are recorded above: the macOS legs by the
  initial-env probe's `/proc` fallback, and the 3.14 legs by the report
  nesting limit that 3.14's parser no longer runs out of stack on. The fix
  landed on the integration branch from this work (e2482bf).

### Filesystem connector split into walk, file-scan and findings collaborators (ADR-005 steps 2-5; #259; October 18)

- `FilesystemConnector` (`shadowscan/connectors/code/filesystem.py`, 6,237
  lines on this branch after the review fixes) is a façade over four
  collaborators in modules of their own, as ADR-005 describes:
  `OwnershipResolver` (#258), `TreeWalker` in `walk.py` (the walk, its
  limits, and the fail-closed coverage accounting including the budgeted,
  discounted and declared gaps the review fixes added), `FileScanner` in
  `file_scan.py` (reading, redaction and analysis of one file, the lockfile,
  credential-file and binary-fixture reads and the credential quota
  disclosure) and `ProjectFindings` in `project_findings.py`, with the records
  they share in `scan_records.py`. The façade keeps configuration, the engine
  hooks (`estimate_timeout_seconds`, the coverage hooks), `scan_tree` and
  `_base`. Sizes: 1,171, 2,184, 2,257, 1,268 and 272 lines.
- #259's four moves were made again on the integrated code rather than
  carried as commits: the fixes of #254 to #258 had changed the same
  functions, so each definition #259 moved was merged three ways (main, this
  branch, #259's moved copy) into the module #259 chose, and the 41
  definitions the fixes added were placed with the collaborator that reads
  them. `isolated` takes the walker, whose gap accounting records a contained
  failure, as the connector's method did here. The walker receives the
  coverage `profile` and whether the gap budget is 0; the collaborator wiring
  test covers both.
- Every name importable from `filesystem.py` before still is, as the defining
  module's object (`name as name` re-exports; `tests/unit/test_negative_context.py`
  pins 304 of them, generated from the façade's imports). Tests patch the
  class or module that owns a name. #259's other filesystem commits (its own
  CLI split, changelog condensation and ownership move) were not carried:
  this branch already had each in another form (#252 with fixes, #256/#258,
  #258).
- Verified by the full suite on 3.11 (25,641 passed) and 3.14, ruff, mypy,
  the complexity gate (baseline written again with `--rebaseline`: the
  façade's entries go, the collaborators' appear under their new names at
  their old values), the policy and consistency tests and the self-scan. Not
  verified: the live clone and API modes of `code.github` and `code.gitlab`,
  and the 2026-10-01 field scan's repositories.

### A diff-scoped walk reports the connector deadline's remainder against the diff-selected files only (October 18)

- **Found by:** the reviewing session's static review of the integrated stack, on
  `walk.py` as the ADR-005 split left it; both lines pre-date the split and are
  on main in `filesystem.py`.
- **Deadline arithmetic:** in diff mode the walk buffered every listed entry and
  skipped the ones the diff filter excluded inside the loop, so when the
  connector deadline stopped it, "deadline reached after X of Y files" counted
  the excluded entries in Y, and the unread-settings carry-over received entries
  the walk would never have read. The filter now runs before the loop, over the
  buffered listing (`TreeWalker._run_with_deadline`), so the remainder and the
  carry-over see only files the walk would read. The regression test selects six
  of ten files and expects "after 4 of 6 files". The carry-over effect was
  smaller than first described: `_diff_included` always keeps posture-client
  settings files and `_note_unread_settings` ignores non-settings entries, so
  the overstated count was the defect.
- **Dead branch:** `_reserved_budget`'s trailing model-artifact check was
  unreachable, as the first branch had already returned for model artifacts;
  dropping it saves a suffix lookup per entry.
- **Ratchet:** `walk.py` grew by one line for the up-front filter (2,191 to
  2,192), recorded with `--rebaseline`.

### A file's source-binding time budget is counted as `timeout`, as the docs define it (October 18)

- `code.filesystem` counted every budget the import-bound source binder
  raised (`SourceBudgetExceeded`) as `analysis-limit`. `docs/scanning.md`
  defines `timeout` as including "a file's matching budget", and the
  binder's time budget is one, so `incomplete_reasons` named the wrong
  category for it. The reason is now read from the binder's own message: a
  time budget is `timeout`, and an AST, call, nesting or recursion limit
  stays `analysis-limit`. Only the category changes; the file is still
  incomplete and keeps its lexical evidence.

### Under the ci profile a project whose manifest repeats a key is a project, as npm and Composer read it; a template at the repository root is documented as not declared (October 18)

- The ci profile declares the gaps in documentation and example paths unless
  they lie in a project of their own, and a directory none of whose JSON or
  TOML manifests parses is not one. The probe parsed JSON manifests with the
  strict decoder, which refuses a repeated key. npm and Composer accept one
  (the last counts), so a real project under `docs/` or `examples/` whose
  `package.json` or `composer.json` repeated a key was taken for a broken
  template, and the gaps in it were declared as the documentation around it:
  the scan exited 0 where its own manifest made it a project that exits 3.
  The probe now reads JSON manifests as those tools do: a repeated key
  parses, a `NaN` or `Infinity` does not. The scanner's own analysis still
  reads manifests strictly and records a gap for one that repeats a key.
- `docs/scanning.md` and `docs/connectors/code.md` said a cookiecutter
  template's unparsed manifest and sources stay declared. That holds for a
  template under a documentation or example path
  (`templates/{{cookiecutter.slug}}/`). A template at the repository root, as
  in a cookiecutter repository, is judged from the root, where no profile path
  applies, so its gaps are judged as without the profile. The docs now say
  so, and `test_a_template_at_the_repository_root_is_not_declared` pins it.

### Plugin workers also start without npm's per-registry `_auth`, more webhook names and values, and .NET connection strings under any configuration path (October 18)

The plugin-environment review found close variants of the credential families
the withheld list targets, which a process-mode worker still inherited:

- npm's per-registry basic credential `npm_config_//<registry>/:_auth` (a
  base64 `user:password`), although the top-level `npm_config__auth` and the
  per-registry `:_authToken` were withheld, and Yarn's `YARN_NPM_AUTH_IDENT`.
- `*_WEBHOOK_URI`, `*_WEBHOOK_URLS` and `*_WEBHOOKURL`, beside the withheld
  `*_WEBHOOK` and `*_WEBHOOK_URL`. A webhook URL carries no user
  information, so the URL-value rule did not take these either. A `*_URL`,
  `*_URI` or `*_DSN` variable holding a Slack, Discord, Microsoft Teams or
  Google Chat webhook (`SLACK_HOOK_URL=https://hooks.slack.com/services/...`)
  is now withheld too.
- .NET connection strings outside a name starting with `ConnectionStrings__`:
  after an `AddEnvironmentVariables` prefix (`App_ConnectionStrings__Db`) or
  as a section's `ConnectionString` (`Azure__Storage__ConnectionString`).

Neighbours stay: `npm_config_//<registry>/:always-auth`,
`MY_CONNECTION_STRINGS_DIR`, `CONNECTIONSTRINGSDIR`, and a webhook URL under a
name that is not a URL name. `options.plugin_env` keeps any of them for a
plugin that needs it. The list in `docs/connectors.md` is updated.

### A process-mode plugin's credential identities are labelled `keyed` under the operator's identity key again (October 18)

- Since the plugin-environment change on this branch, a process-mode worker
  starts without `SHADOWSCAN_IDENTITY_KEY` in its environment. The worker
  learned whether its key was the operator's stable key from its own
  `Engine`, which reads that variable, so it now always concluded it was the
  run's own. The worker still received the operator's key and keyed the
  plugin's credential identities with it, with the same digests as before,
  but it labelled them `run`: `credential_identity_scope()` answered `run` and
  a connector declaring `uses_run_identity_key` got
  `gateway_identity_key_stable=False`. `diff` cannot match findings whose
  `metadata.identity_scope` is not `keyed` across scans, so a plugin
  reporting the scope lost cross-scan matching that `main` had. On `main` the
  worker inherited the variable, built its `Engine` from it, and only then
  removed it.
- The parent now passes the key's stability to the worker with the key
  itself. `test_a_spawned_plugin_keys_credentials_as_the_scan_does` checks the
  label and the digest under the operator's key, and the label without it.
- `docs/production.md` and `docs/production-migrations.md` said the worker
  never sees the raw key. That is true of its environment, but the worker
  holds the decoded key in memory, and a plugin can reach it there. Both now
  say so.

### A report nested past 256 levels is refused as nesting on every interpreter, not only where the parser runs out of stack (October 18)

- `diff`, `merge`, `dashboard` and `inventory`, the commands that read a
  ShadowScan report, refused a deeply nested one only when the JSON parser
  raised `RecursionError`. That limit belongs to the interpreter: about 1,000
  levels on Python 3.11, about 10,000 on 3.12 and 3.13, and on 3.14 whatever
  the stack allows (65,000 levels locally on 3.14.8, and more on the CI
  runner). The same file was refused as nesting on one interpreter and parsed
  on another, where it was then refused for its type or accepted. The 3.14 CI
  leg failed on this: a 100,000-level baseline parsed there and was refused as
  "report must be a JSON object" instead.
- A report is now refused with "report structure exceeds nesting limit" when
  its arrays and objects nest more than 256 levels (`MAX_REPORT_DEPTH` in
  `shadowscan/comparison.py`), whatever the interpreter. ShadowScan's own
  reports stay far inside it, because finding metadata is sanitized to 64
  levels. The walk keeps one iterator per open level, so its memory follows
  the depth, not the size. On a 38 MB report it costs about a fifth of the
  parse.

### A CPython 3.12 tokenizer fault is an unreadable source, not an exception; JavaScript string spans stay inside the text (#259; October 18)

Two fixes carried from #259, whose coverage-guided fuzzing found them. The
fuzz targets and the rest of #259 are not carried here; #259 overlaps the CLI
split, the complexity ratchet and the ownership move, and is to be rebased
after them.

- CPython 3.12's C tokenizer can fail with an exception that says nothing
  about the text when a NUL byte follows an indented or malformed line
  (python/cpython#140576): a `SystemError`, or in some processes an
  `AttributeError`, so it cannot be matched by type. The three places that
  read Python tokens now go through `shadowscan/utils/python_tokens.py`,
  which raises one `TokenizerFault`, and answer it as they answer any source
  the tokenizer rejects. The assignment scanner of `sanitize_text` withholds
  the rest of the text, the source lexer masks everything after its last
  token and reports the file incomplete (exit 3), and the re-export
  prefilter calls the module no import-only shim. No credential was exposed
  before: the filesystem connector's per-file isolation already recorded the
  exception as "file analysis incomplete". The outcome is now deterministic.
- The JavaScript-family lexer stepped over the character after a backslash
  inside a string even when the text ended on the backslash, so the string's
  span ended at `len(text) + 1`. The position is clamped to the end of the
  text, so `"abc\` spans `(0, len(text))` like any other unterminated string.
### Code after a block comment that closes on its line is read as code for redaction; a process-mode plugin keeps the deadline its supervisor enforces (October 18)

A sibling session's agent review of the integrated branch reported four
findings. Two were reproduced and are fixed here; the other two are not
changed.

- **Leak shared with main, fixed.** The line-tail pass of `sanitize_text`
  took a line's first comment as the rest of the line. After a block comment
  that closed on the line (`/* note */ dbPassword: process.env.P?.trim() ||
  "<pw>",`), the code that followed was read as comment, where only
  key-shaped tokens are withheld. A password fallback, a keyword default or
  a later literal after a credential's name therefore stayed in evidence;
  main leaks every such shape. A carried comment that closed mid-line handed
  the whole line on, so an apostrophe in its text (`don't */`) opened a
  phantom literal. The pass now reads the code after a closed `/*...*/` or
  `<!--...-->` as a line of its own, at most 16 comments a line so that a
  line of many comments stays linear. After a carried comment's closer it
  reads only what follows the closer.
- **Regression against main, fixed.** In process mode the supervisor
  enforces the deadline it starts a worker with. The worker received the
  unset default, though, so a plugin that proposes a longer deadline for a
  large input (`estimate_timeout_seconds`, which FilesystemConnector
  implements and a subclass inherits) raised the worker's own deadline. The
  worker then paced itself past the deadline it was held to and was stopped
  with nothing reported, where it would have reported a bounded subset. The
  worker now receives the deadline as a chosen one, which is never raised;
  `docs/api/engine.md` says so.
- **Not changed.** The over-quota probe of the credential matcher does run
  the judge on one more match, but the placeholder samples and repeated
  locations it can add are bounded on their own (five each), and repeats
  only list again a credential already counted, so nothing past the quota is
  reported. `ScanResult.summary()` merging incomplete-reason counts by hand
  where `_ConnectorRunner._run_split` uses `Counter` is a refactor and is left for one.

### Credential review fixes, round 6: sentence passwords with a weak verb, camelCase password names and UUID defaults withheld, catalog and ConfigParser defaults, CR-only text in linear time (October 18)

An adversarial review of the round-5 credential rules reproduced these, and an
independent verifier confirmed each against main 8c72467. Both reviewers were
coding agents; this is not independent human review.

- **Regression, fixed.** Round 5 let `come`, `use` and `set` make an
  instruction in an env or credential file, so a sentence a person picked as
  a password (`NowIsTheTimeToCome`, `ComeWithMeNowPlease`) was read as a
  label and dropped. Main reported those passwords. These weak verbs now make
  an instruction only beside a negation or modal (`must-come-from-vault`), a
  label-vocabulary word (`use-your-own`) or a word of the variable's name.
- **Regression, fixed.** Round 5 reported a password's default of any shape
  after any `.get()`, so a message catalog's defaults (`"Forgot password?"`)
  became credentials, and eight in one i18n module filled the quota: exit 3
  on an ordinary module, where main completed. A ConfigParser read reported
  its option name `"password"` as the password. The any-shape rule now holds
  after an environment read only (`process.env`, `os.environ`, `getenv`,
  `ENV.fetch`, `env()`, `GetEnvironmentVariable`); after any other read a
  default is judged as a key is. Main's false positives on both shapes are
  gone too.
- **Regression, fixed.** The netrc pass found a line's start with
  `rfind("\n", 0, position)`, which on CR-only text scans back to the start
  every time: 400,000 such lines took 55 s against main's 4.7 s. Line starts
  are now found in a doubling backward window, linear in the text.
- **Leak shared with main, fixed.** Under a camelCase name such as
  `dbPassWord`, the detector reported the fallback literal of
  `process.env.DB_PASSWORD?.trim() || "<pw>"` but the redactor read the
  name's last word, `Word`, and left the password in the finding's own
  snippet in every format. The redactor now also reads the name as a whole.
- **Leak shared with main, fixed (minor).** A UUID-shaped key given as an API
  key's settings default was reported but shown in its snippet: its hyphens
  cut it into runs the opaque-key test does not take. A UUID after a
  credential's name is now withheld.
- **Not changed.** A key pasted as an environment variable's name that does
  not look opaque is reported without counting toward the quota, up to a
  bound, and one past the bound is left out without disclosure, as on main.
  Disclosing it would make seven readable long names
  (`SVC1OPENAIAPIKEYPROD`) exit 3 again, which an earlier round fixed. A
  Python `os.getenv("X_PASSWORD", "<default>")` default is not reported on
  main or this branch; that is left for a later round.

`tests/unit/test_credential_review_followups.py` and a CR-only case in
`tests/unit/test_redaction_performance.py` cover the fixes; each regression
case fails before its change.

### Agent configuration review fixes, round 2: rule files of any suffix, escaped and folded keys, analysis limits, walk bounds and directory aliases (October 18)

An adversarial review of "Agent configuration never vanishes into a coverage
gap" (below) found six ways a file the scanner reports as agent, MCP or
coding-agent configuration still vanished into the budget, the test-code
discount or a `--profile ci` declaration, and four ways an ordinary
repository newly exited 3 where main 8c72467 exits 0. Each is fixed with a
regression test in `tests/unit/test_coverage_configuration_spellings.py`
that fails on the previous commit.

- **Rule files of any suffix.** `_agent_configuration` counted a file that a
  directory-wide coding-agent or MCP signature selects, or that lies in an
  agent definition directory, only when its name was one the walker reads by
  itself (`_analyzed_by_name`) or a signature named it literally. A
  `.cursor/rules/deploy.rule`, `.clinerules/01-deploy.rules` or
  `.windsurf/rules/x.rst`, which the signatures select and the scanner reads,
  was one budgeted entry when oversize, linked outside the tree or replaced
  by a FIFO, and discounted or declared under `tests/` when NUL-poisoned or
  unreadable, where main exited 3. Such a file is now configuration whatever
  its suffix; only a binary asset kept beside the rules
  (`_BINARY_ASSET_SUFFIXES`: images, fonts, archives, audio and video) is
  not, so a large `.cursor/rules/diagram.webp` stays an ordinary gap.
- **Oversize content-detected configuration under `--profile ci`.** An
  oversize file whose bytes name a server table (`docs/.continue/mcpServers/evil.yaml`,
  a padded `tests/fixtures/servers.json`) was blinding, but `_budgeted_gap`
  was not told it was configuration, so with `scan_secrets` off the ci
  profile declared it. `_oversize_gap` now passes `configuration` and full
  weight when the content check matched.
- **Escaped and folded keys in unread bytes.** The byte check
  (`_MCP_KEY_BYTES`) accepted an escape only for the letters m, c and p, so
  `mcp\u0053ervers` (valid JSON, the same key to a client) padded past
  `max_file_size` read as no configuration, while any backslash-newline
  anywhere counted as a key, so an oversize PyYAML or VCR cassette (whose
  `yaml.dump` folds long double-quoted strings with trailing backslashes) or
  a shell-continuation export was blinding. `_unescaped_key_bytes` now writes
  each `\u`, `\U` or `\x` escape of a key character as that character and
  joins a folded double-quoted token only when the joined text starts an
  `mcp` key, before the search; the loose escape and fold alternatives are
  gone, and the chunk overlap is 4 KiB so an escaped, folded key cut at a
  chunk boundary is still seen whole.
- **Analysis limits in configuration found by content.** A failure that
  `isolated` contains (a `SanitizationLimitError` from a 100-deep array beside
  `mcpServers` in `tests/fixtures/tools.json`) was recorded without full
  weight, so the ci profile declared it. `isolated` takes `by_content`: the
  file-analysis and credential-detection boundaries pass `_mcp_by_content`
  (what `_detect_mcp` decided, recorded before the server parser runs, or the
  file's bytes by the escape-aware check before that), and the MCP-analysis
  boundary always counts.
- **A key the text check missed, behind a parse failure.** With no parse held
  (a YAML nesting limit, a JSON duplicate key), `_looks_like_mcp_config`
  pre-filtered with the plain substring check `_mentions_mcp_keys`, which
  misses `'mcpServers':` and an escaped JSON key, so the fixture's gap was
  discounted under `tests/`. The decision moved to `_content_declares_mcp`,
  which uses the escape-aware byte check there, so the server parser runs and
  records its defect at full weight.
- **Tables past the walk's bounds.** When `mcp_server_holders` reported
  truncation, the file was decided by `_mentions_mcp_keys`, which both missed
  an escaped key (a 301st list entry with `mcp\u0053ervers` read as no
  configuration, as on main) and found prose in string values: a 300-issue
  export quoting a YAML `mcpServers:` snippet, a 300-path OpenAPI document
  with one in a description, or an 8-deep AST fixture whose comment mentions
  `mcp_servers:` exited 3 with `MCP server tables past the walk limit`, where
  main exits 0. `_names_mcp_key` now requires a key-shaped spelling: a JSON
  key opened by an unescaped quote and followed by a colon, a YAML mapping
  key read from the YAML scanner's tokens (quoting and escapes undone as the
  loader undoes them), or a TOML key at a line start or in an inline table,
  each with any character written as an escape.
- **Directory aliases under generic dot-directories.** A directory link was
  agent configuration when any component of its path was a dot-directory a
  signature names, so `.github/actions/setup -> ../../tools/setup-action` and
  `web/public/.well-known -> ../../static/well-known`, aliases of scanned
  directories, were blinding with `named like agent configuration` (main
  exits 3 too). `_agent_directory_path` now asks whether a trailing run of the
  link's components lies along the directory part of an agent configuration
  glob (`_agent_directory_globs`: the coding-agent and MCP file signatures,
  the posture settings directories, the agent definition directories, the
  clients' settings files and the `.well-known` agent cards), or reaches a
  wildcard there (`.cursor/rules/team`). Such a link to an outside or
  unresolvable target stays blinding and is never declared; an alias of a
  scanned directory is blinding only when a file it holds would be
  configuration at the alias path (`_alias_holds_agent_configuration`, which
  lists at most 1,000 entries and fails closed past them), and otherwise is
  the one budgeted entry `alias of a scanned directory` any alias is.
  `test_an_alias_named_like_an_agent_directory_stays_blinding_inside_the_tree`
  now aliases `.cursor` to a directory holding `mcp.json`, `rules/` or
  `environment.json`, as its comment said, instead of a `rules.txt` no client
  reads there.

Compatibility: on the reviewer's noise trees (issue export, OpenAPI document,
deep AST fixture, folded cassettes, in-tree `.github/actions` and
`.well-known` aliases) no scan exits 3 where main 8c72467 exits 0; the
remaining exit 3 where main exits 0 are padded MCP fixtures under `tests/`
with `--no-secrets`, which main budgeted. `make evaluate` gives the same
tp/fp/fn/tn on every corpus. `_looks_like_mcp_config` delegates its structured
branch to `_content_declares_mcp` to stay within the complexity target.

### go.mod require blocks read in linear time; no dependency named "(" (October 18)

- `code.filesystem` found go.mod `require ( ... )` blocks with the lazy
  pattern `require\s*\((.*?)\)`, which reads from each unclosed `require(`
  to the end of the file before failing: quadratic in a file of them. The
  module-level linearity test measured it within its threshold on Python
  3.11 to 3.13 and past it on 3.14, which is why the 3.14 CI legs added with
  #256 failed while no local run reproduced it. Each opening is now found once
  and its block ends at the next `)`; the blocks are exactly those the
  pattern found (checked on 3,000 generated texts).
- The one-line `require` pattern matched a block's `require (` as well,
  because `\s` spans the line break, so every go.mod with a block reported a
  dependency named `(` whose version was the block's first module. It now
  reads only the one-line form.

### The untraced CI test legs run on pytest-xdist workers; the traced leg stays serial (#259; October 17-18)

- The `test` job runs the suite with `-n auto --dist worksteal`, one worker
  per CPU, including the coverage-traced 3.11 leg that took about 40 minutes
  serially; pytest-cov combines the workers' data before the floors are
  checked, and `make test-parallel` uses the same options. The macOS job
  still runs `pytest -q` through the console entry point. The 60-minute job
  limit is unchanged until the parallel timings are known. The suite has to
  stay safe to run in parallel: no test may depend on another's files, ports,
  environment or ordering.

**October 18, after three heads of #261.** The coverage-traced 3.11 leg failed on
every head run with `-n auto`: at bb05d72 six tests (both dashboard time
budgets, the linear unterminated-regex scan, a `MatchTimeoutError` from the
matcher's 2-second input execution budget, and two import-binding budget
counts), at cfed5ba the dashboard history budget alone (18.4 s against 16 s).
The untraced legs passed every time. Those tests measure documented time
budgets, and under tracing plus one worker per CPU they measure the runner.
The traced leg therefore runs serially again, as `make test` does and as the
budgets were measured (37 to 50 minutes); the untraced legs keep the workers
(10 to 13 minutes instead of 25). `make test-parallel` is now the untraced
run, without coverage, and the policy test holds both recipes to their legs.

### OpenSSF Best Practices evidence page, claiming no badge (#259; October 17)

- `docs/operations/openssf-best-practices.md` answers each of the 67
  passing-level criteria with a status (Met, Confirm, Attest, N/A, Gap) and
  the evidence in this repository, and lists what silver and gold would still
  need. No badge is claimed and nothing records an application for one. One
  gap is left for the maintainer: JWTs verified through a JWKS set no minimum
  RSA key size (`crypto_keylength`). Policy tests keep every criterion
  answered once and tie the page's statements about cryptography to the code.

### Release attestation bundles are named `provenance.sigstore.json` and `sbom.sigstore.json` (#259; October 17)

- The release workflow's two attested bundles were `provenance.json` and
  `sbom.json`; they carry the `.sigstore.json` suffix that release-signature
  checks such as OpenSSF Scorecard's Signed-Releases look for among a GitHub
  release's assets. The workflow still creates no release:
  `docs/operations/publishing.md` has the maintainer attach the wheel, the
  sdist, `SHA256SUMS` and both bundles to a release created by hand, and shows
  how to verify a download against them. **(behaviour change)**

### Self-scan of the checkout in `make check` and CI, with every exclusion explained (#259; October 17)

- `make self-scan` (part of `make check`) and a CI step scan this checkout
  with `examples/shadowscan.self-scan.yaml` and require a complete report:
  findings do not fail the step, an incomplete scan (exit 3) does. Each
  exclusion names a path, not a pattern, with its reason above it; a
  reviewed list in `tests/test_self_scan.py` is the only way to exclude part
  of the first-party trees, and an exclusion that matches nothing fails.
- On this branch the review fixes had added four more files the scanner
  cannot read to completion, each now a named exclusion: the
  signature-authoring guide and the engineering log quote call shapes without
  a closing parenthesis (the call-lexing budget), and the engineering log,
  `tests/unit/test_credential_oracle.py` and
  `tests/unit/test_generic_credential_references.py` hold more credential
  inputs than the five-per-format quota #257 discloses as incomplete. With
  them the self-scan completes: 24 findings, 1,161 objects, exit 0.

### Complexity ratchet holds function and module size and fails closed (#259; October 17)

- `tools/complexity_gate.py` is #259's gate at this branch's target: it holds
  every function above ruff's `C901` limit of 15 in `shadowscan/`, `tools/`
  and `benchmarks/`, and every `shadowscan` module above 2,000 lines, to
  `tools/complexity_baseline.json`. Nothing listed may grow, nothing new may
  join, and an improvement fails the check until `--update` lowers the
  baseline, so the room it made cannot be spent again; `--update` refuses to
  raise anything, and a rise that review accepts is recorded with
  `--rebaseline` as a diff of the baseline. The gate exits 2 when ruff or the
  baseline cannot be trusted, ignores `noqa`, and records the ruff version.
  It replaces the gate #254 added (target 15, `--update --allow-increase`),
  whose CI step, Makefile targets and `make check` membership it keeps. The
  tests express every expected complexity relative to the limit.

### Coverage-guided fuzzing of the redaction and source-lexing code (#259; October 17)

- `tools/fuzz` fuzzes `sanitize_text`, `sanitize` and the source lexer with
  Atheris, hash-locked in `requirements-fuzz.lock` (Linux x86_64 only).
  `make fuzz` and the weekly `Fuzz` workflow run it, the workflow with a
  read-only token and no stored corpus; a failing lexing input is kept as an
  artifact, but an input that beat the redactor is never printed or uploaded.
  The same checks run as Hypothesis tests in the ordinary suite
  (`tests/unit/test_fuzz_targets.py`), and `make audit` and the dependency
  audit cover the new lock. Atheris is not an engine OpenSSF Scorecard's
  Fuzzing check recognises. See `docs/operations/fuzzing.md`.

### KubernetesConnector.analyze decomposed into per-concern helpers (#259; October 17)

- `KubernetesConnector.analyze` (ruff `C901` complexity 66) is a short driver
  over helpers that each own one concern: reading records and `List`
  envelopes, the NetworkPolicy pre-pass, an object's identity and pod spec,
  its containers, exposure tags and the finding. Findings, ids, tags and
  diagnostics are unchanged; `tests/unit/test_kubernetes_helpers.py` covers
  the helpers.

### CLI package, reporter protocol, condensed README, identity sign-in clients and API page narratives (#252, #253; October 17)

- `shadowscan/cli.py` is now the `shadowscan/cli/` package: the group and its
  shared helpers in `__init__.py`, one private module per command family. Every
  command module looks the replaceable names (`console`, `err_console`,
  `_run_scan`, `_emit`, `available_connectors`) up on the package at call
  time, so replacing one on `shadowscan.cli` reaches every command;
  `tests/unit/test_cli_package_seams.py` pins that. `python -m shadowscan.cli`
  works through `cli/__main__.py` (the ShadowBench cases adapter runs it that
  way), and the 20 click commands stay importable from `shadowscan.cli` under
  their old names. The names the old module held only because it imported them
  (`json`, `Path`, `Finding`, `compare_reports` and similar) are gone; import
  them from their own modules.
- `shadowscan.reporters.Renderer` types the renderer contract every
  `RENDERERS` entry keeps: the result, positionally, returning text.
- The README keeps a command summary; the full command reference is
  `docs/reference/cli.md` and the data types moved to `docs/api/index.md`. The
  detection matrix stays generated.
- `identity.okta` and `identity.entra` leave out a sign-in client only when
  every scope is an OpenID Connect Core scope, it carries no AI attribution
  or other tag, and its name matches no signature or the generic hint only on
  a common word (agent, assistant, copilot, bot). "LLM Gateway", "Company GPT",
  "GenAI Portal" and "Gemini" with OIDC scopes stay reported, as on main. The
  "57% to about 80%" precision figure #253 quoted was not measured and is not
  carried.
- The 23 `docs/api/` pages gained a narrative introduction each, checked
  against the code in two passes.

### Credential review fixes, round 5: every password entry, closed label vocabularies, settings defaults, password fallbacks, repeated lines and netrc paths (October 17)

Fixes from round 4's credential and netrc reviews, judged on the same
oracle (`tests/unit/test_credential_oracle.py`), which now holds 554 inputs
with the outcome on this branch and on main 8c72467. Evidence redaction
fails closed: under a password's or secret's name the whole value span is
withheld, and over-redaction is accepted where a shown credential is not
(under other credential names a token that looks opaque is). A label,
possessive or instruction heuristic drops a value only when every word of
it is in a closed vocabulary. A row worse than main still needs a one-line
reason (152 of the 554 have one: 148 "not a credential", four quota
disclosures); of round 4's rows only `DevPasswordLocal` under
`DB_PASSWORD` is worse than main, every word of it label vocabulary or the
name's own.

- **Every password entry on a line is withheld.** The line-tail pass read
  the password rule from the first credential name on a line only, so a
  `password:` after an `apiKey:` entry or a credential-named callee kept
  only the opaque-token rule and a punctuated password or a passphrase was
  shown; a keyword argument of the read (`fallback=`, `default_value=`, `{
  fallback: ... }`) also ended the value before the literal. Each password
  name on the line now withholds its value to the next entry of its own
  mapping, object or argument list (`_credential_joins`,
  `_password_values`), in one linear pass. Main showed both.
- **Overlapping spans are withheld to their union.** A password whose
  start reads as an opaque token was withheld only up to that token
  (`"[REDACTED]&<tail>"`), because `_withhold_spans` kept the shorter of two
  overlapping spans. It now withholds their union.
- **A secret's fallback is withheld whole.** The matcher reports a
  fallback of any shape under a password's, passphrase's or secret's name,
  but the line-tail pass withheld every literal only under a password's
  last word, so `azureClientSecret: process.env.AZURE_CLIENT_SECRET?.trim()
  || "<punctuated>"` was reported and shown in its own finding's excerpt,
  and so was a run-together `dbpassword:` (main showed both). `secret`
  joins the password words, and a last word ending in `password`,
  `passphrase`, `passwd` or `secret` names one.
- **A sentence is a label only with an instruction word.** Two function
  words made an instruction label, so a sentence a person picks as a
  passphrase (`fly-me-to-the-moon`, `may-the-force-be-with-you`) was
  dropped, which main reported. A sentence is now a label only with an
  instruction word or a label word and with every word in the closed
  vocabulary (function, instruction and instruction-context words, label
  vocabulary, the name's words).
- **A possessive phrase is a template only when every word is one.**
  `ton-jardin-secret`, `su-token-de-casa` and similar passphrases were
  templates by a credential noun first or last, so `saas.generic` copied
  them raw from other columns and the matcher dropped them; main withheld
  and reported them. `shadowscan/utils/placeholders.py` now holds the
  template vocabulary that the placeholder test and the credential judge
  share, and a possessive phrase is a template only when every word after
  the possessive is in it.
- **Env-file passwords of account and sentence words are passwords.** In
  an env or credential file `admin`, `user`, `strong`, `internal` and
  `commit` no longer label a value, and a sentence without an instruction
  word is a password (`MyStrongPassword`, `my_secret_password`,
  `InternalUserPassword`), as on main; labels and closed instructions
  (`KeycloakAdminPassword` under its name,
  `change_me_to_a_strong_password`) stay labels.
- **A settings read's default argument is a fallback.**
  `GetValue<string>("OpenAI:ApiKey", "<key>")`,
  `configService.get('OPENAI_API_KEY', '<key>')`, `System.getProperty`,
  `dict.get`, `Optional...orElse` and `requireNonNullElse` lost the key,
  which main reported; `_DEFAULT_READS` names the reads and the position
  (or keyword) of their default.
- **A password fallback of any shape is reported.** Under a name ending in
  `password`, `passphrase` or `secret`, a fallback or default is the
  credential unless the redactor's own `password_literal` test keeps it (a
  variable's name, a path, a URL, a placeholder, fewer than six
  characters) or it is a label, as main reported.
- **A repeated credential's lines are listed again.** Counting a repeated
  credential once also dropped its later lines from the evidence; the
  judge now returns up to five of its locations without counting them, and
  every credential finding's `count`, the `.env` provider-key finding's
  included (which counted each match), is the number of distinct
  credentials.
- **A pasted name counts toward the quota only when it looks like a key.**
  Seven ordinary underscore-free names (`process.env.SVC1OPENAIAPIKEYPROD`)
  made a file incomplete where main completed; such a name is still
  reported, at most five per signature, but counts toward the quota only
  when it passes `opaque_key`.
- **netrc lines.** `_NetrcLines` keeps line starts in a dict instead of a
  sorted list it inserted into, so the reverse-order reads of the netrc
  pass are linear (160,000 lines in 4.7 s instead of 9 s against 1.2 s at
  40,000). A netrc comment holding a Windows path whose directory is a
  netrc keyword (`\\nas\user\fred`, `C:\Users\bob\default\new`) runs to the
  end of its line, so the entry goes on and its password is withheld.
- **Docs.** docs/connectors/code.md, docs/signatures.md, docs/scanning.md,
  docs/production.md, SECURITY.md and the migration notes describe the
  pasted-name scope (member reads and `GetEnvironmentVariable` are
  reported; `os.getenv("<KEY>")` and subscripts are withheld but not), the
  count semantics, the label rules and what can remain; the entry below is
  corrected on the pasted-name forms.

The evaluation corpora give the same per-case results and tp/fp/fn/tn as
8fd7299; the complexity gate reports no function worse than its baseline.

### Credential review fixes: env-file passwords, typed reads, pasted names, repeated credentials, labels and cut-read evidence (October 17)

Fixes from two reviews of the credential pipeline (round 3, rebased as
5aa142b), judged against main 8c72467 on one table of every concrete input
those reviews and the earlier rounds used: `tests/unit/test_credential_oracle.py`
holds 368 inputs (sanitizer lines, matcher lines with their mode, small file
trees, `saas.generic` records and placeholder values), the outcome on this
branch and the outcome on main, computed once and written in as data. A row
where this branch is worse than main must name why: a value that is no
credential (a reference, a label, a placeholder), the quota disclosure of
more than five distinct credentials, or one credential repeated on several
lines, reported once.

- **Env-file passwords built like names are reported again.** In `.env`,
  `.env.local` and the tool credential files, a PASSWORD or CREDENTIAL
  value with one label word or one word of its name was dropped as a label:
  `POSTGRES_PASSWORD=PostgresProd2024Secure`, `DB_PASSWORD=LocalAdmin2024Strong`,
  `snout_passed_thump_bloom` and, by the review's count, 15 of 20 realistic
  camel or snake case passwords with a year, which YAML and compose files and
  main reported. Such
  a value is now a label only when every word of it is label vocabulary of
  either strength, a function word or a word of the name, and every number
  is the name's (`KeycloakAdminPassword` under `KEYCLOAK_ADMIN_PASSWORD`,
  `svc1_local_dev_password` under `SVC1_DB_PASSWORD`,
  `change_me_to_a_strong_password`). `admin_password_123`,
  `DbPasswordFromSecretsManager` and `managedIdentityCredential` in a real
  `.env` are reported, as on main; in templates and other configuration the
  name rules are unchanged.
- **Blanks around `=` keep a password named.** python-dotenv and Node's
  dotenv read `POSTGRES_PASSWORD = TrustNoOneEverAgain`; the assigned name kept
  its blank (`'POSTGRES_PASSWORD '`), so it named no password and the name
  rules dropped the value, which main reported. `matcher._assigned_name` drops
  the blanks and a closing quote before the operator.
- **A password's dotted words are a passphrase outside source code.**
  `DB_PASSWORD=snout.fiber.thump.bloom.gravel` in YAML, compose or another
  non-code file was read as a dotted name; main reported it. Only source
  code reads such a string as a package, preference key or i18n message.
- **Typed reads keep their fallback.** A generic call's type arguments
  between the read and the operator (`configService.get<string>("X") ??
  "<key>"`, C#'s `GetValue<string>(...)`, Kotlin's `getProperty<String>(...)`)
  ended the operand reader at `<`, so the fallback key main reported was
  lost. `matcher._type_arguments` reads a balanced list of type names and
  marks (nested lists, `?`, `[]`, `|`, `&`) after a name with no blank
  before the `<`; a cast to a generic type (`as Record<string, string> ||`)
  is read through the same way.
- **A key pasted as the variable's name is reported.** Evidence withheld
  `process.env.<KEY>` when the name looks like a key (letters and digits
  alternating, or 16 characters or more without `_`), but the detector read
  it as a reference and reported nothing, which main reported. One test,
  `redaction_rules.pasted_key_name`, now decides both: the matcher reports
  the name as the credential of a member read by name (`process.env`,
  `import.meta.env`, `Bun.env` and `os.environ.<NAME>`) and of
  `Environment.GetEnvironmentVariable("<NAME>")`. (Corrected: this entry
  first said the call and subscript forms the redactor reads were reported
  too. The generic rule gives no match for `os.getenv("<NAME>")`,
  `process.env["<NAME>"]`, `ENV["<NAME>"]` or `System.getenv("<NAME>")`, on
  this branch or on main, so those are withheld from evidence and not
  reported.)
- **One credential repeated counts once.** One password in each of six
  compose services, or one key in each of six manifest documents, counted
  six toward the five-per-format quota, so the scan exited 3 with "more than
  5 credentials" for one credential, where main completed. The judge
  recognizes a credential its signature already counted by a BLAKE2b digest
  keyed with a random key of that judge alone, so no credential is kept past
  its match; the repeat is neither counted nor reported again. Six distinct
  keys still disclose the quota, and a finding's `count` is distinct
  credentials.
- **Instruction labels are labels again.** `must`, `never` and `not` had
  become function words, `change` and `key` common words, and a two-letter
  word of the name had stopped counting, so `change-me-before-deploying`,
  `do-not-commit-this`, `must-be-set-at-runtime`, `not-configured-yet` and
  `pg-replica-sync-user` were reported, and an `.env.example` of six exited
  3. Two function words now make an instruction, `me`, `at`, `via`, `yet`,
  `please`, `now`, `before`, `by`, `my`, `a` and `an` are function words,
  `jwt` and `environment` label words, `admin`, `user`, `internal`, `commit`
  and `strong` common words, and a two-letter word of the name counts as a
  common word. The passphrases the earlier rounds named
  (`snout-passed-thump-bloom-gravel`, `db-fiber-thump-bloom-gravel`, the
  stemmed and filler forms) are still reported: none has a function word,
  and none has two common words.
- **Possessive placeholders need words that name a credential.** A
  possessive followed by any words was a template, so in `saas.generic` a
  letters-only credential that begins with one (`je-suis-le-patron`,
  `ta-<mixed-case run>`, `your-secret-garden`) was left out of the credential
  context and its copies in other columns were reported raw, which main
  withheld. `common._possessive_template` requires the credential's noun or a
  placeholder word last (English, German and Dutch possessives) or first or
  last (the others), two words after a two-letter possessive and each word in
  one case. #258's placeholders (`sua_chave_openai`, `votre-cle-api`,
  `your_api_key`, `sua_serper_api_key`) stay templates, `tu_clave` is a
  placeholder by its translated word, and a possessive alone (`sua`) or with
  a trailing separator (`seu_token_`) is a template again.
- **Evidence after a cut read.** In `name: value` form a password after a
  read the value lexer cuts (`dbPassword: process.env.P?.trim() ||
  "<password>"`, `db_password: os.getenv("K", "<password>")`) was shown when
  it was not one opaque token (punctuation, a passphrase), and a key was
  shown after a credential-named callee (`sgMail.setApiKey(process.env.K?.trim()
  ?? "<key>")`, a builder's `.apiKey(...)` ternary), in a PHP or Ruby `=>`
  entry, on Black's next line (`    or "<key>",`) and in an XML comment that
  runs past its line; main showed all of them. `_redact_line_tails` now reads
  a callee whose last word names a credential and `=>` as joins, goes on to a
  line that starts with a fallback operator or follows one that ends with
  one (through comment lines), reads a block comment a credential's line
  opens to its end, and withholds every literal of a password's value up to
  the line's next entry whatever its shape, except an upper-case variable
  name, a path, a URL, a placeholder and a literal under six characters.
  What can still remain is listed in SECURITY.md's "what can remain".
  `AzureKeyCredential(str("<key>"))` now withholds a key that looks opaque,
  which an earlier test kept.
- **Docs.** A placeholder fallback is `example-credential` evidence only
  when it reads as a token (`?? "your-api-key-here-Abc123XyZ"`); one of words
  and an ellipsis (`?? "sk-ant-api03-..."`) records nothing, which two
  passages had claimed otherwise. docs/scanning.md says translated
  placeholder words count only between separators.

The evaluation corpora give the same per-case results and tp/fp/fn/tn as
5aa142b; the complexity gate passes with no function above its allowance.

### Agent configuration never vanishes into a coverage gap (October 17)

The previous change gave every coverage gap one decision, but which file hides
agent configuration was still decided three ways: `_named_configuration` for
the oversize reader, links and special files, `_full_weight_in_tests` for the
test-code discount, the declaration and the budget's weight, and the MCP
parser's `full_weight` for content. They disagreed, and each disagreement
failed open somewhere. One predicate, `_agent_configuration(rel, name,
file_matches)`, now serves every gap site.

- **One predicate, in any letter case and for every signature.**
  `_named_configuration` compared names case-sensitively while the detectors
  do not: a padded `.MCP.JSON`, `Claude_Desktop_Config.json` or
  `.claude/Settings.json`, each reported as configuration when readable, was
  one budgeted entry, and a 100-file tree exited 0 where main exited 3. It
  also dropped the coding-agent and MCP files that only a directory-wide
  signature selects (`.continue/mcpServers/*.yaml`, `.roo/rules/*.md`,
  `.clinerules/*.md`, `.amazonq/rules/*`, `.kiro/steering/*`,
  `.junie/guidelines.md`, `.augment/rules/*`, `.trae/rules/*`), so a link to
  an outside copy or a padded copy exited 0 while a NUL in the same file was
  blinding. Its agent-definition clause made a large asset beside the rules
  (`.cursor/rules/demo.mp4`) blinding. And it named every manifest and shared
  client name, so ordinary single-source aliases exited 3 with no budget:
  `requirements.txt` linked to `requirements/prod.txt`, `.env` to
  `.env.example`, a `Dockerfile` or `providers.tf` to a shared copy,
  `config/config.json` to `config.development.json`. `_agent_configuration`
  is true for a dedicated MCP name, a coding-agent settings path, an
  instruction document, an agent manifest or card (each compared
  case-insensitively), a file in an agent definition directory or that a
  coding-agent or MCP file signature selects, directory-wide globs included,
  when the file is text the scanner reads or a signature names it, and a file
  whose content a caller found to declare servers. It is true too for a
  shared client name in the directory of the client that reads servers from
  it (`.vscode/settings.json`, whose `mcp` table VS Code reads, beside
  `.gemini/settings.json`, `.continue/config.yaml` and `.codex/config.toml`):
  a later pass found an outside or dangling `.vscode/settings.json` link
  costing one entry, where a137fd5 and main exited 3, so the in-tree alias
  of one is blinding again too, as on both. Generic manifests, build files
  and shared client names elsewhere are not: linked or replaced by a FIFO
  they cost one entry. An oversize dotenv file (`.env`, `.env.production`)
  stays blinding while `scan_secrets` is on, as it was and as main had it:
  it exists to hold a key, and unread it hides one, while a link of that name
  hides no byte of the tree. A tool credential file (`.npmrc`, `.netrc`),
  which main never read, stays one entry when oversize, as it was. The oversize reader, `_skip_link`,
  `_skip_non_regular`, `_declared_omission`, `_discounted_test_path` (and
  through it the discount and the gap weight) read the one predicate, so a
  link and an oversize copy of one file are judged alike.
- **An oversize MCP configuration found by its content is blinding.** A
  `deploy/tools.json` holding `mcpServers`, reported as an MCP configuration
  when readable, cost one budgeted entry once padded past `max_file_size`,
  where main exited 3. The oversize gap (`_oversize_gap`) now reads the bytes
  of a file the MCP parser decides by its content (`_guessed_mcp_name`: a
  JSON, TOML or YAML file, or a shared client name) in 1 MiB chunks, confined
  as the reader opens it, lower-cased and without NUL bytes, for any
  spelling of a server table key (`_MCP_KEY_BYTES`: quoted, spaced, explicit,
  dotted and inline-table keys, an `mcp` key, a letter written as an escape,
  a quoted key folded across a line break), and finds one behind any
  padding, past a chunk boundary or in UTF-16. A hit, a file the check cannot
  read, one over 128 MiB (more than a Git host stores outside LFS) and an MCP
  registry `server.json`, which declares its server without such a key, are
  blinding; a data export that names no key still costs one entry. A prefix
  peek was the alternative the plan offered; it would let leading padding
  hide the key.
- **An alias of a scanned directory is one entry; an agent's directory never
  is.** The walker change that made directory links blinding also caught
  links whose target the walk scans at its real path (`lib_alias -> lib`,
  `docs/_static -> ../assets`), with an error saying the target was
  unscanned: ordinary layouts exited 3 although every file was read. Such an
  alias (`_alias_of_scanned_directory`: inside the root, every directory on
  its path walked, within the selected paths, and not test code read as
  product code) now costs one entry, with a diagnostic saying the paths below
  it are not assessed. Under `--profile ci` a directory link named like an
  agent's configuration directory under a test or documentation path
  (`tests/e2e/.claude`, `tests/e2e/.cursor`, `docs/.vscode` pointing outside
  the tree) was declared, since `_declared_omission` judged the name as a
  file's, so the configuration behind it was never inventoried while a link
  at `tests/e2e/.claude/settings.json` exited 3. `_agent_configuration_link`
  now decides before the declaration: a link named like agent configuration,
  or one to a directory (or dangling) whose path names a directory the
  coding-agent and MCP file signatures read configuration from
  (`_agent_directory_names`, derived from the loaded signatures), is blinding
  and never declared, an alias of a scanned directory included; a link to a
  single file under such a directory is judged by its own name.
- **An undecodable test fixture that declares servers is blinding.** In a
  tree of 61 entries, a guessed `tests/fixtures/agent.yaml` holding
  `mcpServers` with a NUL byte was a tolerated one-entry gap, and under
  `--profile ci` a declared omission: `_scan_binary_test_fixture` found the
  MCP structure but `_unreadable_gap` judged the path with
  `_discounted_test_gap(rel)`, which is true for a fixture found by its
  content, and `_budgeted_gap` declared it. The earlier tests passed only
  because each held one file, over any budget. The structure check was also
  text-only for files with no parse held (`_mentions_mcp_keys`), so a quoted
  (`'mcpServers':`), spaced or explicit YAML key, a unicode-escaped JSON key,
  a TOML inline table or literal key were discounted. `_binary_declares_mcp`
  now parses the NUL-stripped text with the reader's bounded loader
  (`_structured_context`) and lets the structure decide, as for a readable
  copy; text that does not parse to a mapping or a list is read for any
  spelling of a key (`_may_declare_mcp`). Such a fixture is blinding under
  both profiles (`_unreadable_gap(by_content=True)`, passed to the
  declaration as `full_weight`), and the servers its text declares are
  reported. The parametrized full-weight tests now run in a 61-entry tree
  under both profiles, with these spellings added.
- **Server tables in a list are read, and the walk's bounds fail closed.**
  Inside a list the structural check counted a server table only when it
  was a mapping, so Continue's list of server records (`mcpServers: [{name,
  command}]`), written by an Ansible copy task or held in a JSON list of
  clients, completed silently where main exited 3. Past its bounds (12
  levels, 256 entries per container) the walk returned False, so a playbook
  with 300 tasks before the copy task, or a table wrapped in 13 lists, was
  never sent to the parser. And a list-rooted document that did reach the
  parser, a server catalog under `tests/fixtures/` among them, exited 3 with
  `MCP configuration must be an object`, which names no defect anyone can
  fix. The walk moved to `mcp_config.mcp_server_holders`, iterative and
  bounded as before: inside a list it also counts a list of server records
  (a mapping carrying `command`, `url`, `args`, `type` or `transport`, which
  a transcript's `{name, status}` does not), and it says when the bounds cut
  it, so `_document_declares_mcp` returns None and `_looks_like_mcp_config`
  decides from the text instead. The parser reads a list-rooted document as
  the server tables its entries hold (`_listed_server_tables`), merged with
  numbered duplicate names: a catalog or a play is reported and leaves the
  scan complete, since nothing is hidden once its tables are parsed, and a
  table past the bounds is recorded as a limit (`analysis-limit`). A
  dedicated name holding a list with no table keeps the old diagnostic.
- **A mapping's nested server tables are read too.** The structural check
  routed a mapping whose only table sat below its top level
  (`profiles: [{mcpServers: ...}]`, a client's per-project
  `projects: {path: {mcpServers: ...}}`) to the parser, which read the top
  level alone, found nothing and let the file pass as ordinary
  configuration with no finding and no gap (on main too). The parser now
  reads such a mapping's nested tables (`_nested_server_entries`) with the
  same bounded walk, so the servers are reported.
- **With `scan_secrets` off, oversize agent configuration in tests stays a
  gap.** `_skipped_oversize` skipped any oversize file under a test path as a
  discounted fixture once credential detection was off, so a 5 KB
  `tests/.mcp.json` or `tests/CLAUDE.md` over a 1,000-byte `max_file_size`
  left the scan complete, contradicting the rule that such files are not
  discounted there. It now skips only discounted test code
  (`_discounted_test_path`, which excludes agent configuration) and leaves a
  JSON, TOML or YAML fixture to the reader, whose content check
  (`_oversize_gap`) keeps the gap when its bytes name a server table and
  otherwise skips it with the same counted warning.
- **Profile ci reads an undecodable declared file for credentials first.**
  #255 read a binary test fixture for credentials before discounting it,
  but #258 declared undecodable documentation, example and generated files
  without any read, so under `--profile ci` a key in a binary
  `docs/setup.md` or `src/client.generated.json` was never reported while
  the same bytes at `tests/fixtures/dump.txt` were. `_read_source` now hands
  any undecodable file whose gap would be discounted or declared
  (`_credential_only_read`) to the credential-only read
  (`_scan_undecodable_file`, formerly `_scan_binary_test_fixture`), which
  records the declared gap after it, naming the read. `_is_generated_path`
  still matches by file name anywhere, so `src/*.generated.*` and `*_pb2.py`
  are declared; ci.md already says so, and such a file is now read first.
- **Profile ci never declares a file it could not read.** The previous
  change passed `unread_credentials` from the oversize reader and from
  notebook outputs only, so under `--profile ci` a test fixture the scanner
  could not open or read (EACCES, `file could not be read`) was still
  declared, the scan complete with none of its bytes read for credentials.
  `_unreadable_gap` now passes `unread_credentials`, so `_declared_omission`
  declares such a file only while `scan_secrets` is off; with it on, the gap
  is charged as without the profile, one whole entry. With this and the
  credential-only read of declared undecodable files, the README's claim
  that the profile never declares a file left unread for credentials holds.
- **Content left unread for credentials weighs a whole entry.** The
  previous change stopped declaring an oversize fixture, but charged it at a
  quarter under a test path, so four 1 MB cassettes each holding a key, in a
  65-entry tree, cost 1.0 against an allowance of 1.3 and the scan exited 0
  with no key read, where main exited 3. The plan decided that content left
  unread for credentials is never discounted or declared and is charged at
  full weight whatever its path: `_oversize_gap` now passes `full_weight`
  while `scan_secrets` is on (unreadable files already did). Reading oversize
  content for credentials alone stays out of scope; SECURITY.md ("What can
  remain") and scanning.md record the trade-off and its remedies.
- **A blinding gap leads its root's published details.** The combined
  summary listed the parts that left the scan incomplete first, but within a
  part `details` kept the first 50 gaps in walk order, so in a tree of 1,000
  files with 60 dangling certificate links a `zz/.mcp.json` link (blinding)
  was cut while 50 tolerated links were listed. `_LedgerPart.evaluate` now
  lists a part's blinding gaps first, each kind in the order recorded; an
  over-budget part's partial gaps are the ones that condemned it already.
- **Each published gap names its root or repository.** In a `code.github`
  scan of ten clones and a tiny one, every one of the 11 details read
  `{path: "ca.pem", ...}`, so the gap the verdict line named
  (`github:tiny`) could not be picked out. A labelled part now adds `part`,
  its label (the scan root's resource prefix, or `github:<repo>`), to each
  detail it publishes; `validate_coverage_summary`, and through it `shadowscan
  merge` and the plugin result check, accepts it as an optional non-empty
  string, so older reports load, and refuses any other value.
- **Diff reads a ledger over budget as incomplete, as merge does.** Merge
  and the plugin result check treat a stats ledger over budget or blinded as
  an incomplete run whatever its `incomplete` flag says, but
  `comparison._complete` read only the flag: a report whose `.mcp.json`
  finding was gone and whose ledger said `within_budget: false` was
  incomplete to `shadowscan merge` and still resolved the server in
  `shadowscan diff`. `_complete` now applies the same rule
  (`_ledger_refutes`); a ledger that is not one the scanner writes stays with
  the unread-content check, which already holds back every missing finding
  of that connector.
- **Strict accounting counts every link, as a budget of 0 does.**
  `strict_coverage` named one skipped link per root and counted only that
  one, and counted no special file past the first ten, so 50 dangling links
  and 15 FIFOs gave `incomplete_reasons` `{unresolved-link: 1,
  unscanned-input: 11}` under `--strict-coverage` and `{unresolved-link:
  50, unscanned-input: 15}` under `--max-coverage-gap 0`, although
  scanning.md calls the two one rule. The representative errors stay, and
  `ConnectorContext.count_incomplete` counts each further entry under its
  reason, as the budget's quiet ledger entries already did.

### Coverage gaps take one decision, judged per root and repository (October 17)

Three mechanisms decided when unread content leaves a scan incomplete, each
without knowing the others: #254's coverage budget, #255's discount of test
code while `include_tests` is off, and #258's `ci` profile declarations. Every
`code.filesystem` gap (and every gap in a `code.github` or `code.gitlab`
checkout) now takes one decision, in the order
[scan semantics](scanning.md#coverage-budget-and-strict-accounting) states:
strict accounting, credentials, declaration, discount, budget.

- **A budget of 0 is strict accounting.** #254 documented
  `--max-coverage-gap 0` as restoring the previous accounting ("0 fails on any
  gap"), but #255's discount checked only `strict_coverage`, so a binary or
  malformed test fixture still left a zero-budget scan complete, and the `ci`
  profile, which refused `strict_coverage`, accepted the zero budget and
  declared the gap: `--profile ci --max-coverage-gap 0` on a dangling
  `tests/` link exited 0. `strict_coverage` and a budget of 0 (the
  connector's `max_coverage_gap`, `options.max_coverage_gap` or
  `--max-coverage-gap`) are now one rule: no gap is discounted as test code,
  declared or tolerated, and the source of the 0 may be the nested
  connector's parent (`code.github`, `code.gitlab`), whose policy the nested
  connector now reads. The `ci` profile is refused with either setting, by
  `code.filesystem` and by the provider connectors at construction, before
  anything is fetched, and by `shadowscan code` as a usage error. The two
  settings differ only in where a gap the budget would charge is reported:
  `strict_coverage` as an error where it happens, a budget of 0 through the
  ledger, whose verdict is an error and counts each gap by its reason. The
  rest (the test-code gaps the default accounting discounts, and content it
  only notes) are diagnostics at the file under either setting, outside
  `stats.coverage`; the first wording said every gap stayed listed there.
  Under strict accounting the notes that become gaps (invalid structured
  syntax, a test file over the binder's budget) now end in `coverage
  incomplete` (`_strict_gap_warning`) instead of reading as notes while
  counted under `unparsed-input`. Strict accounting turns off the
  discount, not the credential-only read: the reader had decided both with
  one predicate, so a zero-budget scan of 61 product files and a binary
  `tests/fixtures/dump.txt` holding a GitHub token reported the gap and lost
  the key a default scan found, and `strict_coverage` had always done the
  same. `_read_source` now hands an undecodable file under a discounted test
  path to the credential-only read under every accounting
  (`_discounted_test_path`), which then records the gap: charged to the
  budget by default, an error under strict accounting.
- **Declared omissions count every entry and never a full-weight file.**
  `profile: ci` recorded one declared note per root for skipped links and
  returned early for the rest, so 40 dangling links under `tests/certs/`
  gave `declared_omissions` 1 where the default profile charged 40 entries
  to the budget. Every declared link is now counted
  (`ConnectorContext.count_declared_omissions`), with the one representative
  warning per root kept. The profile also declared gaps in files whose
  findings keep their full weight under any path: `tests/.mcp.json` with a
  syntax error or a NUL byte, `tests/CLAUDE.md` with a NUL, a structurally
  detected `tests/mcp.yaml` and a padded `docs/.mcp.json` all left a ci scan
  complete. `_declared_omission` now refuses a dedicated MCP name, a
  coding-agent instruction, rule or settings file, an agent manifest or card
  (`_full_weight_in_tests`) and a configuration the MCP parser found by its
  structure, so those gaps go to the budget or fail closed as in the default
  profile. A credential limit was never declared (it is an error under
  every profile); a test pins that.
- **No file left unread for credentials is declared.** The plan's rule that
  no credential is declared, discounted or budgeted without a read was first
  applied only to the credential quota. Under `--profile ci` a 3 MB
  `tests/fixtures/recorded.json` holding an Anthropic key was still declared
  ("unread for credentials; declared omission (profile ci)") and the scan
  stayed complete with the key never read, where main exited 3. With
  `scan_secrets` on, `_skipped_oversize` no longer declares such a file, and
  the reader's oversize gap and a notebook's unread saved outputs pass
  `unread_credentials` to `_declared_omission`, which then declares nothing:
  the gap is recorded as without the profile, an oversize file as one entry
  of the budget (a quarter in discounted test code, as #254 weighs any gap
  there) or blinding when its name selects configuration. With
  `scan_secrets` off the profile still declares an oversize documentation,
  example or generated file. An undecodable file under those paths is still
  declared without a credential-only read; that read belongs to the next
  change (coverage semantics, part B).
- **An unread configuration file is blinding however it goes unread.** An
  oversize `.mcp.json` was blinding, but `.mcp.json`, `.claude/settings.json`
  or `CLAUDE.md` linked to a file outside the tree, or a FIFO in its place,
  cost one entry of the budget, so 62 entries with an outside `.mcp.json`
  holding a server exited 0 where main exited 3, and a FIFO
  `tests/e2e/.mcp.json` cost a quarter while an oversize one exited 3. One
  predicate, `_unread_configuration` (the name selects the file as
  configuration, outside discounted test code), now decides the oversize
  reader, `_skip_link` for a dangling link or one to a single file, and
  `_skip_non_regular` for a FIFO, socket or device; a directory of such a
  name is walked and still costs one entry. Each blinding link kind keeps
  one representative error per root. A shared client name such as
  `config.json` is configuration by its content, which an unread file does
  not show, so it is blinding unread as it already was oversize.
- **Gap weight follows the connector's own test-path rule.** #254 weighed a
  gap at a quarter by its path segments alone (`CoverageGap.relevance`), so
  `include_tests: true`, which makes test code source everywhere else, still
  weighed `tests/` gaps at a quarter, while `testing/`, `e2e/`,
  `cassettes/` and test file names (`src/agent.test.ts`, `test_*.py`), which
  #255 and #258 treat as test code, weighed in full. `coverage_gap()` takes
  the recording connector's `relevance`; `code.filesystem` passes `low` for
  a vendored path, or a test path as `_is_test_path` names it while
  `include_tests` is off, and `high` otherwise. A caller that passes none
  keeps the segment rule, so other connectors are unchanged, and the
  published gap shape is the same. A file whose findings keep their full
  weight under a test path (`_full_weight_in_tests`) weighs in full: the
  first version weighed a FIFO or a directory named `tests/e2e/.mcp.json`
  at a quarter although the discount and the declaration both treated it
  as an MCP configuration, so the three rules now share
  `_discounted_test_path`. `__snapshots__/`, a test segment of
  `CoverageGap.relevance` that `_is_test_path` does not name, now weighs in
  full, as the scan's evidence there does.
- **Discounted test code is charged to the budget.** #255's discount wrote a
  plain warning that nothing counted, so 61 product files beside 200
  `tests/fixtures/agents*.yaml` with duplicate keys, or 200 binary
  `tests/fixtures/*.txt`, three quarters of the tree, scanned as complete
  with no `stats.coverage`, against #254's rule that a low-relevance gap is
  "weighted down, not ignored". `_discounted_gap` now charges the gap to the
  ledger as a partial gap at a quarter weight, its detail naming the
  discount, and a binary or undecodable fixture at a whole entry after the
  credential-only read. A few fixtures leave the scan complete and are
  listed; a seeded tree exhausts the budget. "A few" is about 8% of a
  root's entries for malformed fixtures that record one gap each (4% for a
  structured file with duplicate keys, which records two, and under 3% for
  such a `package.json`, three) but only about 2% for binary ones,
  which cost a whole entry each as the plan's full-weight clause requires:
  a 200-file service with four binary fixtures and one dangling certificate
  link, complete before, exits 3. The docs first said hundreds were needed;
  they now give both shares, and a test pins the binary case. Unparsed test
  source and a test file over the binder's budget stay warnings, as before
  #255, and an oversize fixture with `scan_secrets` off stays a counted
  warning.
- **The budget is judged per root and per repository.** The ledger summed a
  run: `code.github` and `code.gitlab` charged every checkout to one budget,
  and `code.filesystem` every root of `paths`. A repository of 20 files with
  60 dangling `services/` links (three quarters of it unread) beside one of
  5,000 files was tolerated, while 150 repositories each losing one entry of
  101 exited 3 against the run-wide 100-entry ceiling with a verdict that
  said "over the 2.0% budget" at 0.99%. An incremental scan, which runs each
  root alone, already judged per root, so the same tree could exit 3 with
  `--incremental` and 0 without it, or the reverse. `CoverageLedger` now
  keeps parts (`begin_part`, `ConnectorContext.begin_coverage_part`), each
  with its own examined count and allowance; `scan_tree` starts one per root,
  which covers a provider's nested checkout scan because it shares the outer
  ledger. The run is incomplete when any part is over its budget or any gap
  is blinding; the over-budget parts' gaps are counted under their reasons;
  the verdict line names each over-budget root or repository (up to five,
  then a count) and says whether the ratio or the ceiling bound; and the
  published summary combines the parts with `combine_coverage_summaries`, as
  the incremental split does, so its `allowance` is the sum of the parts' and
  a cached and an uncached run publish the same summary. This is the decided
  semantics: a multi-root scan is complete only if every root would be
  complete scanned alone. The provider connectors keep handing their policy
  to the nested connector, which now reads it (strict accounting above).
  The first combined summary cut the parts' details at 50 in part order, so
  `code big small` (3,000 files and 55 dangling links beside 10 files and
  3) listed only the big root's tolerated links while the verdict line
  named the small root, and read "58 weighted of 61.36 allowed,
  within_budget false" with nothing to say how the verdict divided.
  `combine_coverage_summaries` now lists the gaps of the parts that left the
  scan incomplete (over budget or blinded) first and publishes `parts`,
  `parts_over_budget` and `tolerated_gap_entries`, which
  `validate_coverage_summary` accepts as optional and checks against the
  summary's own counts. A single-file root of a multi-root `paths` scan
  counted no examined entry in the plain run (examined 0, allowance 0)
  while its incremental run, a connector run of its own, was floored at the
  one object it examined (examined 1, allowance 0.02); the walker now counts
  a single-file root as the entry it is (`_single_file_entry`), so the plain,
  uncached and cached runs publish the same summary. The test that claimed
  this compared only a plain run with a first incremental run, and its
  within-budget case recorded no gap; it now replays from the cache and
  compares a tolerated gap on every side.
- **Tolerated gaps reach the summary.** Both the budget and the ci profile
  let a scan with unread content exit 0, but only `declared_omissions`
  reached `summary`, the table banner and the exit-3 line; a default-profile
  scan that tolerated a dangling `tests/certs` link looked as if it had read
  everything. `summary.tolerated_gaps` is the sum of `gap_entries` over the
  runs within budget, shown in the banner and the exit-3 line beside the
  declared omissions. A root within its own budget beside one over it
  tolerated its gaps too: `tolerated_gap_entries()` read only the combined
  `within_budget` flag, so they reached neither `incomplete_reasons` nor
  `tolerated_gaps` (0 for a 204-entry root with three dangling links beside
  a 13-entry root with three, 3 for the large root alone). It now reads a
  combined summary's
  `tolerated_gap_entries`, and the over-budget verdict line counts them.
  Fleet merge recomputes it from the stats and reads a
  source whose summary disagrees as inconsistent completion evidence; a report
  without the field loads as before. `validate_coverage_summary` (used by
  fleet merge, dashboard, diff and the plugin result checks) refuses a
  summary within budget whose weighted gaps exceed its allowance, and the
  fleet reader and the plugin decoder mark stats incomplete when their
  ledger is over budget or blinded, so a source cannot present tolerated
  gaps its own arithmetic refutes.
- **Every condition the PRs added has its own reason.** #257's credential
  quota was recorded without a reason and classified from its text, path
  included: `other` in `src/keys.py`, `upstream-error` in `src/http/keys.py`
  and `access-denied` in `src/permissions/keys.py`. #256's unrecognized eBPF
  records were `other`, and a structured fixture whose duplicate keys made
  `code.filesystem` withhold its excerpts was `unscanned-input`. The quota is
  now `analysis-limit`, the eBPF unrecognized-record and malformed-field
  warnings `unparsed-input` and its list limit `analysis-limit`, a Git LFS
  pointer `unscanned-input`, a structured parse that failed on integrity
  `unparsed-input` (a resource or sanitizer limit stays
  `sanitization-limit`), lexical ambiguity and parser and validator issues
  `unparsed-input` unless their own text names a category, and the
  agent-manifest, agent-definition, MCP tool and re-export limits
  `analysis-limit`; a lockfile gap is classified from its fixed reason text
  alone. A refused PEP 263 cookie was already `unparsed-input` through the
  undecodable-content path; a test pins it.

### Review fixes: what diff holds back under the ci profile (October 17)

Fixes from a review of the `profile: ci` diff hold-back and project-root rule
below. Its blocker, a result replayed by `--incremental` that published no
declared omissions or coverage ledger so diff resolved a credential it had not
read, no longer reproduces since the cache stores both (653d076); an
end-to-end diff test over a replayed run now covers a declared omission and a
tolerated gap.

- **A labeled connector's unread content holds back its findings.** Findings
  carry the connector's name (`code.filesystem`), while `stats[].connector`
  is the configured id, the label when one is set
  (`github:acme/ops-agent`), so diff looked up the label's unread content
  under the name, found none and printed "1 resolved", exit 0, for a
  credential in a file the ci profile or the coverage budget had stopped
  reading. Each connector record now states the name its findings carry,
  `stats[].name`, and diff joins findings to records by it, locating
  declared omissions by that connector's path rule. A record without a name,
  from an older report, applies to every connector's findings and locates
  no declared omission behind a label, so it fails closed. The fleet reader
  keeps the name and rejects a malformed one; a plugin worker's record is
  checked for it.
- **A declared omission holds back only the projects it could hide.** A
  report counted declared omissions without saying where, so any declared
  omission anywhere held back every missing project finding: under the ci
  profile, which exists to make cassettes and oversize fixtures routine,
  removing an agent from `svc-a/` exited 3 because `svc-b/tests/big.json`
  was declared. Each declared omission's path is now listed in
  `stats[].declared_paths` (the first 200 of a connector; the count still
  covers every one), stored in incremental cache entries (format 6; older
  entries rescan) and carried through a multi-root job, and diff holds a
  missing project back only for a gap or declared omission inside its
  directory or above it, or for a declared omission its connector does not
  list (more than 200, a malformed list, an older report). Other missing
  findings keep the path-name rule. The fleet reader and the plugin worker
  check the list.
- **A template's manifest does not make it a deployable project.** The
  project-root rule counted a manifest by its file name, so a cookiecutter
  template's `templates/crew/{{cookiecutter.project_slug}}/pyproject.toml`,
  which never parses, made the template a project: its invalid TOML and
  JSON manifests and its unparsed `crew.py` were no longer declared and the
  ci profile exited 3, where it had declared all three. The same held for a
  `docs/package.json` that does not parse. For the profile's rule only, a
  project root with template syntax (`{{`, `{%`, `${`) in its path, or none
  of whose JSON or TOML manifests (`package.json`, `composer.json`,
  `pyproject.toml`, `Cargo.toml`, `Pipfile`) parses, is judged by the
  project around it; a manifest that cannot be read or is over a megabyte
  counts as parsing, so the doubt keeps the gap. Project findings and
  evidence weighting are unchanged.
- **The guides say which directories are projects.** The scanning, CI and
  production guides named only `demo/` and `examples/` projects as the
  exception to the profile's documentation and example paths. Any directory
  with a parsable manifest is one, including a documentation site that is
  its own package (`docs/package.json` in a Docusaurus layout): its blog
  posts, static assets and search index are its source, so their gaps exit
  3, while the `docs/` and `examples/` directories below it stay declared.
  The behaviour is intended and unchanged; the guides now say so.
- **What diff holds back is stated as narrowly as it is.** The comparison
  module, SECURITY.md and the production, CI and drift guides said a
  comparison never resolves a finding in content the current scan declared
  or tolerated as unread. A gap the default profile discounts in test code
  (`_discounted_gap`: a test notebook or fixture that does not parse while
  `include_tests` is false) is a warning that leaves the scan complete and
  is counted neither in `declared_omissions` nor in `stats.coverage`, so a
  project finding that came only from `tests/fixtures/agent.ipynb` still
  resolved once that notebook stopped parsing. The wording now names the
  two records diff reads, and says that a discounted test gap is in
  neither and does not hold a finding back. The code is unchanged here:
  separate work moves discounted gaps into the coverage ledger, which diff
  already reads, and the hold-back then follows without a change to diff.

### Engine review fixes: surrendered findings, explicit deadlines, the cache key and split jobs (October 17)

- The incremental cache is keyed on the coverage gap budget it was judged
  under. The engine hands each connector the scan-wide `max_coverage_gap`
  as a private key, outside the connector configuration the cache
  fingerprint hashes, so a tree that was complete under the default 2% and
  cached was answered from that entry when rerun with `max_coverage_gap: 0`
  and reported complete, while the same run without the cache exits 3. The
  fingerprint now includes the budget. Entries also store the sanitized
  coverage ledger and the declared omission count, which every replay used
  to drop (a cached `ci`-profile scan read as one that had declared
  nothing), and a load refuses either when it is not what the scanner
  publishes. The entry format moves to 5, so every existing entry, keyed or
  unkeyed, misses once after upgrading (`RELEASE_NOTES.md`,
  `docs/production-migrations.md`).
- An explicit 120-second connector timeout is honoured. The engine scaled a
  job's deadline whenever `connector_timeout_seconds` equalled 120, so
  `--connector-timeout-seconds 120`, the same YAML option or
  `ScanConfig(connector_timeout_seconds=120.0)` was raised for a large tree
  like the unset default. The unset default is now
  `config.DEFAULT_CONNECTOR_TIMEOUT`, a 120.0 of its own float subtype that
  the dataclass, the YAML loader and the legacy null use;
  `connector_timeout_is_default()` tells it apart and only it is scaled.
  Readers of the option still see a float equal to 120.
- A job split into repository roots carries every root's account. The
  incremental split rebuilt one `ScanStats` from the roots and dropped
  `coverage`, `incomplete_reasons` and `declared_omissions`, so a multi-root
  scan published no gap ledger, an incomplete one gave no reason and a
  `ci`-profile one read as having declared nothing; the job now publishes
  the roots' combined ledger (`coverage.combine_coverage_summaries`), the
  summed reasons and the summed omissions. Each root is still judged
  against its own budget. The job state kept only the last root's findings
  list for an expiry, and a root reused from the cache registered none, so
  an overrun in the last root reported only that root's findings; every
  root's list is now kept, cache hits included.
- An overrunning thread-mode plugin could still end a scan with exit 0 and
  no report. The engine prepares an expired job's surrendered findings on
  the supervisor thread, outside the worker's isolation, and caught only
  `Exception` there: an object the plugin put into a finding it had already
  yielded, raising `SystemExit(0)` from `__deepcopy__` or `__str__`, or a
  metaclass property behind its registry-record declarations, escaped
  `Engine.run`. Both are now the worker's failure, as everywhere else plugin
  code runs: the finding is omitted with a counted error, a class that
  cannot say what it declares keeps no registry record, the connector stays
  incomplete and the scan exits 3 with its report. A KeyboardInterrupt still
  ends the scan. Regression-tested through the command line.
- Surrendering an expired job's findings is cheap and bounded. Each was
  copied through `to_dict`/`from_dict`, which sanitized its evidence and the
  finding again in full on the supervisor thread: about 27 ms per finding,
  5.5 s for 200, during which no other job's deadline was enforced.
  `models.detached_copy` now reads only the plain data a sanitizer pass
  leaves (exact model objects and enums, dicts with text keys, lists,
  tuples, text, numbers and the scalars the sanitizer keeps), within the
  sanitizer's node and nesting limits, and never runs code a value's own
  class defines; anything else is omitted as "not readable". The copy keeps
  the worker's verified-clean marker, so a finding nobody changed costs a
  digest check, and `reattribute` keeps an id that is already the derived
  text, so a plugin's own findings do too: about 0.5 ms each, built-in or
  plugin. The loop stops after 5 seconds per expired job; the findings left
  are omitted with a counted error and the job stays incomplete.
- A timed-out connector now counts `timeout` in `stats[].incomplete_reasons`
  and `summary.incomplete_reasons`, as does a connector left unstarted
  because timed-out calls hold every worker slot and each omission of
  findings the overrun produced. The supervisor writes these stats itself,
  so they named no reason, and the command line explained an exit 3 from a
  timeout, even one that surrendered findings, as "a connector was skipped
  or recorded no diagnostic". It now says `timeout 1`.
- `ScanConfig(connector_timeout=60, connector_timeout_seconds=120)` is
  rejected as giving both, like any other pair of values and like both keys
  in a configuration file. The constructor compared the canonical value
  with 120, so an explicit 120, which the engine now honours unscaled, was
  silently replaced by the deprecated alias's value.
- The sample configurations no longer set `connector_timeout_seconds: 120`.
  README's full reference, the getting-started page, the production guide
  and the plugin example all did, and since an explicit value is honoured
  unchanged, a configuration copied from them gave a large repository a
  fixed 120 seconds where the unset default would have been raised. The two
  references show the key commented out; `docs/scanning.md` (connector
  deadlines), the architecture options table, the production guide and the
  API pages say that leaving the option out and setting it differ. A
  consistency test fails on any code block of the live documentation or
  example file that sets the default value as a key or flag.

### Review fixes: connector correctness, CI check names, benchmark framing (October 17)

- `gateway.otel` no longer loses resource attributes from nested OTLP
  exports: `service.name` reaches the finding again, so distinct callers no
  longer merge into one `unknown-service` finding. Regression-tested.
- `endpoint.ebpf` reads the native Tetragon, Falco, Tracee and Hubble export
  shapes it always claimed (snake_case and lowerCamelCase), keeps the flat
  record shape, and reports one warning that marks the scan incomplete when
  records match no known shape, so an unread export cannot look like a clean
  scan. Fixtures cover all four producers, and the Falco example rule also
  emits `fd.sip.name` so AI host names reach the alert. Review found that
  the native readers still read a wrong-typed field as empty in silence (a
  Tetragon `process` given as a string, `args` given as a map, a list in
  place of a `sock_arg`, a Hubble `l4` list, Tracee `args` as text) and cut
  `args` and `destination_names` at 100 entries without a word, so a
  socket in entry 101 went unread on a complete scan, while the flat
  shape's malformed `process` already marked the scan incomplete. Each
  reader now notes the fields it could not read, and the connector records
  one fixed-text warning per producer for malformed fields and one for the
  list limit, either of which marks the scan incomplete; the event is still
  scored on what was read. Negative tests cover each producer. A second
  review found the flat shape outside this accounting: a flat record read
  a `destination`, `url` or port given as a list or map as empty in
  silence, so a connection was hidden on a complete scan. Flat records
  now go through the same type checks and report one fixed-text warning,
  `malformed flat event fields`, which also replaces the flat shape's
  separate `malformed process` warning; a JSON boolean is no longer read
  as a port (`bool` subclasses `int`), and a Tracee `remote_addr` or
  `struct sockaddr*` argument whose value is not a map is malformed
  instead of skipped. Regression-tested per field. The Tetragon and Tracee
  readers also read only the first socket argument, so events from the
  repository's own example TracingPolicy, which hooks `tcp_v4_connect`
  with `[sock, sockaddr]`, lost their destination: at kprobe entry the
  socket has no `daddr` or `dport`, and the `sockaddr_arg` holding the
  address and port was never read. Every socket argument (up to the list
  limit) is now read and scored; a fixture in the example policy's shape
  is checked against the policy file. The Hubble
  reader also scored only the first `destination_names` entry, so a
  CDN-shared address listed as `static.example.com` before
  `api.openai.com` gave no finding; every name (up to the list limit) is
  now scored on its own. Regression-tested with the AI host second and
  third. A flat record that also carried a key a native reader claims (a
  string `eventName` with `processName` is taken by the Tracee reader,
  `rule` with an `output_fields` map by the Falco reader) lost its
  top-level destination in silence, because that reader found none and
  the flat fields were never read. When the native reader finds no
  destination and the record has flat destination or port fields, it is
  now scored on those, with the native reading filling the process and
  pod; a Falco alert's own `hostname` (the sensor) and a bare Hubble
  flow's `destination` endpoint do not count as flat fields.
  Regression-tested with both shapes, and with a Falco alert from a node
  named after a runtime that stays unreported. Scoring every Hubble name
  also widened the AI host pattern's reach: it took any `*.googleapis.com`
  host, and a Google front-end address resolves from many, so a flow
  listing `www.google.com` and `fonts.googleapis.com` was tagged
  `llm-egress`. The pattern now takes only the Google AI APIs the bundled
  signatures name (`generativelanguage`, `aiplatform`, `discoveryengine`,
  `dialogflow`, with regional prefixes); the same pattern serves the MCP
  tool-poisoning host rule, which therefore no longer counts other
  `googleapis.com` names as a model provider host (a URL in a description
  still raises the tag). Regression-tested with non-AI
  Google flows that stay untagged and AI API names that stay egress. A
  further review found the narrowed pattern too narrow: it missed the
  mutual-TLS endpoints Google client libraries use with a client
  certificate (`aiplatform.mtls.googleapis.com`,
  `us-central1-aiplatform.mtls.googleapis.com`,
  `generativelanguage.mtls.googleapis.com`) and the Document AI, Contact
  Center AI and Speech hosts the GCP connector's `AI_SERVICES` counts as
  AI, all tagged `llm-egress` before. The Google hosts are now derived
  from `AI_SERVICES`, each with a regional prefix and as its `mtls`
  endpoint, and matched from the start of a label, which also keeps a
  64 KiB hostile MCP description cheaper than before. Regression-tested
  with each missed host; the guide is checked to name every service. The
  same review found the flat fall-back too narrow and too wide. It ran
  only when the native reader found neither a destination nor a port, so
  a top-level `url` beside a Tracee socket with an empty `sin_addr`, or
  beside a non-AI Falco `fd.sip`, was still lost on a complete scan; once
  it ran, a Falco alert's own `hostname` was read as a destination, so a
  node named `ollama-node-1` made the alert egress; and the flat reader
  scored only the first of `port` and `destination_port`. A record with
  native and flat fields is now read both ways and scored on every
  destination and port either reading finds, the producer's own keys are
  never read as flat fields (which also stops a bare Hubble flow's
  `destination` endpoint from counting as a malformed flat field), and
  every flat port is scored. Regression-tested with each record.
- `endpoint.host` reports a host inventory row only when its name or path
  matches an AI product signature, its whole name is a known AI product or
  local model runtime, or its `type`/`category` names an AI category;
  filtered rows add one informational note instead of becoming
  0.7-confidence findings. The whole-name rule came from review: the local
  runtime signatures have no display-name signal, so an osquery `apps` row
  such as `LM Studio.app`, or a bare `Ollama`, `GPT4All`, `llama-server`,
  `Jan` or `Msty` row without a category, was filtered as ordinary software
  on a scan that stayed complete. The row's name, path file name or process
  is now compared, without `.app`/`.exe` or a trailing version, with the
  product names of the bundled provider and coding-agent signatures and the
  endpoint catalog's local runtimes and AI command-line tools.
  Regression-tested with each runtime and with Slack, Chrome, Zoom and Make
  rows that stay filtered. A second review found the rule still filtered
  `Open WebUI`, `AnythingLLM`, `litellm` and model store paths such as
  `~/.ollama/models` and `~/.cache/lm-studio/models`: platform signatures
  were excluded wholesale to keep Make out, and the catalog's model store
  paths were never consulted. Platform signatures now contribute their
  product names, including each product a signature lists in its display
  name ("Self-hosted chat UIs (Open WebUI, LibreChat, AnythingLLM, ...)");
  an explicit catalog list of ambiguous names (Make, Rivet) keeps those out
  by name instead; and a path that is or lies in a catalog model store is
  reported. Regression-tested with each of those rows. The same review
  found new false positives from the whole-name rule: Homebrew's `goose`
  (the pressly/goose database migration tool), `/usr/bin/lms`, a bare
  `Jan`, common words such as `Continue`, `Replicate` and `Cohere`, and,
  because any trailing number was stripped as a version, `Codex 3` and
  `Jan 2024`. A trailing version is now a dotted number or one marked `v`
  or `version`, and the catalog's ambiguous names count only in context:
  as an `.app`/`.exe` application, or on a path inside an application
  bundle or dot-directory named after a product
  (`/Applications/Goose.app/...`, `~/.lmstudio/bin/lms`). A plain
  directory, such as a user named `claude`, is no context.
  Regression-tested both ways. A third review found that this context
  took any `.app` or `.exe` name or dot-directory named after an ambiguous
  product, so GNU make on Windows (`make.exe` as a process or under
  Chocolatey, MSYS2 or GnuWin32), `Make.app`, a `.make` directory,
  `Cohere.exe` and `Replicate.app` were reported again. The catalog now
  lists each ambiguous name's own context, the bundles, executables and
  directories of its product (`Jan.exe`, `Goose.app`, `.continue`, ...),
  and none for Make (Integromat), Replicate and Cohere, which have no
  desktop application; a Windows `goose.exe` is left out because
  pressly/goose builds one too. Regression-tested with each of those rows
  and with Ollama, LM Studio, Open WebUI and AnythingLLM applications and
  executables that stay reported. The same review found the older LM
  Studio CLI path `~/.cache/lm-studio/bin/lms` filtered since `lms` needed
  context: `.cache` names no product and `lm-studio` is no dot-directory,
  although the catalog lists `.cache/lm-studio` as LM Studio's directory.
  `lms` now counts in every directory the catalog lists for LM Studio;
  regression-tested, with a check that ties that context to the catalog.
  Model stores had the same weakness as product names: a store matched as
  any run of path components, and the Jan store is the plain `jan/models`,
  so `/srv/app/jan/models/user.rb` and a user jan's `/home/jan/models`
  were reported as local model stores. A store now counts below a home
  directory (`~`, `$HOME`, `/home/<user>`, `/Users/<user>`,
  `C:\Users\<user>`, `/root`), where the catalog lists it, and elsewhere
  only with its own layout below it (Ollama `manifests` or `blobs`, a
  Hugging Face `models--` directory, a model file), so a service account's
  or shared volume's store is still reported. Regression-tested both ways,
  with every catalog store below each kind of home directory. The review
  also measured a hostile row at about 20 times its former cost: values
  were read up to 1,024 characters instead of 160 and keyed whole, through
  a trailing-version pattern whose `\s+` restarted at every space of a run
  (quadratic in the run's length), and every path component was keyed. A
  component longer than 160 characters is now keyed as no product, the
  version pattern starts only where a whitespace run starts (linear, with
  the same results), and each value is split once with each directory
  keyed at most once. A step-count test bounds the text the version
  pattern reads per hostile row, and another checks that it cannot start
  inside a run.
- These three connector changes alter which findings a scan reports, and
  `gateway.otel` findings from nested exports get new ids; the
  [connector correctness migration note](production-migrations.md#october-17-connector-correctness-migration-unreleased)
  says what moves and to rebuild comparison baselines.
- The CI coverage leg is selected by a job-level environment expression
  instead of a matrix `include` key, so its check reports as `test (3.11)` —
  the name the branch rulesets require — rather than `test (3.11, true)`,
  and the required status can actually gate merges. The repository-policy
  test pins the new mechanism.
- The README carries its benchmark fine print in the results themselves: the
  discovery row names the pre-tuning F1 beside the post-tuning, in-sample
  figure, and the weakest per-surface precisions (identity and SaaS in the
  2026-10-11 cases run) are stated next to the headline numbers.
- Documentation restructuring: `docs/production.md` is the rollout guide
  again, with the per-change migration notes in
  `docs/production-migrations.md` and the dated candidate log in
  `docs/history/production-change-history.md`. The branch also condensed
  this log into a journal under `docs/history/`; the integration with #258
  keeps #258's form instead (this engineering log, and a `CHANGELOG.md`
  that names each change in a line), so there is one detailed log.
- Docs publication: after GitHub Pages is configured for Actions, the
  repository variable `DOCS_PUBLISH` set to `true` republishes the site on
  every docs push to `main`, so publication no longer needs a manual
  dispatch per update; the one-off `publish=true` dispatch still works and
  the policy test pins both explicit paths.
- Offline cloud input is stated loudly: the cloud connector guide and the
  unsupported-`_kind` warning both say that `cloud.aws`, `cloud.gcp`,
  `cloud.azure` and `cloud.oci` replay `--dump-records` exports, not a
  provider's native log, so a CloudTrail file explains itself instead of
  producing an incomplete scan with a cryptic warning.
- Python 3.14 is supported: `requires-python` allows it, CI tests it on
  Linux and macOS, and the hash locks already resolve on it. A PEP 263
  cookie that Python 3.14's own `detect_encoding` refuses (`punycode`,
  UTF-32) stays a coverage gap when it names a slow codec or one that does
  not read ASCII as ASCII — the scanned estate's interpreter may still
  honor it — instead of falling into the keep-default branch and being
  silently analyzed; a bare `utf-16`/`utf-32` cookie is now a gap on every
  interpreter for the same reason. That gap is undecodable content, so it
  follows that rule: blinding in product code, and in test code whose
  evidence is discounted read for credentials and charged to the coverage
  budget, unless `profile: ci` declares the path. Regression tests force the refusal path
  so the pre-3.14 CI legs exercise it too.

### Review fixes: credential precision, the ci profile, incomplete reasons, the ownership move and plugin environments (October 17)

Five fixes from an external review of `main` at 8c72467, which scanned five
public repositories with the tool and read the committed benchmark metrics.

- **Assigned names and translated placeholders are no longer credentials.**
  Every one of the 70 "Hard-coded credential" findings the review's scans of
  three public SDK repositories produced was a false positive:
  `include_tracing_api_key=include_tracing_api_key`, `self.api_key =
  resolved_api_key`, `ENV_API_KEY = "ANTHROPIC_API_KEY"` and Portuguese
  tutorial placeholders such as `OPENAI_API_KEY=sua_chave_openai`, each at
  confidence 0.8 to 1.0. The generic assigned-credential rule
  (`heuristic.inline-credential`) accepts an unquoted value because `.env`
  and shell assignments carry none, and Shannon entropy at 3 bits per
  character does not tell a token from an identifier. The rule now requires
  a token's shape: a value without digits must mix cases evenly, a value
  with digits must not be identifier-shaped (separated by `_` or `.` into
  identifier segments, letters all one case, few digits). A snake_case
  password with a year in it is given up for that in source code. In an
  env or credential file (`.env`, `.env.local`, `prod.env`, `.netrc` and the
  other tool credential files, but not a template such as `.env.example`,
  `.env.sample`, `.env.template` or `.env.dist`) a PASSWORD or CREDENTIAL
  value cannot name another variable, so these shape rules, and the
  CONSTANT_CASE label rule, apply there only to token names (`API_KEY`,
  `ACCESS_TOKEN`, `CLIENT_SECRET`): `POSTGRES_PASSWORD=TrustNoOneEverAgain`
  and `DB_PASSWORD=summer_vacation_beach_2024` in `.env` are reported. A
  value built like a name whose words are all label vocabulary, function
  words or the name's, and whose numbers are the name's
  (`KEYCLOAK_ADMIN_PASSWORD=KeycloakAdminPassword`,
  `svc1_local_dev_password`), is a label there (as narrowed by the credential
  review fixes above; one such word had been enough), and placeholders stay
  unreported. The first version of this rule applied to every text that is
  not source code, so env templates, Helm values, compose files, workflows,
  `.properties` files and Markdown reported setting names and placeholders
  in a password's place (`adminPassword: useExistingSecretKey`,
  `spring.datasource.password=springDatasourcePassword`), and a
  `.env.example` of eight development labels exited 3; 90d22be reported
  none of them, and neither does this branch now. Vendor-prefixed hex
  tokens keep their digit density and still match. Placeholder recognition
  covers the languages documentation is translated into (a possessive
  followed by words, and the placeholder words of four letters or more in
  Portuguese, Spanish, French, German, Italian, Dutch, Indonesian and
  Turkish). The possessive needs a separator and another word after it, and a
  translated word counts only as a whole word between separators. Without the
  separator, every letters-only token beginning `Su`, `Ta`, `Je`, `Ton` or
  `Vos` was a placeholder, which `saas.generic` then did not learn as a
  credential and copied raw from other columns into its findings; matched
  across case boundaries and inside runs of letters, the short words (`hier`,
  `aqui`, `kunci`) more than doubled how often a random key was taken for
  one. The rate is back to that of the English rules alone, about one in
  eleven thousand random 32-character base62 keys in a seeded simulation. A
  credential under a documentation, example or generated path is reported
  with that context's weight, confidence cap and `docs-only`,
  `example-code-only` or `generated-code-only` tag, as project evidence found
  there already was. Regression tests carry the field-scan lines; the
  evaluation corpora are unchanged. The committed 2026-10-11 ShadowBench
  cases run (in-scope precision 77.9%, decoy specificity 63.0%) was not
  re-run: a later run on it is in-sample, as the README's Benchmarks section
  says.
- **`profile: ci` and `incomplete_reasons`.** Four of the five scanned
  repositories exited 3 for a gap in content a source gate does not read: a
  1.2 MB JSON fixture, a dangling test certificate link, a cassette the
  credential pass timed out on. Fail closed stays the default. `profile: ci`
  (`--profile ci`) declares such gaps under test, fixture, documentation,
  example and generated paths as omissions: warnings that name the file,
  end in "declared omission (profile ci)", are counted in the new
  `declared_omissions` stat and leave the scan complete; every other gap, a
  connector deadline, a `max_files` limit and a triage scan still exit 3,
  and the profile is rejected with `strict_coverage`. Documentation and
  example directories are judged below the file's project root, as
  `negative_context` judges evidence: a project under `demo/` or
  `examples/svc/` with its own manifest is reported at full weight, so a NUL
  byte hiding its tool code still exits 3 under the profile (a review found
  it declared). A directory link takes the project of the directory that
  lists it. `shadowscan diff` no longer reads such an omission as a
  resolution: a review's baseline with a credential in `docs/setup.md`,
  compared with a `--profile ci` scan in which that file had grown past
  `max_file_size`, printed "1 resolved" and exited 0 with the key still in
  the file. A missing finding observed under a path the profile declares in
  (while the current report counts declared omissions), or in a gap path
  that #254's `stats.coverage` lists as tolerated, now makes the comparison
  incomplete (exit 3, the finding `unknown`); a project finding is held back
  by a gap in its directory and by any declared omission, and a report that
  cannot say where its connector stopped reading holds back every missing
  finding of that connector. Findings missing from content the scan read
  still resolve. Every diagnostic that
  leaves a scan incomplete is counted by reason category in
  `stats[].incomplete_reasons` and `summary.incomplete_reasons`
  (`oversize-file`, `unresolved-link`, `unparsed-input`,
  `sanitization-limit`, `timeout`, `access-denied`, `upstream-error`,
  `analysis-limit`, `subset-scan`, `unscanned-input`, `other`), named on
  stderr with the exit 3 and shown in the table banner; the fleet reader
  validates the new fields and loads older reports unchanged. A reason key
  that a merged report or a plugin worker supplies outside these categories
  is counted as `other`, and the banner escapes the reason text like other
  report text, so a crafted report cannot send terminal control sequences
  (a window title, a screen clear) through `shadowscan merge`. The classifier
  no longer reads the scanned path: `code.filesystem` names the reason of
  its oversize, undecodable, link, non-regular and analysis-limit gaps and
  classifies any other gap with its path left out, so a NUL byte in
  `src/http_client.py` is `unparsed-input`, not `upstream-error` (and the
  canonical undecodable-content case is `unparsed-input`, not `other`).
  Each coverage gap keeps its reason, published in
  `stats[].coverage.details[].reason` and used when an over-budget verdict
  counts the partial gaps. The example GitHub Action passes `--profile ci`.
- **ADR-005, first move.** The ownership group of `FilesystemConnector`
  (`_git_info`, CODEOWNERS reading and matching, their caches and budgets)
  is `OwnershipResolver` in `code/ownership.py`; the connector calls
  `self.ownership`, nothing forwards the old names, and the eight test
  modules that patched or called them address the resolver. Every name
  importable from `filesystem.py` before the move still is, as the ADR's
  2026-10-15 status requires: the moved constants, and the ten names it
  imported only for the moved methods (`subprocess`, the bounded git
  metadata helpers, `link_in_path`, `open_confined_file`,
  `parse_timestamp`), are re-exported as their defining modules' objects.
  Behaviour is unchanged (same evaluation counts, identical offline demo
  findings apart from timestamps and root-derived ids). The class is 121
  methods, down from 127.
- **The changelog is a changelog again.** This file holds the detailed
  engineering log, one dated entry per change, as `CHANGELOG.md` did;
  `CHANGELOG.md` is now a summary that names each change in a line and
  points here. The October 16 entry above is corrected: it said #251's
  banner pills and raster chart were not carried, and #251 carried them.
  The README's `mcp-registry snapshot --url` default is corrected to
  `https://registry.modelcontextprotocol.io` (it said Smithery; the code
  never defaulted to it).
- **Plugin workers do not inherit credentials.** A process-mode plugin
  worker inherited the scanner's whole environment, so an approved
  third-party connector could read `GITHUB_TOKEN`, cloud credentials and
  every other secret the operator had exported for the built-in connectors.
  The worker is now started without, and removes again from its own
  environment before the plugin is imported, every variable whose name ends
  in `TOKEN`, `ACCESSTOKEN`, `SECRET`, `KEY`, `APIKEY`, `PASSWORD`,
  `PASSWD`, `PASSPHRASE`, `CREDENTIALS`, `CREDENTIAL`, `PAT`, `JWT` or
  `CONNECTION_STRING` (after an underscore, or as the whole name, ignoring
  a version such as `_V2` after it), the CI and cloud SDK variables that
  carry a credential, the file holding one or a session
  (`AWS_ACCESS_KEY_ID`, `AWS_WEB_IDENTITY_TOKEN_FILE`,
  `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`, `AZURE_CLIENT_CERTIFICATE_PATH`,
  `AZURE_FEDERATED_TOKEN_FILE`, `IDENTITY_HEADER`,
  `GOOGLE_APPLICATION_CREDENTIALS`, `GOOGLE_GHA_CREDS_PATH`,
  `CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE`,
  `CLOUDSDK_AUTH_ACCESS_TOKEN_FILE`, the OCI key and security-token files,
  `BW_SESSION`, `OP_SESSION_*`, `DATABASE_URL`, `DATABASE_DSN`) and every
  `*_URL`, `*_URI` or `*_DSN` whose value carries a user or password (an
  `@` after `://`), except the
  names the new `options.plugin_env` lists for a plugin that reads its own
  credential from the environment (exact names, at most 64, validated);
  configuration selectors such as `AWS_PROFILE` and `KUBECONFIG`, `PATH`,
  `HOME`, locale, temporary-directory, proxy and CA settings stay, and a
  value the configuration interpolates with `${VAR}` is expanded by the
  scanner before the worker starts. The scanner's own environment is not
  changed, and thread-mode plugins, which share it, are unaffected, as
  before. The worker's result validation also checks the two statistics
  fields the ci profile added. A follow-up review found the worker's removal
  alone left every withheld value in the environment the worker was started
  with, which `del os.environ[...]` does not change: a plugin read them from
  `/proc/self/environ`. The spawn now leaves them, and the identity key even
  when `plugin_env` names it, out of the environment it hands on; the
  worker's own removal stays as a second line. A first version did this
  with `os.unsetenv` for the duration of `Process.start()` (0.9 to 1.8
  seconds with the built-in signatures, while the pickled configuration is
  written to the child), which changed the whole scanner's environment: a
  program another thread started meanwhile with the inherited environment
  (botocore's `credential_process` helpers such as aws-vault or 1Password
  `op`, a thread-mode plugin's helper) started without the credentials it
  needed, and with `PYTHONSAFEPATH=1`. The worker is now launched through
  its own spawn launcher (`_WorkerPopen`, CPython 3.13's
  `popen_spawn_posix` launch with `subprocess.Popen(env=...)` in place of
  `spawnv_passfds`), which hands it an explicit environment, built from a
  copy of `os.environ` without the withheld variables and with
  `PYTHONSAFEPATH=1`; nothing in the scanner's environment changes at any
  point, so there is no window and no lock. The worker no longer receives a
  descriptor of the scanner's multiprocessing resource tracker, which would
  have been started with the scanner's environment and working directory;
  a plugin that creates multiprocessing semaphores starts its own.
  `test_program_another_thread_starts_during_a_plugin_spawn_keeps_its_environment`
  starts a program on another thread while the spawn pickles the worker,
  inside `Process.start()`: before, it saw no token, no identity key and
  `PYTHONSAFEPATH=1`; now it sees the scanner's environment. A worker
  still runs as the scanner's user and can read the scanner's environment from
  `/proc/<scanner pid>/environ`: withholding keeps credentials from a plugin
  that does not look for them, not from one that does, and SECURITY.md, the
  production guide and the plugin contract now say so instead of saying a
  worker "does not inherit" them. They now name the route, the parent's
  `/proc/<ppid>/environ`, which holds every withheld variable and the
  identity key, and recommend passing credentials through files or a
  secrets manager (out of the environment, though not out of a same-user
  plugin's reach) and running an untrusted plugin under a separate user or
  container in a job that does not hold the credential. The same review
  found the first list missed common CI and cloud credentials: `SYSTEM_ACCESSTOKEN` (the Azure
  Pipelines job token), `AZURE_DEVOPS_EXT_PAT`, `SENDGRID_APIKEY`, Azure
  connection strings, GitLab's `CI_JOB_JWT_V2`, the Azure managed-identity
  `IDENTITY_HEADER`, the credential-file variables google-github-actions/auth
  exports beside `GOOGLE_APPLICATION_CREDENTIALS`, the ECS
  container-credentials token file and connection URLs such as `REDIS_URL`
  or `MONGODB_URI` that carry a password; the list above now includes them.
  `SESSION` is not a suffix (it would withhold the desktop's
  `DESKTOP_SESSION`), and a bare number after a word does not count, since
  `GIT_CONFIG_KEY_0` names the Git setting `GIT_CONFIG_COUNT` requires.
  A further review found tooling credentials whose credential word is a
  prefix, has no underscore before it, or is missing from the name:
  Terraform's `TF_TOKEN_<host>`, npm's `npm_config__authToken`,
  `NPM_CONFIG__AUTH` and per-registry `:_authToken`, `NGROK_AUTHTOKEN`,
  GitLab's `DOCKER_AUTH_CONFIG`, `COMPOSER_AUTH`, Bundler's
  `BUNDLE_<HOST>__COM`, Azure App Service's `CUSTOMCONNSTR_*`,
  `SQLAZURECONNSTR_*`, `SQLCONNSTR_*`, `MYSQLCONNSTR_*`,
  `POSTGRESQLCONNSTR_*` and the other connection-string types, .NET's
  `ConnectionStrings__*`, and webhook URLs (`SLACK_WEBHOOK_URL`), which
  carry their secret in the path. Names ending in `AUTHTOKEN`, `WEBHOOK` or
  `WEBHOOK_URL`, those prefixes, any `BUNDLE_` name with `__` (which also
  takes the gem-scoped `BUNDLE_BUILD__<gem>` and `BUNDLE_LOCAL__<gem>`) and
  the two exact names are now withheld; `PATH`, `HOME`, `LANG`, `SHELL`,
  `TMPDIR`, `DOCKER_CONFIG`, `DOCKER_HOST`, `NPM_CONFIG_REGISTRY`,
  `BUNDLE_GEMFILE`, `BUNDLE_PATH`, `TF_LOG` and `COMPOSER_HOME` stay.
- **Not carried: redaction patterns on the `regex` module.** The review
  suggested giving the credential redaction patterns a match timeout
  through the `regex` module, as the code connectors' patterns have, so a
  pattern regression could not hold a worker past the connector deadline.
  Measured on the redaction performance suite's hostile shapes, `regex`
  (2026.9.10, `re`-compatible mode) runs these patterns 2 to 15 times
  slower than stdlib `re` (`Bearer a--` followed by 100,000 `a_` pairs: 0.6
  s against 9.0 s; the whole set 6.8 s against 25.3 s), slow enough to fail
  the suite's own linear-time bounds and to be paid by every excerpt,
  diagnostic and export of every scan. The patterns' possessive quantifiers
  and atomic groups, the work and nesting budgets and
  `tests/unit/test_redaction_performance.py` remain the defence against a
  regression; an abandoned worker is already bounded by the job deadline.

### Credential quota disclosed, Bedrock owner tags collected, repeated tags count once (October 17)

- `code.filesystem`: the credential matcher keeps at most five matches per
  credential format and file (`MAX_SECRETS_PER_SIGNAL`). A file holding more
  used to be reported with `count: 5`, no diagnostic and a complete scan, so a
  clean-looking report under-counted the one finding whose count is read
  literally. The matcher now looks one match past the quota when the caller
  asks (`match_secrets(..., limited=)`), and the connector records
  `<file>: credential quota limit reached: more than 5 credentials matched
  <format>; credential evidence incomplete` (exit 3, passed to `ctx.error`
  with `reason="analysis-limit"`, so `incomplete_reasons` counts it as an
  analysis limit whatever words the path holds) and sets
  `metadata.secrets_limited` on the finding. No candidate cap remains
  (d6ebf33 removed #255's 25-candidate read), so this is the only message.
  Callers that report no credentials (connector blob scans) are unchanged.
  Only matches the connector would report count toward the quota and the
  look past it: a reference, a short `sk-` look-alike that is not random or
  that a counted assignment covers, and a documentation placeholder (the
  connector passes `placeholder_reason` as `match_secrets(...,
  placeholder=)`, judged on the credential a match stands for) take no
  place. A `.env.example` of sample keys is therefore complete, with up to
  five samples per format kept as example evidence.
- `code.filesystem`: the tool credential files `.npmrc`, `.yarnrc`, `.netrc`,
  `_netrc`, `.pypirc`, `.git-credentials`, `.boto` and `.s3cfg` are read by
  name (`CREDENTIAL_FILE_NAMES`). They have no suffix, so no rule selected
  them and a provider key committed in one was neither reported nor disclosed
  as unread. The connector guide now says what makes a file analyzable and
  that an unselected name (`*.jsonl`, `*.bak`, `*.j2`) is never opened.
- `code.filesystem`: those files are read by the credential pass alone
  (`_scan_credential_file`), with no excerpt cut from them. As first
  integrated, selecting them by name ran every analysis pass over them, and
  `sanitize_text` did not read netrc's `password <value>`, so the one-line
  entry `machine api.openai.com login deploy password <pw>` became
  framework-usage evidence (`domain:provider.openai`) whose snippet was the
  whole line: `shadowscan code` exited 0 with the password in the JSON,
  SARIF, HTML, Markdown and OCSF reports, as for `_netrc` (read before as a
  file without a suffix) and `.NETRC`. A provider key in a login field also
  put the password beside it into the credential finding's own snippet.
  Their credential findings, counts and formats are unchanged, with empty
  snippets; a netrc host is no longer LLM-usage evidence; and with
  `scan_secrets: false` or `--triage` the files are not opened, so an
  oversize one is no gap there. Their file-name evidence, which carries no
  content, is still recorded in every mode: as first changed, the credential
  pass never recorded it and the `--no-secrets`/`--triage` return came first,
  so a repository holding only `.codex/.netrc`, `.gemini/.npmrc` and
  `.claude/hooks/.netrc` lost the OpenAI Codex, Gemini CLI and Claude Code
  agent-config findings that the directory-wide coding-agent globs gave
  before.
- Redaction: wherever their syntax appears (a Dockerfile or CI script that
  writes a `.netrc`, a JSON string), `sanitize_text` withholds the value after
  netrc's `password`, `passwd` and `account` (one line or one token per line,
  comments, `\n` escapes, quoted values, `echo "..." > ~/.netrc`), the lines
  of a `macdef` macro, and Yarn 1's `.yarnrc` registry credentials written
  `name value`; references (`$NETRC_TOKEN`, `${{ secrets.X }}`) stay. The two
  rules run after every other pass and only add markers. The other files'
  syntax (`.npmrc` `_authToken=`/`_auth=`/`_password=`, `.pypirc`
  `password =`, `.git-credentials` URL userinfo, `.boto` and `.s3cfg`
  secret keys) was already withheld and is pinned by
  `tests/unit/test_credential_file_redaction.py`; `test_credential_file_names.py`
  renders every report format of a repository holding each kind.
- Redaction: the netrc pass reads a text in linear time. As first written,
  an unquoted value matched to the end of its non-blank run and the next
  token was read from the `\n` escape inside it, so each token of a run
  parted by escapes read the rest of the run again; and where an entry
  ended at a token the format does not define, each entry found in the
  comments after it read the remaining comments again. sanitize_text took
  24 s for `x = "machine\nlogin\nu\n..."` at 400 KB (0.4 s before the pass
  existed), and a 600 KB `app.py` exhausted its file analysis budget, so
  `shadowscan code` exited 3. A value now matches up to its escape; the run
  it is withheld to is found once and shared by the values in it, and the
  blanks and comments between two tokens are read once whichever entry
  reaches them. What is withheld is unchanged, except that a reference with
  more than 64 characters glued after it past an escape is withheld without
  being read; `tests/unit/test_redaction_performance.py` times these shapes
  at two sizes.
- Redaction: the netrc pass reads the forms real clients accept that it first
  missed, each of which put the password into every report format from a
  Dockerfile, script or notebook that writes one: keywords in any case
  (`MACHINE h LOGIN u PASSWORD v`, which curl reads), PowerShell's `` `n ``
  escapes (`Set-Content $HOME\_netrc "machine h`nlogin u`npassword v"`),
  `default` anywhere a word starts (`echo default login x password v >>
  ~/.netrc`), vertical-tab and form-feed blanks and `\v`/`\f` escapes, and a
  login named `account` or `password` (`login account password v`, whose
  snippet read `login account [REDACTED] v`): a value that is itself a
  keyword is withheld and read again as that keyword. A quoted name now ends
  at its closing quote and an unclosed one at the next blank, so neither
  hides a token after it (`login "u"\npassword v` in a JSON string); a
  comment after a `\n` escape runs to the next one; an entry in a comment
  between two tokens is read on its own, as one after an entry's last token
  was; a quoted name is read on its own as well; a macro's name may be a
  keyword (`MACDEF init`); and the rest of a macro's name line is withheld
  along with its body. Failing closed, a prose word after `default password`
  is withheld (`Change the default password [REDACTED] deploying`). The
  connector guide, SECURITY.md and the migration note no longer claim more
  than this, and SECURITY.md lists the commented-out token that remains.
- Redaction: a netrc entry no longer ends at a token the format does not
  define on the line of its last token, so the password after one is
  withheld. Reading `\v`, `\f` and backtick escapes as blanks everywhere cut
  an unquoted Windows domain login (`login CORP\fred`, `CORP\victor`), as
  `\n`, `\r` and `\t` already cut `CORP\nancy` and `CORP\tom`, and the
  escaped backslash of a source string was cut the same way
  (`"login CORP\\fred password v"`): the rest of the name ended the entry,
  and the password after it was in every report format (`shadowscan code`
  exited 0 with it in the JSON, SARIF, Markdown and HTML reports of an app
  that kept such an entry).
  Escapes now separate tokens only on a line written as an escaped string,
  one that holds a quote or an escape next to a keyword; on a netrc file's
  own lines a backslash is part of the name, as clients read it. Once a
  `machine`, `login` or `user` token is read, a token the format does not
  define is skipped on the line of the entry's last token, as curl skips it,
  so a name an escape seems to split and `machine h force yes password v`
  end nothing either; a head inside such a token still starts its own entry.
  Such a token on a later line still ends the entry: skipped there too, a
  `machine learning` near the top of a document withheld the word after
  every later `account` (16 more of 23,359 repository and installed-package
  files changed, against 2 with the line rule: a documented entry and a
  prose line). Failing closed, a prose word after `password` or `account`
  that follows `machine` or `login` on its line is withheld (`my machine has
  no login password [REDACTED]`). SECURITY.md lists the later-line token as
  what can remain.
- Redaction: a netrc comment in an escaped string ends at the next
  line-break escape, where its line does. A `#` after a blank was read to
  the end of the physical line even in a string whose lines are `\n`
  escapes, so an indented comment line or a trailing comment there
  (`"machine h\n  # deploy bot\n  login bot\n  password v\n"`,
  `"login u # note\npassword v"`) hid every escaped line after it, and the
  active password among them was in the JSON report of an app that keeps
  such a string. An entry right after a comment's `#`
  (`#machine h login u password v`) is read as well. SECURITY.md and the
  connector guide said an entry in a comment was withheld and listed only a
  comment line of its own as what can remain; they now say where a comment
  ends, and SECURITY.md lists a commented-out token outside an entry of its
  comment, a trailing one (`login u # was password v`) included.
- Redaction: what is glued to the closing quote of a netrc name or value is
  the next token, as Python's `netrc` reads it. Read as the rest of
  the quoted text, a keyword there hid its value (`login "u"password v`,
  `password "a"password v`, `login \"u\"password v` in a JSON string),
  and the password was shown; a value is still withheld up to the next
  blank.
- Redaction: a netrc file's own comment that holds an apostrophe or a quote
  and a Windows path (`# Bob's share is C:\new\data`, `# don't change: used
  by \\nas\backup`) runs to the end of its line again. Its line held a
  quote, so it was read as an escaped string, and the comment ended at the
  path's first `\n` or `\r`; the rest of it was a token the format does not
  define on a later line than the entry's last token, which ended the
  entry, and the password on the next line was shown (`shadowscan code`
  exited 0 with it in the JSON, SARIF, Markdown, HTML, OCSF and table
  reports of an app that kept such an entry in a raw string, which was
  withheld before the comment change above). A comment
  now ends at a line-break escape only where escapes are read and it is in
  escaped text: its line holds an escape next to a keyword, a line-break
  escape comes before the `#`, or the same quote comes both before and
  after it. Failing closed
  whatever a comment's reading, a token the format does not define on a
  later line no longer ends an entry while a `password`, `passwd` or
  `account` follows it in the entry's region, the eight lines from that of
  the entry's last token up to a blank line or the next entry's head. This
  also withholds `machine h`, then `force yes`, then `password v` on the
  next lines, which SECURITY.md listed as what can remain. Prose pays for
  it: a word after `account` or `password` within the region of a prose
  `machine` is withheld (`machine learning tools` / `create an account
  [REDACTED] each user`). Over 23,360 repository and installed-package
  files, the pass now changes 13 against 12: a JSON schema's description
  under a `machine` word is new, and more words are withheld in the netrc
  examples of SECURITY.md and this log and in a test's netrc string.
- Redaction: a netrc entry spread over adjacent string literals is read as
  one string. In Python's implicit concatenation
  (`NETRC = ("machine h\n"`, then `"login u\n"` and `"password v\n")`
  on the next lines), a JavaScript or C `"...\n" +` chain, or literals
  parted by a line continuation, the closing quote and the next line's
  opening quote were tokens the format does not define, so the entry ended
  after `machine` and the password was in the report excerpt; a single
  literal was withheld. A closing quote, then blanks, line breaks, a `+` or
  a line continuation, then an opening quote now part tokens as a blank
  does, and an opening quote right before a token is skipped alone, so a
  comment between two literals ends nothing either. Every earlier round of
  the netrc rule showed these passwords; main had no netrc rule.
- Redaction: a netrc `default` entry with no login reads past a token the
  format does not define as a `machine` entry does. SECURITY.md said the
  value after such a token on the line of the entry's last token was
  withheld, but the reader did so only after `machine`, `login` or `user`,
  so `default force yes password v` and `default port 443 force yes
  password v`, which curl reads as it skips unknown tokens, kept their
  password. The region rule above applies to such an entry as well. The
  value after a quoted word glued to a quoted name (`login "u""v"password
  v`, `\"u\"\"v\"` in a JSON string) is withheld too: such a word now ends at
  its closing quote, as a quoted name does. An escape before a keyword with
  blanks between marks escaped text, so an indented comment in unquoted
  escaped text (`NETRC=machine h\n  # note\n  login u\n  password v`) no
  longer hides the escaped lines after it; every earlier round and main
  showed that password. A keyword in quotes (`"password" v`), which
  Python's `netrc` reads as the keyword, is listed as what can remain.
  Prose pays most for `default`, a common word: a word after `account` or
  `password` on the line of a prose `default` or in its region is withheld
  (`the default service account [REDACTED] the instance`). Over 23,360
  repository and installed-package files the pass changes 33, against 12
  before these three changes: one more from the region rule after
  `machine`, six from a prose `default` on the line of an `account` or
  `password`, and fourteen from the region of a prose `default`, mostly
  docstrings. The region search tries only the words that can start a
  match, so the pass takes 20 s of CPU over those files against 18 s.
- `cloud.aws`: `_h_bedrock_agent` read the agent's owner from `tags`, but
  `GetAgent` and `ListAgents` return no tags and the collector never called
  `ListTagsForResource`, so no live scan could attribute a Bedrock agent to
  its owner (the offline fixture carried a `tags` block the API never
  produces). Bedrock agents and AgentCore runtimes now carry their tags from
  `ListTagsForResource` (covered by the documented `bedrock:List*` and
  `bedrock-agentcore:List*` grants); a denied or malformed listing marks the
  scan incomplete and leaves the resource without an owner. AgentCore
  runtime findings gain `owner` from the `owner`/`Owner` tag. As first
  integrated, a response whose `tags` was not a string map was recorded as
  `ok` in the live-scope details, since the call itself had returned; it is
  now recorded as `failed` before the warning, as `_paginate` records a
  malformed page.
- Risk: `_weighted_factors` deduplicated capabilities but not tags or
  providers, so a finding listing `hardcoded-credential` three times scored
  100 where one scored 65. Each tag and provider now counts once, and
  `Finding.from_dict` canonicalizes the list fields of a report, cache entry or
  plugin result the way the `add_*` methods already did for built-in findings.
- Docs: record export replay has a third pitfall (an export is sanitized, so
  the replay of a live run cannot observe its `plaintext-credential`
  evidence and reports no gap for the difference), and SECURITY.md lists the
  plural `secrets`/`tokens` collection keys among the forms redaction keeps
  by design.

### Precision, completeness and connector requirements from an outside review (October 17)

- **Markup redaction runs in linear time.** The XML tag pattern of the
  redaction pass (`redaction_markup._XML_TAG`) let name characters belong to
  the tag or to its attributes, so an unterminated tag followed by a long run
  of letters was retried at every split of that run: quadratic in stdlib `re`,
  which no connector or job deadline interrupts, and every scanned file passes
  through it. Its quantifiers are now possessive. The tag is always the
  longest name run and the attribute alternatives never overlap, so the matches
  are unchanged (a differential test compares the two patterns on 20,000
  random documents); the cost is linear.
- **The generic credential rule reports literals, not names of credentials.**
  `heuristic.inline-credential` admits `.` and `_` in its value, so a read of
  the environment (`apiKey = process.env.ANTHROPIC_API_KEY`), a member chain
  (`old_password = self.cleaned_data["old_password"]`,
  `password = hasher.encode(...)`) or a variable passed through
  (`self.api_key = api_key`) passed as a long, diverse key and was reported as
  a hard-coded credential at high risk. An unquoted identifier or member chain
  in source code, and elsewhere a member chain that code follows (a call, a
  subscript, `;`, `,`, `)`, `}`) or that starts at `process.env.`,
  `import.meta.env.`, `os.environ.`, `self.` or `this.`, is now a reference,
  not a credential; a quoted value is always a literal, a random-looking value
  is never a name, and in an env file an unquoted value
  (`DB_PASSWORD=Summer.Vacation2024`) stays a candidate. A reference's value
  goes on past a call, subscript, optional or non-null chain on it
  (`Environment.GetEnvironmentVariable("X") ??`, `process.env.X?.trim() ||`,
  `configService.getX() ??`) and a TypeScript cast (`as string ||`), through
  parentheses around an operand (`|| ("<key>")`) and a Python triple-quoted
  literal (`or """<key>"""`), all of which 90d22be and main reported, and
  through operators, which may end a line or start a later one (after
  comment lines or a backslash continuation too). An empty line before an
  operator, `;`, `,`, a closing bracket or any other token ends it; empty and
  comment lines between an operator and its operand do not, since the
  operator needs one (`||\n  // dev fallback\n  "<key>"`, which main
  reported, had ended at the second line break). Any
  white space but a line end separates tokens, as do the zero-width space,
  word joiner and byte order mark (a no-break space before `||` had ended the
  value, which 90d22be and main reported). The
  operands are read once, left to right, within 512 characters of the
  match. That read is Python and costs more per match than one regex, and it
  ran inside the regex iteration, whose timeout charges the time between two
  matches to the pattern: a 260 KB file of 2,000 credential reads with
  chained calls, or 1,600 lines of `?.trim()` chains with no credential,
  timed out (exit 3) where 90d22be completed. `matcher._judged_finditer`
  now reads a secret pattern's matches in batches of 64, judges them between
  regex executions and charges the judge to the input's execution budget;
  the executions together keep one pattern's allowance. A follower with no
  quote followed by 16 characters of the value class can hold no fallback
  literal and is not read at all (`_FALLBACK_HINT`), so such a match costs
  one regex search, about 9 us as on 90d22be, instead of 150-440 us for a
  512-character chain. A fallback, concatenation or
  ternary after it (`process.env.OPENAI_API_KEY || "<key>"`, `?? "<key>"`,
  `process.env.PREFIX + '<key>'`) is still reported when a string literal
  that is a direct operand of `||`, `??`, `?:`, `or`, a ternary branch or `+`
  is one token of the value class and looks like a key. A literal passed to a
  call, a constructor or a throw there (`?? getSecret("<path>")`,
  `?: error("X is not set")`), a sentence and an empty or word-like fallback
  (`|| ''`) are not, nor is a fallback whose segments each read as a word or
  a number: a default mode or label (`|| "anonymous-public-access"`, `??
  "disabled-in-this-build"`), a header name (`"x-api-key-header-name"`), a
  URL path (`process.env.API_BASE + "/oauth2/v2.0/authorize"`) or a model id
  (`or "gpt-4o-mini-2024-07-18"`), which 90d22be reported as keys; a
  fallback must look like a token, so a generated passphrase there is given
  up. The placeholder test judges the fallback literal
  itself (`?? "your-api-key-here-Abc123XyZ"` is `example-credential`
  evidence; `?? "sk-ant-api03-..."` reads as words and an ellipsis, so it is
  no fallback credential and records no evidence at all). Labels
  of three or more letter words (`'request-scoped-credential'`,
  `'fc-shared-env-must-not-be-used'`) are not high-entropy keys when, read
  without a plural `-s` or past `-ed`, one word is credential, placeholder,
  development or filler vocabulary that passphrase word lists leave out
  (`local-development-only`, `foo-bar-baz-qux-quux`,
  `lorem-ipsum-dolor-sit-amet`, `rotate-these-tokens`), two words are such
  vocabulary that is also a common word (`unsafe-dev-only-default`,
  `defaults-were-replaced`), or one such common word comes with a function
  word (`this-should-be-changed`, `dont-use-this-in-prod`); or when a word
  repeats a word of three letters or more of the assigned name, or the slug
  is CONSTANT_CASE (upper case joined by `_`). A single common word does not
  make a label: with one vocabulary list and stemming, `passed`, `valued`,
  `keyed`, `devs`, `locals`, `unsafe`, `default` or `lorem` in a generated
  passphrase (`snout-passed-thump-bloom-gravel`) hid it, which 90d22be and
  main reported. Other word slugs, joined by `-` or `_` and in any case, are
  generated passphrases (`DB_PASSWORD=snout-fiber-thump-bloom-gravel`,
  `SNOUT-FIBER-THUMP-BLOOM-GRAVEL`) and are still reported, even without
  digits or mixed case. Words joined by `.` are a passphrase
  (`snout.fiber.thump.bloom.gravel`) only as a password in an env or
  credential file: in source code and other configuration a dotted string
  of words names a package, an Android preference key, an i18n message or
  a namespace (`KEY_ACCESS_TOKEN = "net.openid.appauth.state"`,
  `I18N_PASSWORD = "forms.login.field.hint"`), which 90d22be did not report
  and the first version of the dotted rule did. A value
  with an ellipsis (`sk-ant-api03-...`) is a documentation placeholder
  (`example-credential` evidence). Secret matches are filtered before the
  five-per-signal cap, so rejected references no longer use up the places of a
  key further down the file. Provider-specific key formats are unchanged.
- **An environment read stays visible in evidence.** After a credential name,
  the redaction passes kept nothing of the value: `const apiKey =
  process.env.OPENAI_API_KEY;` became `const apiKey = [REDACTED];`, which reads
  as a hard-coded key. A value that is exactly one read of an environment
  variable by an upper-case name (`process.env.X`, `import.meta.env.X`,
  `os.environ["X"]`, `os.getenv("X")`, `os.environ.get("X")`,
  `System.getenv("X")`, `Environment.GetEnvironmentVariable("X")`,
  `os.Getenv("X")`, `ENV["X"]`, `ENV.fetch("X")`, `Deno.env.get("X")`,
  `getenv("X")`) is now kept. Only blanks and then the end of the line, `;`,
  `,`, `)`, `}` or `]` may follow the read. A default argument, a fallback
  (`|| "v"`, `or "v"`, `?? "v"`, also chained in a `key: value` entry),
  concatenation, a computed name, a method on the value or a comment after the
  read (`apiKey: process.env.X // old: <key>`) keeps the whole value withheld,
  as does any other identifier, call or token. When `,` or `;` ends the value
  before the comment (`apiKey: process.env.X, // old: <key>`, `api_key =
  os.environ["X"]; # <key>`), the read stays visible and the comment keeps
  its words, but `redaction_assignments._redact_line_tails` withholds
  each opaque token in a comment on a line that assigns a credential name,
  after any value (main showed those tokens too). In `key: value` form the
  value lexer stops at the quote of a subscript or call argument, so the
  fallback after such a read (`azure_api_key: os.environ['K'] if PROD else
  '<key>'`, `or`, `??`, `||`) was shown, on main as well; the mapping pass
  now reads past the bracket the withheld read left open, and a fallback
  after a read assigned to a conditionally named setting (`azureKey:
  process.env['K'] ?? '<key>'`) takes that setting's name. That covered one
  unspaced subscript or call with one argument only: a spaced subscript
  (`process.env[ 'K' ] || '<key>'`), an optional-chain call
  (`process.env.K?.trim() || "<key>"`), a call with two arguments
  (`cfg("a", "b") || "<key>"`) and a default argument (`os.getenv("K",
  "<key>")`) still showed the literal, on main too. `_redact_line_tails` now
  reads every string literal after the credential name on its line, not
  only the comment, and withholds each token in it that
  `_credential_literal` takes for an opaque key (`name=` inside a literal is
  not part of the token; a template with a replacement field is left alone,
  as the assignment passes leave it). Words, references, model names and
  placeholders on the line stay. An XML or HTML comment counts as a comment
  there too (`<add key="OpenaiApiKey" value="%OPENAI_API_KEY%" /> <!-- <key>
  -->` showed the key, on main as well). The variable name must not look
  like an opaque key (`redaction_rules._opaque`: letters and digits alternating
  in a long run) and must not run to 16 characters or more without a `_`
  (`_PASTED_KEY_NAME`), so an upper-case key or base32 secret pasted as the
  name (`os.getenv("<KEY>")`, a digit-free TOTP secret in
  `process.env.<KEY>`) stays withheld while `OPENAI_API_KEY`, `PGPASSWORD`,
  `GITHUBTOKEN` and `K8S_TOKEN` are shown.
- **Fewer spurious incomplete scans.** Exit 3 was the common case on ordinary
  repositories, so a CI gate on a nonzero exit failed on them for good:
  - A JSON or YAML document whose structure declares no MCP servers (a
    transcript array whose records list `mcp_servers` statuses, a scalar, a
    workflow example writing an MCP configuration in a heredoc) is no longer
    parsed as an MCP configuration and rejected. A dedicated MCP
    configuration name, or a document whose structure declares servers, keeps
    the strict rules. That includes a list holding a mapping of servers within
    the walk's bounds (twelve levels of mappings and lists, 256 entries each):
    an Ansible task writing `~/.cursor/mcp.json` from structured `content`, or
    a top-level `- name: client` / `mcpServers:` list. The first cut returned
    False for every list and passed those as complete with no finding;
    `_document_declares_mcp` now walks lists, where only a mapping of servers
    counts. Tests: the `ansible-task`, `yaml-list` and `json-list` cases of
    `test_a_real_mcp_configuration_that_does_not_parse_stays_a_gap`,
    `test_a_list_of_records_with_a_server_status_list_is_not_an_mcp_configuration`
    and `test_the_structural_mcp_walk_descends_into_lists_within_its_bounds`.
    The structure is the YAML parse every structured file already gets, so a
    guessed YAML file is not parsed a second time for this check; without a
    held parse, the substring checks come first and a YAML parse can only
    veto a text hit. The first cut parsed every non-workflow YAML file twice;
    in the review's run, 20 OpenAPI-style files of 574 KB took 82 s against
    42 s on main. Tests:
    `test_a_yaml_file_without_mcp_keys_is_parsed_once` and
    `test_a_yaml_mcp_configuration_is_decided_from_the_parse_already_held`
    count the parses instead of timing them.
  - Import-bound calls are read up to 65,536 characters instead of 8,192
    (`source_semantics.MAX_CALL_TEXT`): agent constructions carry their
    instructions and tools inline, and their options were unread. The
    JavaScript call extent is found with one regex pass over its parentheses.
    A longer call is still a gap.
  - In test code that the scan discounts (`include_tests` false), a malformed
    fixture (invalid manifest XML, YAML that fails the integrity checks,
    source the lexer cannot settle, a parser input defect) is a warning that
    leaves the scan complete, as an oversize test fixture already was. A
    binary or undecodable test fixture is read for credentials only (its bytes
    as Latin-1 without NUL bytes, no excerpts), since credentials are never
    discounted, and is then a warning. `strict_coverage` and `include_tests`
    keep every such gap, and the same files in product code are gaps as
    before. So are files whose findings test paths do not discount: an MCP
    configuration (by a dedicated name such as `.mcp.json`, or a JSON, TOML
    or YAML file, `settings.json` and `config.yaml` included, whose structure
    or, for a binary one, text declares servers), a coding-agent instruction,
    rule or settings file (`CLAUDE.md`, `.cursor/rules/`,
    `.claude/settings.json`, the MCP and coding-agent file-name signatures)
    and an agent manifest or card (`FilesystemConnector._full_weight_in_tests`).
    The first cut discounted every file under a test path, so
    `tests/.mcp.json` with a NUL byte or a missing brace, or
    `testing/CLAUDE.md` with a NUL byte, dropped its 0.96 to 0.98 confidence
    finding and the scan still reported complete. Tests:
    `test_a_full_weight_file_under_a_test_path_that_cannot_be_read_stays_a_gap`
    and `test_a_structured_fixture_without_mcp_keys_stays_discounted`.
- **OpenAI Agents SDK realtime agents are agents.** `RealtimeAgent` from
  `@openai/agents/realtime` (and `agents.realtime` in Python), and the
  `RealtimeSession` / `RealtimeRunner` that run one, are agent constructions
  with the `tools` and `handoffs` options of `Agent`; they were LLM usage at
  autonomy L0. The realtime `tool()` factory defines executable tools, and the
  Python import pattern recognizes `RealtimeAgent` and `RealtimeRunner`.
  Evaluation corpus: two positive cases and a hard negative (a local
  `RealtimeAgent` class) in `current_idioms_corpus.json`.
- **Live connectors ask for what the vendor references require** (checked
  against the published API references, not live tenants):
  - `identity.okta`: an OAuth bearer needs `okta.appGrants.read` for
    `/apps/{id}/grants` besides `okta.apps.read`; documented in the
    connector, its guide and the least-privilege table.
  - `saas.slack`: `team_id` is sent with `users.list`, the `admin.apps.*`
    lists and `team.integrationLogs`, which an org-level token requires.
  - `saas.github-apps`: GitHub serves the approved fine-grained PAT list only
    to GitHub App tokens. New `app_token` (env `GITHUB_APP_TOKEN`) for that
    listing; a refusal without it names `app_token`. A GitHub App token with
    the organization Administration, Personal access tokens and GitHub
    Copilot Business read permissions covers every call.
  - `identity.entra`: the service principal listing selects only v1.0
    properties (`publisherName` and `createdDateTime` are beta); the publisher
    comes from `verifiedPublisher`. Agent identities need
    `AgentIdentity.Read.All`, now documented.

### Coverage gaps are budgeted, so exit 3 means something again (October 17)

- A scan reported itself incomplete over any unread byte. One dangling
  symbolic link under `tests/certs/` made `psf/requests` exit 3, and 43 of the
  87 repositories in `benchmarks/shadow-ai-discovery` are marked incomplete
  for the same class of reason. An exit code that fires on half of real
  repositories teaches operators to suppress it, which is what strict
  accounting was meant to prevent.
- New `shadowscan/coverage.py` records each gap with the entries it costs and
  the path it occurred at, and takes the verdict once at the end of the run. A
  *blinding* gap -- the walk stopped, a page was refused, a deadline expired,
  a symbolic link names a directory (inside the tree or outside it), a
  manifest or agent card would not parse, an agent, MCP or dependency
  configuration file its name selects is over `max_file_size`, undecodable
  bytes anywhere but in test code while `include_tests` is off (the walk
  reads `Vendor/`, or `vendor/` with `default_excludes: false`, as source),
  any sanitizer limit -- marks the scan incomplete at once, with no budget:
  the scanner cannot bound what it missed. A *partial* gap costs a known
  amount (a dangling link, or a link to one regular file, is one entry) and
  accumulates against `options.max_coverage_gap` / `--max-coverage-gap`, 2%
  of examined entries with a ceiling of 100 weighted entries.
- Gaps under paths that cannot hold deployed code (`node_modules`, `vendor`,
  test fixtures) are weighted to a quarter, not ignored, so a tree seeded with
  thousands still exhausts the budget. A file that could not be read or
  decoded is never weighted down by its path: in test code whose evidence is
  discounted it is read for credentials and charged a whole entry, and an
  unparseable manifest there is charged a quarter (see the October 17
  coverage-semantics entry above, which also makes the budget per root).
- Tolerated gaps are counted in the JSON report's `stats[].coverage`, and the
  first 50 (`MAX_PUBLISHED_GAPS`) are listed under `stats[].coverage.details`
  with their paths and weights, `details_truncated` counting the rest. A
  one-line verdict joins the connector's warnings, so nothing is hidden by
  being tolerated. SARIF has no coverage block; its notifications carry that
  line, which names the JSON report and so is worded without brackets, which
  SARIF escapes in a message. `strict_coverage` and `--max-coverage-gap 0` are
  both strict accounting and restore the previous accounting: no gap is
  tolerated, discounted as test code or declared by `profile: ci`.

### Connector deadlines scale to their input, and an overrun keeps its findings (October 17)

- A fixed 120-second deadline truncated large repositories: the walk hit it
  mid-tree and the connector reported nothing, which reads as a clean result
  on every surface except the exit code. `langchain-ai/langchain` produced
  zero findings at the default. A new `estimate_timeout_seconds` engine hook
  lets a connector propose a budget from a cheap bounded probe of its own
  input, and the engine caps any proposal at 30 minutes. `code.filesystem`
  counts up to 20,000 entries (directories and files, pruned as the walk
  prunes them, for at most a second) and scales the deadline in proportion
  above 12,000, so it proposes at most 200 seconds at the 120-second default.
  A larger tree needs an explicit `--connector-timeout-seconds`; without one
  an overrun still marks the scan incomplete. An explicit
  `--connector-timeout-seconds` is honoured unchanged, 120 included: only an
  unset deadline is scaled, so a configuration that sets
  `connector_timeout_seconds: 120` turns the scaling off. The same scan now
  completes with 51 findings.
- A connector that still overruns surrenders the findings it had already
  produced and sanitized, instead of having them discarded. The scan is
  marked incomplete either way; dropping them turned an overrun into an empty
  report. The timeout diagnostic now says results are truncated and names the
  option to raise. Surrendered findings are copied away from the abandoned
  worker and prepared as a completed job's are: a plugin's get the id its own
  name derives and lose any registry record, so an overrun cannot report a
  built-in finding's id or an approval the completed run would not.

### Risk scoring gains capability interactions (October 17)

- The additive model could not express that two capabilities are worse
  together than apart: `browsing` with `code-exec` is the
  prompt-injection-to-execution path, and private data with untrusted content
  and an outbound channel is one injection from exfiltration, yet each scored
  as any unrelated pair of the same weights. Seven combinations in
  `COMBINATION_WEIGHTS` add a named `combination:` factor when the whole set
  is present. The capability sets are fixed so an id means the same thing in
  every report; only the weights are tunable, under
  `options.risk_weights.combinations`. Factors still sum to the score.

### OCSF events always carry the required `time` attribute (October 17)

- `time` is required on the Detection Finding class, and the reporter omitted
  it whenever no scan timestamp parsed -- reachable in ordinary use, since
  `fleet.merge` sets `started_at` to the empty string for an undated merge. A
  validating pipeline rejects an event missing a required attribute, so the
  whole report was discarded rather than read. The render time is published
  instead, with `unmapped.time_source` set to `report_render` so a consumer
  can tell a substituted timestamp from a scan's own.
- `tests/fixtures/ocsf/detection_finding_1.1.0.json` holds the class's
  attribute requirements and drives the conformance tests, as the vendored
  OASIS schema does for SARIF. It states that it is a transcription, because
  OCSF serves its schema rather than distributing it;
  `python -m tools.ocsf_schema --refresh` replaces it from the live
  definition, and `--check` (wired into CI) fails if the reporter's version
  moves without it.

### Lint, tests and tooling (October 17)

- Ruff's flake8-bandit rules (`S`) are enabled for the shipped package. All 38
  findings were false positives -- SafeLoader subclasses, XML parsing behind
  an entity-declaration guard, argv-list subprocess calls, environment
  variable names -- and each now carries a `noqa` with its reason, so they are
  reviewed decisions rather than unexamined gaps and a new occurrence fails
  CI. Tests and tooling are exempt, where a hard-coded token is the point of
  the test. A blanket `noqa` (no codes, for a line or a whole file) would
  silence every rule with no reason given; ruff's `PGH004` rejects it, and
  `test_noqa_comments_name_the_rules_they_suppress` holds the linted paths to
  that whatever the select list says.
- `C901` was never enabled and 119 functions exceed complexity 15, the worst
  at 127. `tools/complexity_gate.py` measures against that target and compares
  with `tools/complexity_baseline.json`: existing debt stays buildable, a new
  or worsened function fails CI, and `--update` records only decreases and
  removals. Recording an increase takes `--allow-increase` as well, so it
  shows in the baseline's diff for review. Allowances are keyed by file and
  qualified name (`Class.method`, `outer.inner`). Keyed by bare name, with
  the worst score kept, every `analyze` in `endpoint/runtime.py` shared
  `MCPInventoryConnector.analyze`'s 30, so any of the other five could grow to
  30 unnoticed; the migrated baseline gives each entry its old allowance and
  splits the one pair above the target, `source_ranges.py`'s two `_code`, at
  34 and 26. `make check` and `make check-fast` run the gate and
  `tools.ocsf_schema --check`, as CI does.
- 62 timing guards measured wall time for what is an algorithmic, CPU-bound
  question, so a parallel run failed linear code. They measure CPU time now,
  with inline `time.process_time()` bounds that contention cannot inflate;
  no bound is scaled by the machine's speed or retried. `tests/perf.py`
  explains the choice. It held a calibrated CPU budget with a single retry
  and a wall budget scaled by a sampled load factor; no guard used them, so
  they are gone. The symbolic-link listing-deadline test counts work instead:
  it charges 10 ms per link check to a connector clock that nothing else
  advances, so where the walk stops does not depend on the machine's load.
- `tests/unit/test_aws_stubber.py` exercises AWS collection through botocore's
  own `Stubber`: continuation tokens, the page cap, pages kept across a
  mid-listing failure, real `ClientError` shapes, and that an SDK error
  message never reaches the report. The existing tests replace `_paginate`
  with a `Mock`, which skips all of it in the largest connector in the
  codebase. These found `AuthorizationError` -- Organizations and SNS --
  missing from `_DENIED_CODES`, so those denials read as unexplained failures
  instead of naming a missing permission.
- `live_collection` is declared per connector, pinning the README's new
  "28 of the 38 connectors collect from a live API" against the classes, with
  a test that each connector declaring no live mode actually refuses to
  collect.
- The slow timed sweeps carry a `slow` marker and `make test-fast` deselects
  them, taking those modules from 105 seconds to 0.4. CI runs the full suite
  as before, and a consistency test fails the build if any workflow adds
  `-m "not slow"`.

### README: benchmark chart generated from the committed ShadowBench cases run (October 16)

- From #249 (merged as #250): the README's Benchmarks section gains a
  cross-tool chart. It is generated by `tools/readme_visuals.py` from
  `benchmarks/shadowbench/cases/results/2026-10-11/metrics.json` and checked by
  `make readme-visuals` / its test like the other images, so its figures change
  only when that committed run does. In #249's layout (ranked estate-recall
  bars, then a table), it adds each tool's surface coverage and in-scope
  recall with its interval, and carries the authorship and "not a verdict on
  any product" caveats in the image. #249's raster figures (0.90 estate
  recall, four tools absent from any committed run) were not carried by #250.
- The hero banner is enlarged in the generator as #249 proposed (560 px tall,
  128 pt name, larger tagline and pills). #250 left out its connector and
  signature count pills, which go stale in an image.
- #251 then added what #250 had left out: the banner carries "38 connectors"
  and "233 signatures" pills, `docs/assets/benchmarks-cross-tool.webp` (a
  raster cross-tool summary that no generator in `tools/` produces, so its
  figures cannot be regenerated or checked against a committed run; the
  README caption names the runs it summarises) sits beside the generated
  SVGs, and `tests/unit/test_readme_visuals.py` permits a connector or
  signature count in an image, which it had rejected since #226. The counts
  are therefore in two places: the pills, and the README text the
  consistency tests check against the shipped packs; regenerate the banner
  with `make readme-visuals` whenever the packs change.
- #245 (from #244) restructured the README into a landing page with a command
  reference and a Python API section (about 620 lines added), with review
  fixes: a working API example that fails closed on an incomplete scan,
  corrected data-type notes and `risk_basis` values, the global `-v`/`-q`
  options, restored test anchors and the exit-3 note. It dropped an unsourced
  cross-tool benchmark image and hand edits to the generated banner; #251
  reintroduced the image as described above.

### Plugin workers no longer see the raw identity key (October 16)

- From #247: a process-mode plugin worker inherited `SHADOWSCAN_IDENTITY_KEY`
  in its environment, so a third-party connector that does not declare
  `uses_run_identity_key` (and any program it started) could read the raw
  operator key. The worker now removes it from `os.environ` after the engine
  has read it and before the plugin is imported; connectors that declare
  `uses_run_identity_key` still receive the decoded run key. Thread-mode
  plugins share the scanner's process and environment, so this does not
  apply to `--plugin-execution thread`.
- `clone_environment()` sets `http.sslVerify=true` explicitly. Git already
  verifies by default and system and global configuration are disabled, so
  this changes no current behaviour.
- Not carried from #246/#247: DNS pinning (`main` already pins clones through
  `clone_pins`, without the expiring `+` entry), CA-bundle propagation to Git
  (no code path sets a worker CA bundle, so it had no effect), and abandoned
  worker pruning (`_prepare_run` already clears finished workers).

### Integration review fixes (October 15)

- **Redaction time under a conditional name (#235).**
  `_redact_yaml_multiline_values` read a kept block under a name that carries
  a credential only when its value is opaque (`key`) again from every such
  name nested in it, and blank lines below the deepest one once per name
  above them. A 500 KB staircase of nested `key:` lines took five to seven
  seconds and 200 KB of them over blank lines about twenty, so one file in an
  untrusted repository could exhaust its matching budget and leave the scan
  incomplete (exit 3). A conditional name inside a block already kept is no
  longer read again, and a bare `key:` whose first nested entry is read again
  under its own name is left to the mapping's own entries, so the pass is
  linear again (milliseconds for the same inputs and for a 1 MB staircase of
  alternating `key:` and `x:` lines). Names that always carry a credential
  (`password`, `api_key`) are read as before. Timing regressions pin the
  staircase shapes.
- **A note inside a block scalar kept its credential (#235).** `key: |` over an
  opaque value kept it when a `# rotate quarterly` comment or a sentence sat
  in the block, before or after the value: every line was joined into one
  value, and the note's whitespace failed the opaque test. The lines that can
  be part of a wrapped value (no whitespace, no leading `#`, not a URL or a
  path) are now joined at each indentation, those on either side of a note,
  sentence, URL or path apart and together. Each run of lines without
  whitespace is also joined across indentation, `#`-led lines included, and
  ends at a line that cannot be joined, at a mapping entry and where the block
  of the innermost entry above it ends: `pwd: |` over `b39f` and a
  tab-indented `9fc2`, `sshKey: |` over `q7Rk2Xw` and a deeper `9pLm4Tz`, and
  `pwd: |` over `#aXV5bY` and `g4Sy` are withheld (an earlier revision of this
  fix split them at the change of indentation or at the `#` and showed them).
  A nested `key:` or `pwd:` block inside a kept outer block therefore yields
  the same joined values as when read alone, also under a sequence entry
  (`- pwd: |`), and an outer URL, path or placeholder line never hides its
  wrapped value. Indentation is the blanks and tabs before a line, as the
  block boundary measures it: a form feed after them no longer moved a line
  into a nested block's group, where its placeholder text kept the outer block
  and hid the nested one. Each line is also tested on its own, after a
  trailing ` # note` (`tlsKey:` over `<opaque>  # rotated 2026-01`) or a `- `
  sequence marker (`key:` over `- <opaque>`) is set aside, as the single-line
  form `key: <line>` reads its value: an identifier made of words
  (`ipv4Addr6To4`) and a digest after its algorithm (`sha256:<hex>`) keep
  their text, as on one line, where the earlier revision withheld
  `cacheKey:` over `- ipv4Addr6To4` and about four times as many synthetic
  non-secret blocks as #235. A line that form never reads as a value is tested
  as written: a block scalar's leading `#` is content (`pwd: |` over
  `#<opaque>`), and a line with other symbols or `sha256:<opaque>` is withheld
  when it holds an opaque run. A random value of about 8 to 16 characters that
  happens to read as words now keeps its text on a line of its own, as it
  does after `key: ` on one line. A bare `key:` is left to its nested mapping
  only when the first entry is read again under its own name: one with its
  value on its line (`algorithm: RS256`), or one over its own block whose name
  this pass reads (`key:`, `password:`). Over an entry that nothing reads
  again (`private:`, `stringData:` or `value: |` over an opaque line, the same
  with a tag or an anchor before the indicator such as `value: !!binary |`,
  or any entry after a lone carriage return) the whole block is read, as #235
  did. On 63,000 generated documents no output shows a credential that
  `main` withholds; against #235 the remaining shown values are such
  word-like random values and values #235 withheld only by joining them with
  a following `next:` key or a path line. Regression tests cover a note
  before, between and after the wrapped lines, a trailing note, a sequence
  entry, a `#`-prefixed value in `|`, `|-` and `>-` blocks, a path or URL
  beside the value, nested blocks inside a kept block, wrapped values across
  indentation (tab, deeper and shallower lines, a nested block's end, a
  sequence entry, a form feed), node properties, the identifier and digest
  lines that stay, a bare conditional name over `private:`, `stringData:`
  and `value:` with LF and CRLF line ends and over a nested `key:` after a
  lone carriage return, through `sanitize_text` and `sanitize`. Operators
  with Kubernetes secrets or Helm values written this way should regenerate
  retained reports and cached evidence and rotate any key they show.
- **`--deny-private-origin` lost to a connector grant (#235).** The flag only
  set `allow_private_origin` to false, which is also the default, and the
  engine preferred a connector's own `allow_private_origin: true`, so a
  configured grant (or `run ... --set allow_private_origin=true`) still reached
  loopback, private and cloud-metadata addresses for that connector although
  the operator had refused them for the scan. Before #235 built-in connectors
  rejected the key, so no connector key could lift the flag. `ScanConfig` gains
  a keyword-only `deny_private_origin`, which `--deny-private-origin` sets on
  every scanning command, and the engine checks it before the connector's key,
  for the plugin lookup as well as collection, as a scan-wide
  `allow_instance_credentials` already overrides a connector key. A conflicting
  connector key is overridden without an error, and the connector's own
  configuration (`ctx.config`) reads the value the engine enforces, in thread
  and process plugin workers alike, so a plugin whose own transport honours
  the documented key is refused too; under the refusal it read `true`. The
  flag refuses the `allow_private_origin` grant only. It does not revoke
  `allow_instance_credentials`, under which cloud connectors still contact the
  instance metadata service and the `cloud.gcp` credential transport accepts a
  private token endpoint; `SECURITY.md`, the threat model,
  `docs/production.md`, `docs/api/http.md` and the configuration guide say so
  and tell operators to pass `--deny-instance-credentials` as well. A
  `ScanConfig` with both `allow_private_origin` and `deny_private_origin` true
  is refused, and a configuration file cannot set the refusal; an in-file
  `options.allow_private_origin: false` stays a default that a connector grant
  overrides. Affects operators and pipelines that pass `--deny-private-origin`
  with a configuration that grants a connector; library callers can now refuse
  with `ScanConfig(deny_private_origin=True)`. Regression tests cover `scan`
  with and without the flag, `run --set allow_private_origin=true
  --deny-private-origin`, the engine and plugin-lookup policy, the connector's
  `ctx.config` with and without the refusal in threads and in a spawned plugin
  worker, and the both-true rejection.
- **Private-origin documentation (#235).** The per-connector grant examples in
  `docs/getting-started/configuration.md` and `docs/production.md` used
  `gateway.logs` with `input:`, which reads an export and makes no HTTPS
  request, so an operator who copied them granted nothing and the real internal
  connector still failed closed. They now use `endpoint.mcp` with
  `agent_card_urls` and say that an offline `input` run makes no requests. The
  A2A probe docstring, `SECURITY.md`, `docs/connectors/endpoint.md` and the
  `endpoint.mcp` egress row in `docs/production.md` named only
  `options.allow_private_origin`; they now name the connector-level key and
  `--deny-private-origin`. The threat model's symlink row joined `O_NOFOLLOW`
  and `O_DIRECTORY` with a full-width vertical line (U+FF5C) that neither
  pastes nor greps as the ASCII flag operator; it is now an escaped `|` outside
  the code spans, which keeps the table intact.
- **Clone host pinning (#234, #236, #237).** #234's
  `validate_clone_destination()` resolved the clone host again before Git ran
  and refused private answers, but it pinned nothing: Git resolved the name
  itself afterwards, so an answer that changed in between (DNS rebinding) still
  reached an unchecked address, and an inherited `HTTPS_PROXY` resolved it
  elsewhere. It also passed when the name did not resolve, and its
  `getaddrinfo` had no time limit, bringing back the unbounded lookup #236
  removed. It is replaced by `clone_pins()`: after `validate_url`'s preflight
  the host is resolved once more with #236's bounded resolver
  (`resolve_destination` in `utils/http.py`), every answer of that second
  lookup is checked, and Git is pinned to those answers with
  `http.curloptResolve` under the URL's own spelling of the host (trailing dot
  included), with `http.proxy` empty so proxy variables are ignored; the
  preflight's answers never reach Git. A host with no answer in time is not
  cloned and the repository uses sampled API mode (incomplete); a refused
  answer is refused like `validate_url`'s, and a host libcurl would spell
  differently from the pin (non-ASCII as written in the URL, percent-encoded or
  starting with `-`) is refused rather than left unpinned. The ASCII check
  reads the URL's own host, not urlsplit's lowercased one, which turns U+212A
  KELVIN SIGN into an ASCII `k` that a libcurl without IDN never looks up.
  `validate_url` and `clone_pins` refuse port 0: read as the default port
  (`port or 443`), `https://host:0/...` matched the origin and the pin was
  keyed to 443 while libcurl looked up `host:0` itself. `validate_url` refuses
  port 0 in every API URL, and an origin written with it matches no URL. Git
  2.37 added the option, below #237's 2.45 floor, and `MINIMUM_CLONE_GIT`
  asserts the tie. Clones need direct HTTPS egress to the clone host. For
  `code.github` on github.com that is `github.com`, which API listing
  (`api.github.com`) never needed, so a worker that reached `github.com` only
  through a proxy variable now scans every repository in sampled API mode
  (incomplete); for GitHub Enterprise Server and GitLab the clone host is the
  API origin's host, which API listing already reaches directly. Regression
  tests drive a real Git clone of an unresolvable `.invalid` host to a loopback
  listener (mixed case and trailing dot, with a proxy variable set) and cover a
  rebinding between the lookups, an unresolvable or stalled lookup, IPv6
  brackets, refused spellings (the Kelvin sign included) and port 0. The real
  Git test bounds its listener's `accept()` and wakes it on the way out, so a
  run whose pin is missed fails at once instead of waiting out its join and
  leaving the thread behind.
- **A refused clone URL ended the repository (#237).** `_clone` raises
  `ValueError` for a provider clone URL off the API origin or naming another
  repository (and now for a clone host that resolves to a refused address), and
  `_fetch` did not catch it, so the repository was recorded as an error and none
  of it was scanned, while `docs/production.md` said it fell back to sampled API
  mode. `_fetch` now warns with the reason, marks the scan incomplete and falls
  back to API mode, which reads the listed repository by its own name from the
  configured origin, like any other failed clone. Affects `code.github` and
  `code.gitlab` scans whose provider returns such URLs; a regression test covers
  both providers and both refusals.
- **Plugin isolation default: documentation and compatibility (#234).** #234
  changed the `plugin_execution` default from `thread` to `process`, but
  `docs/production.md` (its security-policy example, and a paragraph saying the
  default "remains `thread`"), `docs/connectors.md`, `docs/architecture.md` and
  `docs/getting-started/configuration.md` still gave `thread` as the default,
  and the changelog listed none of the new failure modes. The pages now give
  `process` as the default and `thread` as the opt-out, and
  `docs/production.md` carries an upgrade note. With `plugin_execution` unset,
  these now make a scan incomplete (exit 3) where the thread backend completed:
  a plugin result above the 16 MiB JSON transport limit; connector
  configuration or signature objects that Python cannot pickle, which only an
  application building `ScanConfig` itself can pass; an embedding script
  without an `if __name__ == "__main__":` guard, which runs again in each plugin
  worker before the plugin starts, repeating its side effects, including output,
  which the worker does not discard, and fails the plugin if that run exits or
  raises at module level (for example `sys.exit(main())`) or uses up the
  connector deadline; and a plugin that starts
  `multiprocessing` or `ProcessPoolExecutor` children, which the daemonic
  worker refuses. The worker also discards the plugin's standard output,
  standard error and logging. `options.plugin_execution: thread` or
  `--plugin-execution thread` keeps such a plugin in the scanner process. The
  engine's allowlist check now calls `shadowscan.config.plugin_names()` instead
  of repeating its parsing; behavior is unchanged. Affects operators and
  embedding applications with allowlisted third-party plugins. A repository
  consistency test ties the documented default to `ScanConfig`.
- **The abandoned-worker exit watchdog cut a job deadline short and outlived
  its call (#234).** After a connector worker was abandoned, the CLI armed a
  30-second process exit for report output even when `--job-deadline-seconds`
  or `job_deadline_seconds` was set, so output the operator's deadline allowed
  (a slow disk under `-o`, a slow reader of standard output) was cut off at 30
  seconds: standard output stopped mid-document and an existing `-o` file kept
  the previous report, while the message ("abandoned-worker exit deadline
  exceeded") said neither. The watchdog was also never cancelled: where the
  hard exit is replaced (the test suite, in-process callers), it fired 30
  seconds after the call had returned, called the exit again and stopped any
  clone running at that moment. It is now armed only when no job deadline is
  set, or when Ctrl-C interrupts report output: the interrupt also cancels the
  job deadline, and interpreter exit would then wait for the blocked worker
  indefinitely. It is cancelled when the call ends with any other exception,
  including a failed report, and its message says that coverage is incomplete,
  that the report may be missing or truncated and that an existing output file
  may not have been replaced. Affects CLI scans in which a connector timed out;
  `docs/production.md` documents the limit, and `docs/scanning.md` now gives
  exit 1 when the report could not be written. Regression tests cover a set job
  deadline, Ctrl-C during output with and without one, the cancelled watchdog
  after a written and a failed report, and the message.
- **A whitespace-header JWT after a long dotted segment was kept (#237).**
  #237's second reading, which withholds a JWT whose header JSON is written
  with whitespace (`IHsi…`, `eyAi…`, `ewoi…`), took three dotted segments from
  the first one of 16 or more characters. When that segment was no header, the
  search went on after the third segment, so the token's own header, read only
  as the second or third segment of that run, was never tried. A token right
  after such a segment (`com.example.authenticationservice.<token>`,
  `request_identifier_0001.<token>`, a URL path segment of that length) was
  kept whole in report text, evidence and logs, still verifiable. A run that is
  no token is now searched again from its second segment. Each segment is
  matched at most three times, so the pass stays linear. Affects scans whose
  evidence holds such a token after a dotted name: its report text, and finding
  ids derived from it, change, and reports written before this change may
  still show it. Regression tests cover five prefixes and three header layouts
  through `sanitize_text` and `sanitize`, and time dotted runs of 256 KB and
  1 MB.
- **The secret gate and the AI review sanitizer missed most whitespace JWT
  headers (#237).** `tools/check_secrets.py` (`make secrets`, the
  `no-hardcoded-secrets` hook and CI) and `tools/ai_review/sanitize.py`
  recognized such a header by seven fixed base64url prefixes (`IHsi`, `eyAi`,
  `eyAg`, `eyAK`, `ewo`, `CXsi`, `Cnsi`). Of the 440 layouts with up to two
  whitespace bytes before and after the `{`, all of which PyJWT accepts, they
  caught 11: a tab or carriage return after the `{` (`ewki`, `ew0K`), two bytes
  before it (`ICB7`, `DQp7`) or three or more (`ICAg…`) passed the gate and
  could reach posted review text. Both now match the base64url encoding of any
  number of spaces, tabs, line feeds and carriage returns before the `{` and
  any after it, as a regular expression that stays linear. As before they do
  not decode the header or require `alg`; runtime redaction remains the
  complete check. Affects contributors, whose tracked file holding such a token
  now fails `make secrets`, and AI review gate output; every tracked file still
  passes. Regression tests cover every layout with up to four bytes before and
  two after the `{`, longer runs, and three hostile inputs for linear time.
- **A JWT in a dotted chain or after a doubly encoded separator kept its
  payload and signature.** Both leaks pre-date #237, whose
  `docs/production.md` entry said whitespace-header tokens were withheld
  everywhere. The `eyJ` rule took three dotted segments from the first `eyJ`
  it met, and that `eyJ` can be an unrelated segment or the `eyJ` payload of a
  whitespace-header token: `eyJ4IjoxfQ.v2.<token>`, `<token>.<token>` and
  `<token>-<token>` withheld up to the next token's header and kept its
  payload and signature, verifiable once the header is guessed. An encrypted
  token (JWE, five segments) kept its ciphertext and tag under either reading.
  A token is now withheld to the end of its dotted chain, with any text joined
  on by a dot (`<token>.json`, a full stop right after it); the chain is read
  once after the match, not by the pattern that is searched again after a run
  that is no token, so the pass stays linear. A token right after a doubly
  percent-encoded separator (`%253D`, `%252F`, as in a redirect URL nested in
  another's query) followed a hex letter, which neither reading took as a
  boundary, and was kept whole for every header layout; both readings now
  start after such an escape as after a single one. `docs/production.md` now
  describes the coverage and names the gaps that remain: a token glued
  directly to letters, one after a separator encoded three times, and a UTF-16
  header. Affects report text, evidence and logs that held such a token, and
  finding ids derived from them; reports written before this change may still
  show it. Regression tests cover seven chains and a JWE with compact and
  whitespace headers through `sanitize_text` and `sanitize`, and three doubly
  encoded prefixes with four header layouts; the hostile-input timing test
  gains a long chain after each kind of token and a run of double-encoded
  candidates.
- **A report could land behind another user's link (#237).**
  `write_private_text` checked only the links named in the output path itself,
  then let `os.path.realpath` follow the rest unchecked. An operator's link to
  another user's link (`mine -> shared -> victim/`), a link inside another
  link's target (`mine -> shared/sub`), or a link planted where a component was
  missing when it was checked put the report, mode 0600 and owned by the
  operator, in a directory the other user chose. The output directory is now
  resolved one component at a time, as the kernel resolves it: every link met,
  in the path or in a link's target, must be owned by root or the current user,
  more than 40 links are refused as a loop, and a missing component, or one
  that is not a directory, is an error instead of being resolved later (as
  first written, a link to `notes.txt/../a` put the report in `a`, as
  `realpath` had, where the kernel fails with `ENOTDIR`). `..` in the output
  path is resolved lexically first, as since #237 (before it the kernel
  resolved `..` after the link), so `-o mylink/../r.json` writes beside
  `mylink`, not in the parent of the link's target; `SECURITY.md`,
  `docs/production.md` and the controls guide now say so, and the dashboard
  guide states the link rule. Affects `-o` and `--inventory-json` paths that
  run through a chain of links; links owned by the operator or root (macOS
  `/tmp`) are followed as before. Regression tests give links to another uid
  with `lchown` (as root) and cover a chain, a link inside a target, a link
  planted after the check, own and root-owned links, relative links with `..`
  (`L -> M/../x` with `M -> far/deep` lands in `far/x`, not in the `x` beside
  `L`), a link through a regular file, a loop and a missing directory.
- **Long output names in multibyte characters failed (#237).**
  `_temporary_name` cut the destination name at 200 characters, but `NAME_MAX`
  counts bytes: a legal name of 253 to 255 bytes in CJK, accented or emoji
  characters (83 CJK characters and `.json`) gave a temporary name over 255
  bytes, and the write failed with "could not write report", although #237
  said long legal names no longer fail. The name is now cut at whole characters
  to at most 200 bytes. Affects every output written under such a name.
  Regression tests cover CJK, accented and emoji names.
- **The configuration read diagnostic did not mention the encoding (#237).** A
  configuration file that is not UTF-8 got "it must be a readable regular file
  of at most 8 MiB", which leaves out the actual cause; the message now asks
  for "a readable regular UTF-8 text file of at most 8 MiB". Affects operators
  with a Latin-1 or UTF-16 configuration file. A regression test covers a
  Latin-1 file.
- **identity.jwt shortened `kid` and claim names before redacting them
  (#237).** #237 bounded both but cut them before the finding was sanitized,
  against its own "sanitize before shortening" comment: a token inside a `kid`
  or a claim name that straddled the 200- or 64-character cut lost its third
  segment, no longer looked like a token, and its header and the start of its
  payload were reported. Both are now sanitized first and cut after, as agent
  claim values already were; only the 100 claim names reported are sanitized,
  which keeps a token of many claims cheap. Affects identity.jwt findings for
  tokens that carry such a header or claim: their `metadata.kid` and
  `metadata.claim_names` change. A regression test places a token across both
  cuts.
- **HTTP transport contracts carried from draft #231; the private-address
  claim is qualified.** Copilot's commit 82093b7 is cherry-picked with its
  authorship: `docs/api/http.md` and the `shadowscan/utils/http.py` module
  docstring state the transport's invariants, and
  `tests/unit/test_http_contracts.py` fails when a urllib3 upgrade changes the
  request hook, the response shutdown and release methods or the per-client
  pool-class mapping the transport relies on. As written, both texts called the
  refusal of private and cloud-metadata addresses unconditional, although the
  trusted `allow_private_origin` opt-in (scan-wide, or per connector since
  #235) lifts it and `--deny-private-origin` overrides both, and they predated
  #236's bounded DNS resolution. They now call the refusal the default, name
  the opt-in and its override, say that the numeric connection and TLS hostname
  verification still apply under it, and describe the bounded lookup (at most
  20 seconds, less under the client timeout, the acquisition deadline or the
  connector deadline) and the refused duck-typed `session`. `docs/api/http.md`
  first named urllib3's `NameResolutionError` as the failure at connection, a
  type an `HttpClient` caller never sees: the client reports it as
  `requests.ConnectionError`, or as `ValueError` once the acquisition deadline
  has passed, as the page now says and a test of both pins. A contract
  assertion pins that the private connection class differs from the public one
  only in that flag. Documentation and tests only; runtime behavior is
  unchanged. Affects readers of the API reference and contributors who change
  the urllib3 constraint or lock. The rest of #231 (the process plugin default,
  schema-aware `--set` coercion, the `engine_state.py` and `http_transport.py`
  split and the Docker Python pin guard) is not carried, and the draft stays
  open for it.
- **Four hardening hunks carried from draft #232.** Rewritten as one commit
  that credits Copilot as co-author:
  - `safe_git_env` passed the scanner's `GITHUB_TOKEN`, `GH_TOKEN` and
    `GITLAB_TOKEN` to every Git child process, which runs on untrusted
    repository content, although Git never needs them: a clone authenticates
    with its origin-scoped header. They are now removed like the report
    identity key. Affects workers that export those variables; configured
    connectors behave as before.
  - `checkout_has_lfs_pointers` walked the clone by path names saved from
    `scandir` and followed links in the checkout's own path, so a directory
    replaced by a link between the listing and the open was walked outside the
    checkout, and a file swapped after its `lstat` was read unchecked. It now
    opens the root with `open_confined_directory` and each directory and file
    relative to an open descriptor without following links, compares the
    opened file with its listing before and after reading it, and gives
    "unknown" (the clone "could not be inspected", incomplete) instead of a
    clean result for a replaced entry, a directory nested more than 64 levels
    deep, or a platform without descriptor-relative no-follow opens. Affects
    `code.github` and `code.gitlab` clones; only such deep checkouts change
    outcome in practice.
  - Process-mode plugin workers, where neither `/proc/self/fd` nor `/dev/fd`
    lists descriptors, made only descriptors 3 to 4095 non-inheritable, so a
    worker with a higher descriptor could pass it to a program the plugin
    starts. The range now runs to the open-file soft limit (`RLIMIT_NOFILE`,
    else `SC_OPEN_MAX`), capped at 2^20. Linux and macOS list descriptors and
    are unaffected.
  - The Dockerfile comment and `docs/production.md` said to drop the Wolfi
    Python pin once `python3.12 -c "import hashlib; hashlib.sha224"` passes;
    that only looks the name up. The check is now `hashlib.sha224(b'')`, which
    builds a hash.

  Regression tests: provider token variables in `safe_git_env`; a link in the
  checkout path, missing platform primitives, a directory replaced by a link or
  by another real directory during the walk, a file replaced before it is
  opened or changed in place while it is read, and descriptors closed at the
  depth limit and the deadline; the descriptor-limit fallbacks. Each fails
  without its code hunk, and the directory identity check and the after-read
  comparison, which no carried test reached, each fail a test of their own
  when removed alone; the comment fix has no test. Two of #232's tests are
  adapted: the infinite soft limit uses the platform's `RLIM_INFINITY` (-1 is
  not infinity on macOS, where the suite also runs), and a same-content file
  replacement gets a distinct modification time, because within one coarse
  clock tick a new file can reuse the old inode and every timestamp. Not
  carried, and left in the open draft: the clone credential temporary file,
  plugin worker key separation, triage `allow_custom_base_url`, the Python pin
  CI probe, the parser fuzz tests and the `validate_url` `is not None` change.
- **A spent DNS budget raced the resolver, and stalled lookups piled up
  threads (#236).** `_resolve_bounded` started its worker before looking at
  the budget, so once a connector deadline had passed each lookup still
  started a thread and then waited zero seconds: a fast answer could win that
  race and the lookup went ahead (its answer still checked), a slower one was
  refused, so the outcome after the deadline depended on scheduling. Nothing
  limited the abandoned workers either, and connectors that check one endpoint
  per project or repository (Azure Foundry, remote repositories) keep calling
  `validate_url` after their deadline: in a probe, 500 lookups against a
  stalled resolver left 500 live threads. A spent (or NaN) budget now refuses
  before any thread starts, and at most 32 workers (`_MAX_RESOLVER_THREADS`)
  run at once; a lookup waits within its budget for a free slot and otherwise
  fails closed. A slot is returned exactly once: by the worker when the
  resolver returns, or by the lookup when its budget is spent once the slot
  is taken or when its worker cannot be built or started. That release
  covered only `RuntimeError`, so 32 thread starts failing with `MemoryError`
  under memory pressure left no slot, and every later lookup in the process
  refused; a one-shot guard keeps an interrupt that arrives after the thread
  started from returning the slot twice. The clone pin lookup
  (`resolve_destination`) shares the resolver and gains both bounds. Every
  new refusal is the `TimeoutError` callers already turn into a
  refusal (`ValueError` in the preflight, `NameResolutionError` at connection,
  `DestinationUnresolved` for a clone), so no lookup goes ahead without an
  answer to check. Affects scans whose resolver stalls or whose connector
  deadline passes during collection, which were already incomplete.
  Regression tests cover a spent budget with an instant resolver (no thread
  and a refusal every time, directly, through `validate_url` and through
  `resolve_destination`), 20 lookups against a stalled resolver with three
  slots, a lookup that waits for a slot, slots freed once the resolver
  returns, a worker thread that cannot be built or started (`RuntimeError`
  and `MemoryError`), one interrupted after it started, and lookups whose
  budget ends right after they take the only slot.
- **The late-DNS test was flaky and left the post-resolution check
  untested (#236).** The test gave the acquisition deadline 50 ms and the
  resolver a 100 ms sleep, so a scheduler stall raised the guard's
  `ValueError` instead of the expected `NameResolutionError` (45 of 300 runs
  under CPU load). And since the bounded wait gives up on that resolver first,
  deleting the check after resolution in `_new_conn`, which keeps a late
  answer from opening a connection, failed no test. Two deterministic tests
  replace it: a resolver that fires the acquisition timer's callback and then
  answers, which only that check refuses, and a guard pinned at 50 ms with a
  resolver blocked on an event, where a spy requires the DNS wait budget to be
  exactly the guard's. Deleting either guard line in `_new_conn` now fails a
  test. Tests only.
- **The URL preflight ignored the client timeout and deadline (#236).**
  `SECURITY.md` said the `validate_url` preflight applied the same bound as the
  connection-time lookup, tightened by the client timeout and the acquisition
  deadline, but only the worker's connector deadline tightened it: a request
  from `HttpClient(timeout=5)`, or from a client with its own `deadline` (LLM
  triage sets its budget that way), waited up to 20 seconds on a stalled
  resolver before its connection-time lookup. `validate_url` gains a
  keyword-only `dns_budget`, and `HttpClient` passes its timeout, cut to its
  remaining deadline, for the request, redirect and Link and OData pagination
  preflights. Other callers (Git clone checks, SDK, MCP registry and JWKS
  preflights) and the clone pin lookup still get only the connector deadline;
  `SECURITY.md`, `docs/production.md`, `docs/api/http.md` and the LLM triage
  guide (which still called the resolver unbounded) now say so, and that one
  request can wait on DNS twice. Affects `HttpClient` requests whose resolver
  stalls. Regression tests spy on the budget of every preflight with and
  without a deadline, end a stalled preflight at the client timeout and at
  the deadline, and pin the client timeout at connection, which no test
  covered.
- **A Black Duck service without a Bridge CLI pin skipped the job (#236).**
  #236 put `vars.BRIDGECLI_DOWNLOAD_VERSION != ''` in the job's `if:`, so a
  configured service without the pin skipped the job, and a skipped job
  reports success: a misconfigured integration looked like an unconfigured
  one. The job is gated on the service variables alone again, and its first
  step, before checkout, fails with an `::error::` unless the variable holds
  an `x.y.z` version (an empty, blank or `latest` value would let the action
  download the vendor's current CLI). The pin fixes a version, not content:
  the action downloads that version's bundle from `repo.blackduck.com` over
  HTTPS with no checksum check, and tools the Bridge CLI fetches for a scan are
  not covered. The workflow comment, the workflow README and the #236 entry
  below now say so instead of claiming that unpinned vendor code can no longer
  run. Affects maintainers who enable Black Duck. Policy tests check that the
  job requires and passes the pin, and run the committed check against empty,
  blank, padded, partial, pre-release and valid values.
- **Names importable from `filesystem.py` before the helper move were dropped
  (#236).** The move left 40 names that
  `shadowscan.connectors.code.filesystem` exposed on main unimportable from
  it, among them `NegativeContext`, `negative_context`, the `*_WEIGHT_SCALE`
  constants and the docs, example and generated path predicates; main's own
  `tests/unit/test_negative_context.py` no longer imported, while ADR-005 and
  the #236 entry said the moved names were re-imported. `filesystem.py` now
  re-imports each of them from its defining module, the names it had only
  imported for itself (`ast`, `tomllib`, `has_template_markers`, the CI
  pipeline name sets and the marked JSONC loader) included, so the module's
  names match main again. Patch such a name in its defining module: rebinding
  it in `filesystem.py` does not change the helpers. Affects plugins and
  scripts that import these names from `filesystem`. A regression test pins
  each name to its defining module's object.

### Cap runtime dep ranges at the next major (October 15)

- `pyproject.toml` now caps `click`, `rich`, `PyYAML`, `requests` and
  `PyJWT[crypto]` at the next major, and does the same for the optional
  cloud SDKs (`boto3`, `google-auth`, `azure-identity`, `oci`) in `aws`,
  `gcp`, `azure`, `oci` and the aggregate `cloud` extra. `urllib3` already
  carried `<3`. `regex` stays uncapped: it is calendar-versioned with no
  major to cap, and a year cap would shut out every later release,
  security fixes included.
- The caps protect the unlocked `pip install NexusShadowScan` path from
  silently resolving a user into an untested upstream major; deployment
  and CI continue to install the hash-locked `requirements.lock`, so
  the reviewed version set does not change.
- All current `requirements.lock` pins sit inside the new caps (click
  8.5.0, rich 15.0.0, PyYAML 6.0.3, requests 2.34.2, PyJWT 2.15.0,
  regex 2026.9.10, boto3 1.43.101, google-auth 2.58.0, azure-identity
  1.25.3, oci 2.187.0); the lock does not need regeneration.

### Per-connector private-origin grants, block-scalar opaque secrets, threat model (October 15)

- **Redaction (credential policy).** A YAML block scalar under a name that
  carries a credential only when its value is opaque — bare `key`, as opposed
  to `password` or `api_key`, which always do — is now withheld when the block
  holds an opaque value. `_redact_yaml_multiline_values` gated on the
  always-sensitive name test alone, so `key: |` over a Kubernetes secret's
  base64 blob kept its text while the single-line `key: <opaque>` beside it was
  withheld by the assignment pass; only a value with a recognizable format
  (`sk-`, a PEM header) was caught in the block form. The block's lines
  without whitespace are joined without a separator at each indentation, and
  each line is read on its own (see Integration review fixes above), with the
  same `_credential_literal` test the single-line pass uses, so a wrapped base64
  blob is tested as the one value it encodes, while a path, a sentence, a
  placeholder and a name that does not name a credential (`data: |`) keep their
  text. Regression tests cover every block marker, the quoted spellings of the
  key, the wrapped form and each value that must survive.
- **Egress policy.** Every connector now accepts `allow_private_origin`,
  lifting the loopback, link-local, private and cloud-metadata refusal for that
  connector alone. Reaching one internal gateway previously required
  `options.allow_private_origin`, which applies to every connector in the
  configuration, so a repository, endpoint or cloud connector in the same scan
  also lost the refusal. A connector that sets the key uses its own value and
  one that does not inherits the scan-wide setting, so a connector-level `false`
  keeps a connector public under a scan-wide grant; an explicit
  `--deny-private-origin` overrides both (see Integration review fixes above).
  The key is normalised like the other connector switches, so an interpolated
  `"false"` cannot enable it, and a non-boolean fails closed without echoing
  its value. The engine reads it
  for both the connector lookup, which imports an approved plugin, and the
  collection it wraps.
- **Threat model.** `docs/security/threat-model.md` consolidates the trust
  boundaries that `AGENTS.md` holds for contributors and the egress, limit and
  fail-closed notes spread through `docs/production.md` into one page per
  boundary, naming the control and the module that enforces it, with the
  residual risks stated plainly: best-effort redaction, a plugin that is not a
  sandbox, external transports outside the HTTPS client's policy, offline
  replay that is not live acceptance, author-written corpora and the absence of
  independent review.

### Filesystem connector helpers move into bounded modules (October 15)

- The module-level helpers of `connectors/code/filesystem.py` (6,249 lines)
  moved, verbatim, into five modules beside it: `path_context.py` (test,
  documentation, example, generated and CI-pipeline paths and their
  discounts), `project_evidence.py` (`_ProjectEvidence`, corroboration and
  weak mentions), `model_identifiers.py` (model-id literal recognition),
  `source_text.py` (offset-preserving text shaping and the structured
  credential context for excerpt redaction) and `excerpts.py`. The
  connector class is unchanged and `filesystem.py` (now about 5,200 lines)
  re-imports every name that was importable from it before the move,
  including those it no longer uses (see Integration review fixes above).
  `_LazyExcerpt` takes the connector's redacted-lines reader instead of the
  connector, which removes the helper module's dependency on the class.
- No behaviour change: with a fixed `SHADOWSCAN_IDENTITY_KEY`, the offline
  demo report before and after the move is identical apart from timestamps
  and `collection_scope.fingerprint`, which covers the scanner source digest
  by design; the evaluation corpora and the full test suite are unchanged.
  ADR-005 records this as continuing its beside-the-class pattern; its four
  collaborator-class moves remain open.

### Bounded DNS resolution and a typed HttpClient session seam (October 15)

- `shadowscan.utils.http` now resolves names in a bounded worker
  (`_resolve_bounded`): `socket.getaddrinfo` has no timeout of its own, so a
  stalled system resolver could previously hold a connector worker past every
  cooperative deadline check. Each wait is at most 20 seconds
  (`_RESOLVE_TIMEOUT`): at connection it is tightened by the client timeout
  and the acquisition deadline, and in the `validate_url` preflight by the
  connector deadline and, for `HttpClient`, by the client timeout and
  deadline (see Integration review fixes above; as first merged, the
  preflight followed the connector deadline alone). On expiry the request
  fails closed (`NameResolutionError` at connection, `ValueError` in the
  preflight, so transports such as git that rely on the preflight stop too)
  and the abandoned worker's late answer is discarded, never connected to. A
  name that does not resolve (NXDOMAIN) keeps its existing meaning at both
  sites. The late-DNS regression tests in
  `tests/unit/test_http_response_integrity.py` pin the DNS wait budget to the
  acquisition deadline and refuse an answer that arrives after it (as first
  merged, one timing-dependent test stood for both and asserted no timing),
  and `tests/unit/test_http_dns_deadline.py` covers the stalled-resolver,
  expired-deadline, late-answer, NXDOMAIN, client-timeout, client-deadline
  and worker-cap cases.
  SECURITY.md and the production resource-limit notes describe the bounded
  wait; a process/job supervisor is still the only hard execution limit.
- `HttpClient` refuses a duck-typed `session` at construction with
  `TypeError`: the proxy, adapter-identity and verify checks assume requests
  semantics, and a stand-in that is neither a `requests.Session` nor a
  `unittest.mock` double (the documented test seam, which carries no real
  transport) would previously have sent requests with those checks silently
  skipped.

### Black Duck job requires a reviewed Bridge CLI pin (October 15)

- The optional Black Duck workflow job now also requires the repository
  variable `BRIDGECLI_DOWNLOAD_VERSION` and passes it to the action as
  `bridgecli_download_version` (an input verified against the pinned
  action revision). The wrapper action was already pinned by commit SHA,
  but at run time it downloads the Bridge CLI, and the committed
  configuration would have fetched the vendor's current, unreviewed CLI
  the moment a service variable was set. Configuring a service without
  an `x.y.z` pin now fails the job at its first step, before checkout (as
  first merged, it skipped the job, which reports success; see Integration
  review fixes above). The variable pins the Bridge CLI by version, not by
  content: the action downloads that version's bundle from
  `repo.blackduck.com` over HTTPS with no checksum check, and tools the
  Bridge CLI fetches for a scan are not covered. The workflow README
  documents the second variable.

### Review hardening: redaction, clone mode, output paths, SARIF and diagnostics (October 15)

- Redaction withholds JWTs whose header JSON is written with whitespace and so
  does not encode to `eyJ` (`IHsi`, `eyAi`, `ewo`...); PyJWT and the
  identity.jwt decoder accept them, and a nested one in a claim was persisted
  verbatim. A second, budgeted reading accepts a dotted run when its first
  segment decodes to a JSON object with an `alg` member. `tools/check_secrets.py`
  and the AI review sanitizer recognize such a header by its base64url shape,
  with any JSON whitespace before or after its `{` (`ewki`, `ew0K`, `ICB7`,
  `DQp7`...); unlike redaction they do not decode it or require `alg`, and they
  report a compact `eyJ` header only with an `eyJ` payload.
- Clone mode requires Git 2.45 (`MINIMUM_CLONE_GIT`): the clone's metadata
  reads pass `--no-lazy-fetch`, which older Git rejects, so every clone on 2.32
  to 2.44 ended incomplete without provenance while the docs promised a scan.
  The three doc passages are corrected and the version tests assert 2.43 and
  2.44 fall back to API mode.
- A provider clone URL must name the listed repository, not just the API
  origin; GitLab under a relative URL root is supported.
- `write_private_text` refuses a path through a directory link owned by another
  user and creates and renames the temporary file relative to the opened real
  directory, matching the documented "never through a symbolic link" claim,
  which now states that rule. Long legal output names no longer fail.
- SARIF artifact locations resolve `.`/`..`, drop locations that climb above
  the root or name a network path, cap `startLine` at the 32-bit limit and
  escape lone surrogates instead of failing the render.
- identity.jwt refuses `expected_issuer`/`allowed_algorithms` without
  `jwks_url`, classifies tokens with a non-string `kid` or a `crit` header as
  unverified instead of dropping them, and bounds agent claim values and claim
  names.
- Configuration diagnostics quote an unknown key or connector name only when it
  is a lowercase name of at most 40 characters with at most three digits, so an
  unprefixed token pasted as a key is not echoed; an unreadable, oversized or
  special configuration file gets a read diagnostic; `llm_triage.provider` and
  `min_level` of the wrong type raise `TriageConfigError`.
- `terminal_text` and saved reports escape every Unicode format character, the
  variation selectors and other blank characters.

### Security hardening: plugin isolation, pre-clone DNS check, exit watchdog (October 15)

- **Plugin process isolation by default.** `plugin_execution` now defaults
  to `process` so third-party plugins run in isolated child processes
  instead of sharing the scanner's address space.  Operators can still set
  `plugin_execution: thread` in configuration to restore the previous
  behavior. Some plugins and embedding scripts now fail closed (exit 3) under
  the new default; the integration review fixes above list them.
- **Pre-clone DNS validation.** `validate_clone_destination()` resolved the
  clone URL hostname and rejected private, loopback, link-local, and
  cloud-metadata addresses before handing the URL to git. It did not pin Git
  to those addresses or narrow the gap to Git's own lookup, and it repeated
  `validate_url`'s check; the integration review fixes above replace it with
  `clone_pins()`, which does pin Git.
- **Bounded exit watchdog for abandoned workers.** When the engine detects
  timed-out connector workers and no job deadline is set (see the integration
  review fixes above), a 30-second daemon-thread watchdog arms
  automatically so the CLI process cannot hang indefinitely during report
  emission or clone cleanup.  The watchdog calls `os._exit()` as a last
  resort if the normal exit path blocks; the report may then be missing or
  truncated.

### Collection completeness and registry assurance (October 15)

- Make scenarios require a valid blueprint and an explicit flow array. Invalid
  detail responses mark collection incomplete instead of reading as an empty
  workflow. Zapier validates pagination metadata before accepting the end of
  an inventory. Valid empty workflows and terminal pages remain supported.
- CODEOWNERS reads stay relative to the directory opened for source collection.
  A root replacement detected before ownership lookup leaves the scan incomplete;
  later replacements cannot redirect the anchored ownership reads. A candidate
  below a file named like its directory (`docs`, `.github`) is absent; a link in
  its path is not followed and leaves ownership incomplete.
- A gateway caller whose identity is operator-asserted, unverified or missing
  authenticated assurance remains shadow when an inventory is supplied. Exact
  card bindings are retained as review candidates; they no longer confer an
  owner, declared governance or registration risk credit. Rescan gateway logs
  and establish fresh comparison baselines after upgrading.
- CloudTrail (`cloud.aws`) and Cloud Audit Log (`cloud.gcp`) callers record
  `metadata.caller_identity_assurance`: `provider-authenticated-field` for the
  principal the provider authenticated, so exact bindings keep approving them
  (without the `registry-identity-unverified` tag earlier scans added), and
  `unverified` for the `unknown` caller of events without a principal, which is
  a review candidate.

### Medium-severity review corrections

- Generic SaaS inventory retains whole-record credential context when selecting
  report and matching fields. Known credentials are removed before splitting or
  shortening values, and cannot establish product or permission evidence;
  credential context is never retained in findings. Every value under a
  credential name is learned however it looks (`Abcd1234`, `12345678`,
  `MyTestPassword99`, `prod-secret-here-7Hq2`), except a placeholder as the
  whole value (`none`, `****`, `xxxxxxxx`, `changeme`, `your_secret`), which
  withholds nothing, and a value shorter than eight characters, which would
  withhold every field containing it: it withholds only a field equal to it,
  and nothing when it is a flag (`N`, `-`, `Yes`, `N/A`). A short credential
  inside a longer field (`ChatGPT hunter2`) is still shown. An earlier
  revision of this change also left out every value the placeholder heuristic
  (`looks_like_placeholder`) matches, such as one containing `test`, `demo` or
  `here`, so a copy of such a credential in the name, owner, status or ID was
  printed in a complete scan; regenerate reports made with it. A name withheld
  entirely by a credential leaves the scan incomplete instead of silently
  omitting the app.
- Generic SaaS findings whose resource a credential redacts take their ID from
  the redacted resource and a keyed pseudonym of the raw one, not a public
  digest that confirmed guessed credentials. Their IDs change and are scan-local
  (`metadata.identity_scope: run`) unless `SHADOWSCAN_IDENTITY_KEY` is set;
  distinct raw resources keep distinct IDs. `diff` names these apps beside
  gateway callers when it asks for the key.
- Zapier and Workato reject provider error envelopes and malformed collections
  even beside empty result arrays: that page is omitted. A missing or malformed
  Zapier continuation keeps the page's Zaps and marks coverage incomplete.
  Earlier valid pages survive with incomplete coverage.
- Teams combines catalog and installed-version definitions with version, bot,
  installation and team provenance. Installations of one definition are counted
  (`installation_count`, `team_count`) with a sample of at most 20 teams, so the
  finding stays bounded however many teams install the app. At most 20 definition
  observations, versions and bot IDs are listed, in sorted order, and the rest
  are counted (`definition_observations_omitted`, `versions_omitted`,
  `bot_ids_omitted`): 3,000 installations of distinct definitions made a 953 KB
  finding, and at 8,000 it was omitted and the scan incomplete. Permissions and
  conflict detection read every observation. It reports requested
  RSC permissions, not verified grants; contradictory observations of one
  definition mark coverage incomplete. Scalar version/bot fields are populated
  only when unambiguous; otherwise they are `null`.
- JavaScript/TypeScript destructuring declarations invalidate shadowed SDK
  constructor bindings, including aliases, nested patterns, defaults and rest
  bindings. Property keys, initializer references and members named like a
  declaration keyword (`options.const`) do not declare bindings.
- Discovery benchmark comparisons reject newly unavailable runs independently
  of F1, require every selected repository in both metric sets, and never label
  failed or incomplete negative scans clean. Adapter-approved nonzero exits
  remain successful runs; partial facts remain diagnostic evidence.
- Added offline fixtures and regression tests for all five corrections. These
  automated checks do not establish live tenant acceptance or field accuracy.

### Review-driven hardening: redaction, SSRF, parser cost, detection coverage (October 15)

- **Credential destinations.** `validate_url` rejects a backslash anywhere in the URL: a host
  such as `evil.example\.services.ai.azure.com` reads as a Foundry host to `urlsplit` but as
  `evil.example` to the HTTP transport. The Azure Foundry bearer-token endpoint is now matched
  against a full-host regex with a canonical-netloc check instead of a hostname suffix.
- **Redaction.** Amazon Bedrock API keys (`ABSK…` and `bedrock-api-key-…`), Zapier MCP server
  URLs whose path is the credential (`mcp.zapier.com/api/mcp/s/…`, `actions.zapier.com/mcp/…`),
  and `user:password` in URLs whose scheme contains an underscore (SQLAlchemy dialects such as
  `oracle+cx_oracle://`) are now withheld. A handful of credential environment-variable names
  whose last word is not a credential word (`AWS_BEARER_TOKEN_BEDROCK`, `LOBE_ACCESS_CODE`,
  `FLOWISE_SECRETKEY_OVERWRITE`, `MODAL_TOKEN_ID`, `ZAPIER_MCP_URL`) are covered, and a test
  derives the required coverage from the signature packs. Source excerpts, semantic
  configuration metadata and the provider text connectors shorten for a report (agent,
  knowledge-base and flow descriptions, instructions and system prompts, welcome messages,
  trigger conditions, dynamic-group matching rules and policy statements from the AWS, Azure,
  GCP, OCI, Entra, Make, Salesforce and ServiceNow connectors) are redacted before they are
  shortened, so a cut can no longer separate a credential from the context that identifies it.
  Lists of names (scopes, permissions, variable names) are still cut first. A provider text
  field that is not a string (a list or a number in an AWS, Azure, GCP, OCI, Salesforce or
  ServiceNow description, instruction, welcome message or trigger condition) still rejects its
  record as malformed, which leaves the scan incomplete, as when the text was cut first; it
  never reaches the report whole.
- **LLM triage.** The redacted summary sent to the model now withholds e-mail addresses and IP
  addresses wherever they appear in a title or evidence description, and covers more
  identity-bearing metadata keys, matching the privacy the documentation describes.
- **Bounded parsing.** The runtime-process connector no longer runs a backtracking package regex
  on an over-long argument (an unprivileged local process or one offline row could otherwise
  stall every connector while the GIL is held), and the Python source tokenizer charges the
  per-input matching budget between tokens, so a single very long line fails closed on CPython
  3.12.0–3.12.3 instead of burning a core. A source excerpt judges random-looking literals before
  its cut by reading only the part it shows and a 256-character lookahead, not the whole line:
  a minified bundle line with a few dozen credential-shaped tokens no longer exhausts the
  matching budget and leaves the scan incomplete. A literal that runs past the part read and is
  withheld ends the excerpt.
- **Detection coverage.** MCP client configurations and CloudFormation/ARM JSON templates are
  recognised from their parsed structure rather than a byte-prefix window, so leading padding
  can no longer hide a server table or an AI resource on a complete scan. The MCP tool-poisoning
  rules read the same window the instruction audit inspects. The Kubernetes connector inspects
  `initContainers` (native sidecars) and `ephemeralContainers`; a privileged one adds the
  `privileged-pod` tag, and a null one (an empty field as Helm renders it) is absent, not
  malformed. An endpoint record value past the sanitizer's safety limits is withheld with one
  fixed-text warning that marks the scan incomplete, instead of aborting the connector.
- **Fleet and reporters.** A fleet merge drops any advisory `llm_triage` block a source carries,
  so one source cannot plant a verdict on another's finding. Out-of-range report timestamps are
  omitted from OCSF, CycloneDX and SARIF output instead of aborting the whole report.
- **Engine, CLI and plugins.** Every plugin finding is attributed to the plugin, in thread and
  process mode, with the id the plugin's own name and the finding's resource give, whatever name
  it was built under or id it was given (`id=`, `dataclasses.replace` of a finding built under
  another name), so a plugin can neither report under a built-in connector's name nor take the
  id of that connector's finding for the same resource, which merged the two. Plugin worker
  processes are started with `PYTHONSAFEPATH` so a scanned checkout in the working directory
  cannot shadow `multiprocessing`; it is set only while a worker starts, and the previous
  environment is restored, so programs the scanner or an embedding application starts later keep
  their script directory on `sys.path`. The changed-file git diff passes
  `--no-ext-diff`/`--no-textconv`. Plugin names must be lowercase ASCII `namespace.provider`, so
  a confusable cannot read as a built-in; a plugin whose name has an uppercase letter or an
  underscore no longer loads. The `urllib3` logger is pinned to ERROR so a malformed upstream
  response cannot log a request URL. The `inventory check` and `signatures list` commands strip
  terminal control sequences from untrusted fields.

### Runtime identity, collection completeness and semantic fallback (October 15)

- Runtime process classification now reads the executed target of supported
  launchers, rather than treating later application arguments or package-source
  options as executed AI tools. A package runner an interpreter runs
  (`node /usr/local/bin/npx -y pkg`, `node.exe ...\npx-cli.js`,
  `python3 /usr/bin/pipx run ...`, `python -m pipx`) is read as that runner, and
  the command line's first argument is read when the executable is only the
  interpreter (npm's `npm exec pkg` process title on node), split into words
  when it is one argument with spaces, as a live `/proc` shows a title. Launch
  options are read with each launcher's grammar (`--name=value`, Deno permission
  flags, `node --inspect`, `npx --prefer-offline`, `uv run --frozen`,
  `uv run -m`, `python -P` and combined flags such as `-Im`); launches with
  options the grammar does not recognize are not reported. A command line cut by
  an argument/byte bound marks coverage incomplete, even when the retained
  prefix produces no finding, when the dropped arguments could change what runs
  (none left, or a launcher's target unread); a long command line of another
  program, or one whose tool was read, is classified from its leading arguments,
  and one counted warning reports them. A row an export marks
  `argv_truncated: true` loses its final argument, which the cut may have
  shortened, as a live command line over the byte limit does: a launcher target
  in it is undecided (coverage incomplete) rather than classified as complete or
  reported under a cut name (`server-gi`). Host and user identities are retained
  in full within validated input limits, so different devices or users cannot
  merge through a shortened display prefix.
- GitHub App installation inventories validate declared totals against unique
  returned installation IDs, across all pages of a live listing or of an offline
  export file (one page envelope per line is accepted). Inconsistent or
  malformed count information marks coverage incomplete while retaining valid
  observations; the existing HTTP origin, pagination and response-size
  protections remain in effect.
- Python source and notebook cells that the scanner's interpreter cannot parse
  retain lexical observations but mark semantic analysis incomplete. Unparsed
  ranges cannot acquire agent classification or execution capabilities from
  semantic claims that were not established; independently parsed neighboring
  source remains usable. In a test path the scan discounts, source that does not
  parse only warns unless `strict_coverage` is set. Notebook cells declared
  another language (under `%%bash`, `%%sql`, `%%writefile requirements.txt` and
  similar cell magics, or in an R or Julia notebook) are still parsed, since the
  repository writes the declaration and Jupyter starts a kernel by its name: a
  cell that parses as Python is bound, and one that does not keeps lexical
  evidence only, without a gap. A kernel named like a Python kernel (`python3`)
  makes a Python notebook whatever its `language` field says, and `%%script`
  with a Python or IPython interpreter (`%%script env python3`,
  `%%script ipython`) holds Python. Python 2 modules and templates stay a gap
  until listed in `exclude`.
- Rescan affected inputs and rebuild comparison baselines after upgrading.
  Long runtime identities now produce their full resource bindings and may
  change finding IDs. Review and regenerate affected inventory cards instead
  of treating a missing old, shortened resource as resolved. These changes are
  verified with authored regression fixtures; they do not establish independent
  field accuracy or live tenant acceptance.

### README: why and how first, AI-assisted benchmark authorship (October 15)

- From #229: "The Why" and "How it works" now follow the name table, ahead
  of install, so a reader meets the problem and the pipeline first; the
  benchmark note says the maintainer wrote ShadowScan, both corpora, their
  labels and the harnesses with AI coding assistants, as "Project status"
  already says of the code; "Safety notes" is now "Safety and security
  notes".
- Not carried from #229, because each would have made the README less
  accurate or broken a test that guards it: hand-deleting five rows of the
  generated detection matrix (`make readme-matrix` owns it), removing the
  statement that later ShadowScan runs on the 2026-10-11 estate are
  in-sample, dropping ShadowScan from the list of what the benchmark author
  wrote, "reports may still contain" for "still contain" sensitive
  inventory data, and a superlative in the banner's alt text.
- The README benchmark tests read the Benchmarks section up to the next
  heading instead of up to "The Why", so moving a section no longer empties
  the text they check. The in-sample test now also requires the README's
  explanation (rules changed with the run's errors in view; fewer errors are
  not evidence of better field accuracy): the estate row's "in-sample
  (below)" alone had let a deletion of that explanation pass.

### README restructured as a landing page (October 15)

- The README leads with install, quick start, a command reference and the
  offline demo output; deep reference material (deployment and development
  installs, coverage policy, incremental correlation, baseline upgrades, the
  risk-policy YAML, full finding-field notes) now lives only in the `docs/`
  pages it duplicated, and the README links them. The README drops from 777
  to about 515 lines. `docs/getting-started/configuration.md` links
  `docs/concepts/risk.md` instead of the removed `README.md#risk-policy`
  anchor.
- The command reference lists every top-level command, including
  `inventory check`, `mcp-registry snapshot` and `signatures show`, and the
  exit-code table keeps `diff`'s 2 and 3 and the rule to gate CI on any
  non-zero exit.
- Review fixes kept the statements the condensed draft dropped: the warning
  that the unrelated `shadowscan` PyPI package is not this project and the
  attestation check, the exact `shadow` rule (a name match only suggests an
  inventory entry), the evidence table under "The Why", the advisory-only LLM
  triage exception to failing closed, the retention limits (no span prompt or
  completion content, no process command lines, no live endpoint probing
  except opt-in A2A Agent Card fetches), the credential-boundary rule, the
  plugin allowlist and its "not a sandbox" limit, and the review-state,
  assurance and governance links.

### README visuals generated from the code (October 15)

- The README banner and the architecture diagrams are now SVG files that
  `python -m tools.readme_visuals` (`make readme-visuals`) generates from the
  code: the surfaces from `Surface`, every built-in connector from the
  connector registry, the report formats from the reporters and the package
  name from `pyproject.toml`. A test fails when a committed image is stale,
  when a surface, connector, report format or report command is missing from
  them, or when an image carries a version, a count or the repository slug.
  `docs/architecture.md` shows the new connectors-by-surface diagram.
- The raster images #222 added are replaced: the banner showed the former
  repository slug, `v0.1.2` and connector counts, and both architecture
  diagrams showed six surfaces, 27 connectors and 215 signatures.
- `docs/assets/discovery-tool-scorecard.png` is removed. It gave letter grades
  to 11 named third-party tools from a benchmark this repository does not
  contain, which #199 had already ruled out.
  `docs/assets/cross-tool-comparison.webp` is removed too: nothing referenced
  it, and it showed head-to-head figures from
  `tools/benchmark/results/REPORT.md` without that report's statement that
  they are author-written synthetic results, not field accuracy. A test now
  keeps `docs/assets/` to the generated images.

### Redaction review fixes, second round (October 14)

- `sanitize` keeps every container of a record a container of its type. A
  mapping whose keys read alike once their credentials are withheld in one
  of its two readings and not in the other (`SSWS a--auth` and `SSWS b`)
  was withheld as one string: agent definition front matter lost
  `description`, `tools`, `model` and `permissionMode` while the scan stayed
  complete (exit 0), an agent card with such keys stopped its analysis with
  an `AttributeError`, and a finding with such keys in its metadata or
  evidence attributes failed to report. Each reading now keeps a copy of
  every member of the source mapping, so the readings pair up member by
  member; only members both readings keep are shown, and a key two members
  share keeps one value, as the earlier rules kept it. Readings that do not
  pair up raise a sanitization limit error (scan incomplete, exit 3)
  instead of changing a container into a string.
- A run that starts the line after a name glued to a `Bearer`, `Basic` or
  `SSWS` credential that stays beside it (`<token>--token`,
  `<token>--password`, `<token>--auth`, `<token>--cookie`) is examined like
  any run that starts a later line. The step that withholds the runs
  resumed after the kept name and never read the next line, so a value the
  passes read once that run goes (`<token>--token` then
  `=abc.def = password: <value>` on the next line) was shown: after
  `--auth` or `--cookie` until the next sanitization, after `--token` or
  `--password` on every one. Such a text now withholds the value on the
  first sanitization, and sanitizing it again changes nothing. In a chain
  of lines that each start with a run, each run still goes in its own
  reading, and the rest of a chain longer than three now goes at once before
  one more reading: the value after the fourth run of a chain was withheld
  only on the next sanitization, and the value after the fifth on none.
- Correction to the October 14 redaction notes: in a text with no run
  glued to the credential, a run at the start of a later line that holds a
  value (`--http1.1 https://...`, `--max-time=30`, `--tlsv1.2`) was not
  "still removed, as before". The earlier rules showed it; the October 14
  change removed it with no marker, so an excerpt lost a curl option and
  did not show that anything was withheld. Such a run stays withheld (the
  current rules never show what they withheld), now with a marker in its
  place, as in a text with a glued run: `Bearer <token>` then
  `--max-time=30` reads `Bearer [REDACTED]` then `[REDACTED]`. A run that
  is only a name or separator (`--verbose`, `---`) is still kept.

### Whole-branch review fixes (October 14)

An agent-run review of the integrated branch found these defects; each was
reproduced before it was fixed and verified again after. The bundled
evaluation corpora make no new prediction changes.

Cross-checked against an independent parallel integration of the same pull
requests, which found three more defects, fixed here with its regression
tests: a CloudTrail AI-service event outside the lineage operation list
(InvokeModelWithBidirectionalStream, Retrieve, ApplyGuardrail,
InvokeEndpointAsync and the like) was silently skipped in offline exports —
it now counts for its caller with a disclosed untraced warning, while only
the listed operations carry a session trace; CloudTrail's display-format STS
expirations ("Jan 20, 2024, 3:16:07 PM") were misread, silently unlinking
the session — they are parsed first now, and an unreadable expiration is a
disclosed invalid-timestamp gap; and n8n's registered openAiAssistant node
now classifies its workflow as an agent. The same comparison carried an n8n
sink and trigger registry keyed by the node type and operation names n8n
declares, so email, database and messaging writes establish egress roles by
declared operation.

#### ShadowBench

- Cases runner: after a stage, hard links, FIFOs, sockets and device nodes
  in `work/` are removed instead of handed to root. A tool running as uid
  65534 could hard link another account's file (any file it may read and
  write) into `work/`, and the runner then made root its owner and the
  adapter read it as root. Regular files and symlinks with a single link are
  still handed to root, escaping symlinks are still swept, and the row's
  note counts everything removed.
- Cases scoring: a case with no row on a surface and modality the tool does
  not run (its other rows there are `unsupported`, or it has none there and
  its adapter does not declare the pair) counts as `unsupported`, as the row
  the runner writes there would, instead of an in-scope error. Scoring a run
  of some surfaces or cases (`--surfaces`, `--cases`) no longer charges a
  tool with errors on surfaces it never runs or lists them as covered. A
  missing row anywhere else, or for a tool without a loaded adapter, is
  still an error. The committed 2026-10-11 metrics and report are unchanged.

#### Correlation

- Correlation compares Azure resource IDs case-insensitively, as Azure
  Resource Manager does: a role assignment whose scope ARM returns lowercased,
  or a diagnostic-log resource ID in upper case, links exactly to the listed
  resource again. Only ASCII letters fold, and findings keep the spelling they
  reported; ARNs, GCP names and OCIDs are still compared byte for byte.
- Correlation treats a GCP service account address
  (`<name>@<domain>.gserviceaccount.com`, bare or in
  `projects/<project>/serviceAccounts/<address>`) as one global identifier: a
  Vertex AI caller in one project links exactly to the service account another
  project defines, where a declared project conflict used to block even a
  review candidate. Lookalike addresses outside `gserviceaccount.com`, or with
  upper-case letters, stay local identifiers in their project. Google-managed
  accounts that many projects share (`@system.gserviceaccount.com`,
  `@firebase-sa-management.iam.gserviceaccount.com`) link nothing.
- Correlation no longer reads repository paths under `projects/` as GCP
  resource names: two monorepos that both hold `projects/api/src/main.py` were
  linked as one GCP resource. From a code finding, a `projects/` value is a GCP
  resource name only with a valid project id or number, a GCP collection after
  it, no `:<line>` suffix and no source-file extension on its last segment
  (`projects/support-bot/agent/main.py` is a file); other findings' GCP names
  parse as before.
- A declared scope value that correlation cannot compare (redacted, padded, or
  with wildcard characters, as a Notion workspace display name such as
  `Acme [EU]` has) still refuses every identifier link for its finding, but no
  longer removes the finding from name review candidates.
- `identity.entra`: findings replayed from an export whose coverage marker
  names another tenant than `tenant_id`, or no tenant, carry
  `metadata.account_attributed: false`. Their `account` still names
  `tenant_id` (finding ids are unchanged), but correlation no longer takes it
  as the records' Entra tenant, so an application id equal to one of the
  configured tenant's Teams bots is a review candidate,
  not an exact link.

#### Evidence analysis

- Lockfile inventory: a pnpm package from a git, tarball, URL or local
  source is inventoried by name with `version: null`, its source kind and a
  limitation instead of being dropped. An AI package locked only from such a
  source (directly or transitively) previously left an empty, complete scan;
  it now produces a `lockfile-inventory` finding. An entry whose name cannot
  be told is still reported as `unsupported pnpm package key` (security220-1).
- Instruction audit (`SKILL.md` body and front matter, MCP tool
  descriptions): a line over 4,096 characters is audited sentence by
  sentence instead of only at its two 4,096-character ends, so an
  instruction in the middle of a long line is reported (and an MCP tool
  gets `tool-poisoning`). Only a single sentence over 4,096 characters is
  still audited at both ends and marks the audit `partial`. Quoted spans are
  removed with a linear scan, so a long line of unmatched curly quotes no
  longer costs quadratic time (security220-2).
- `runtime.processes` inspection: `ESRCH` is `not_applicable` only for a
  zombie with no threads left (state `Z`/`X`, `num_threads` 1). A process
  whose leader thread exited while other threads run (state `Z`,
  `num_threads` above 1) showed an empty maps and descriptor read and
  `ESRCH` on `environ`, and was reported as a complete, empty inspection;
  those sources, and `ESRCH` from a process in any other state, are now
  `unreadable` and leave the scan incomplete (exit 3) (security220-3).
- `code.filesystem` with `inspect_model_artifacts`: a link with an artifact
  suffix to a scanned artifact with the same suffix in the same project and
  test classification (`latest.gguf` to `model-q4.gguf`) no longer makes the
  scan incomplete; the target is inventoried at its real path. Links to
  artifacts outside the root, in excluded directories, under test paths or
  with another suffix remain gaps (C220-2).
- `endpoint.mcp`: invisible operators (U+2061-U+2064) and bidirectional
  isolates (U+2066-U+2069) in a tool description now raise `tool-poisoning`,
  like the other invisible and bidirectional controls; they previously added
  only `invisible-text`. The rule uses the instruction audit's invisible set
  (C220-3).
- `endpoint.mcp` instruction audit: a tool description that starts with a
  `---` line is audited as text, not as `SKILL.md` YAML front matter. The
  lines after it (other than `name` and `description`) were not audited, and
  a leading `---` without a closing one marked the scan incomplete (C220-4).

#### Connectors

- Cloud: an offline `cloud.aws` `cloudtrail-event` record with no `eventName`
  (absent, `null` or empty) is malformed, not an ignored non-AI operation: it
  is skipped with a warning and the scan is incomplete (exit 3). A named
  operation outside the collected set is still ignored. (C220-1)
- Low-code: n8n node types that put `Mcp` or `MCP` after another word
  (`githubMcpClient`, `acmeMcpTool`, `zapierMcp`) are MCP AI steps;
  `mcp9808`, `smcp` and `SMCP` words still are not. (F7)
- Low-code: the n8n HTTP model-call rule reads the method from `method`
  (HTTP Request v3 and later) or `requestMethod` (v1 and v2), and reads an
  expression-mode URL (`=https://...{{ $json.u }}`) without its leading `=`;
  a host written as an expression is never classified. (F8)
- Low-code: an n8n POST to a bare `/chat/completions` on a host that is not a
  known model host counts with the same corroboration as `/v1/messages`
  (an `anthropic-version` header, or a body with `model` and `messages`,
  `prompt` or `input`); a bare `/messages`, `/responses` or `/completions`
  still never counts. (F18)
- Gateway: in text access logs, a server-written single-label or IPv4
  `host=` token (`host=tgi:8080`, `host=10.20.0.5:8080`) matches a declared
  `internal_model_hosts` entry, as it already did in JSON logs; undeclared, it
  is named in the advisory and an undeclared `localhost:11434` keeps the
  Ollama-route rule. Self-hosted-route requests with no logged host are
  counted in the same advisory instead of being dropped without a
  diagnostic. (F9)
- Gateway: `internal_model_hosts` accepts one hostname as a string (YAML or
  `--set internal_model_hosts=host`), and `shadowscan gateway` takes a
  repeatable `--internal-model-host`; unset sources keep their finding
  ids. (F15)
- Kubernetes: items of a raw API list (`kubectl get --raw /api/v1/pods`), which
  the API server sends without `kind`, take the kind their typed `List` names
  (`PodList` items are Pods) and are analyzed, including on a chunked page
  that stays incomplete. An object without a `kind` anywhere else, or with a
  non-string or empty `kind`, makes the scan incomplete instead of being
  skipped silently. (F10)
- Kubernetes: `nvidia.com/gpu` counts only when it is a resource quantity
  above zero; `0` and `"0"` no longer make a GPU workload, and a value that is
  not a quantity makes the scan incomplete. (F19)
- Docs: the production notes quote the Kubernetes "workload has malformed
  container command" and "... container args" warnings as emitted. (F20)

#### Documentation

- Benchmark documentation: the README's estate row says the labels were
  frozen after a label-completeness pass in which every runnable tool ran once
  (it said "before any tool ran"), and the README, the ShadowBench README, the
  estate README and the deployment guide say that ShadowScan's detection rules
  were changed with the 2026-10-11 estate run's errors in view, so a later
  ShadowScan run on that estate is in-sample. Consistency tests pin both
  statements.
- Operator documentation: the deployment guide and the bounded-evidence entry
  now say which network record defects withhold flow attribution (a malformed
  context outside VPC flow records, an invalid JA4 value, an answer list over
  32, a record without a usable client) and that a malformed TTL or timestamp
  withholds nothing. `RELEASE_NOTES.md` "Before you upgrade" now lists the
  October 14 finding-id changes (Atlassian sites, Kubernetes names over 160
  characters, `gateway.logs` `internal_model_hosts`) and the new exit-3 cases.

### Bounded evidence analysis across connectors (October 14)

Carried from #220 with the review fixes below. The bundled evaluation corpora
give the same predictions before and after. The new tests are author-written
synthetic fixtures; they establish implementation behavior, not independent
review, live tenant acceptance or production precision.

Also carried, from the reviewed parts of #217: MCP tool descriptions are
screened with the code surface's bounded instruction-content rules (hidden
HTML-comment content, fetch-and-execute or decode-and-execute phrasing) and
for terminal control sequences, each a tool-poisoning review candidate with
zero-weight explanatory evidence; the `tool-name-shadowing` tag gains its
missing threat rule (OWASP LLM01/ASI01, ATLAS AML.T0051.001) and a default
risk weight of 10 (a default-weights change; see the migration notes);
supported lockfiles are credential-scanned like every other read file, with
detected values redacted and never retained in the dependency inventory; and
the Vertex AI, Bedrock and Azure OpenAI provider signatures record their
endpoint and IP-range source references. Live DNS enrichment stays deferred
(#210): an offline network scan performs no DNS resolution.

- Low-code: a shared bounded, cycle-safe graph core for n8n, Flowise and Dify
  exports adds non-scoring `workflow_graph` metadata: node and edge counts,
  role counts and an example input → AI → outbound path by node ordinal. Exact
  node types assign graph roles only. `lowcode.n8n` and the export reader
  report the same workflows as before, for example OpenRouter, embeddings,
  vector-store and community MCP nodes outside the registry. A malformed or
  over-budget graph marks coverage incomplete and sets the graph status to
  `incomplete`, but keeps the workflow finding. A `null` n8n output slot is an
  unconnected branch, not a defect. In `lowcode.n8n` the graph and
  `metadata.node_count` cover the same nodes, an n8n workflow that also
  carries Dify-like `kind`/`workflow` fields is read as n8n, and a graph that
  fails unexpectedly affects only its own workflow. A document is a graph only
  when its nodes identify n8n or Flowise (or it is a Dify app): a long
  `nodes` list alone is never reported as an over-budget graph.
- Source inventory: bounded `uv.lock` v1, Poetry 1.1/2.0/2.1, `pnpm-lock.yaml`
  6/9 and `Cargo.lock` 3/4 parsing adds `lockfile-inventory` findings
  (dependency inventory only, possible confidence), with direct/transitive
  labels only where roots and edges establish them. No package manager runs.
  A lockfile that is malformed, an unsupported version, over a limit (1,000,000
  bytes, 4,096 packages, 16,384 edges) or a symbolic link is reported against
  that lockfile with a fixed reason. Beside its `pyproject.toml`,
  `package.json` or `Cargo.toml` this is a warning and the scan stays complete;
  without that manifest the scan is incomplete, as for an unparseable manifest.
  A pnpm package from a git, tarball or URL source is skipped and counted in a
  limitation while the rest of the file is inventoried; a `uv.lock` package
  without a version (a workspace member or dynamic version) is inventoried
  with `version: null`; an integer past Python's digit limit in a TOML lockfile
  is reported as invalid TOML.
- Model and binary artifacts: opt-in `inspect_model_artifacts` (with
  `model_metadata_bytes`) inventories GGUF, safetensors, ONNX envelope and
  PyInstaller structures through confined, bounded reads. Nothing is
  unpickled, decompressed, loaded or executed. GGUF array values (tokenizer
  vocabularies of 32,000-256,000 entries, scores, merges) are skipped without
  being decoded, under their own element and byte bounds, so llama.cpp models
  are inventoried. An extensionless file is searched for a PyInstaller cookie
  only when it starts with an ELF, PE or Mach-O header; when a root's artifact
  budget is spent, remaining selected files are counted in one warning that
  marks coverage incomplete, and extensionless files still get normal text
  analysis. Symlinked Hugging Face cache entries are not followed; the source
  guide documents that gap.
- `SKILL.md` files and MCP tool descriptions get a bounded static sentence
  audit with fixed rule explanations and line numbers, and quoted-example and
  prohibition controls. For MCP tools it is additional, zero-weight signal: the
  existing `tool-poisoning` rules still apply unchanged, including to
  documentation URLs and tool references, and an audit indicator can also
  raise the tag. The `SKILL.md` audit also covers the front matter `name` and
  `description`. A line over 4,096 characters is audited in its first and last
  4,096 characters and marks the audit `partial`, not the scan incomplete.
  Oversized text (over 64 KiB), malformed front matter and unclosed fences
  mark coverage incomplete.
- Runtime: opt-in Linux `inspect_maps`, `inspect_fds` and `inspect_env_keys`
  read bounded mapped-library names, descriptor-link extensions and
  allowlisted environment key names, with process identity checks and
  budgets. They never read process memory, open descriptor targets or keep
  environment values. Kernel threads are not inspected, and a source that
  fails with `ESRCH` while the process identity is unchanged is recorded as
  `not_applicable` without marking coverage incomplete. A live command line
  over 65,536 bytes is classified from its leading complete arguments,
  recorded in `metadata.command_lines_truncated`, and leaves the scan
  incomplete.
- Network: DNS-to-flow attribution requires a matching client and context and
  an answer valid at the flow time (`dns_max_ttl_seconds`, default 86,400;
  `dns_clock_skew_seconds`, default 0). Flows are grouped per connection, with
  their times in at most 64 buckets each, and a bucket that straddles an
  answer's validity is not attributed. DNS answers are stored per client and
  address as merged validity intervals, so repeated lookups use no extra
  storage and attribution looks intervals up by bisection. A storage bound
  withholds DNS attribution only for the affected client/address, with a
  limitation on its findings and a warning that leaves the scan complete; the
  Ollama port rule does not depend on DNS storage. A record defect that could
  hide DNS or TLS evidence (a malformed context outside VPC flow records, an
  invalid JA4 value, an answer list over 32, a record without a usable client)
  withholds flow attribution only for the client it names, or for the whole
  input when no client is known or the record limit is reached; a malformed
  TTL or timestamp keeps the record with that field unknown and withholds
  nothing. Zeek JA4
  values are validated,
  non-scoring context. Offline scans make no DNS or fingerprint queries. In the
  bundled demo one finding is removed (a client borrowing another client's
  expired answer: 133 to 132 findings) and Cursor's confidence drops from 0.8
  to 0.5.
- AWS: CloudTrail exports retain bounded event provenance and exact
  assumed-role lineage (session ARN, issuer, creation time and lifetime, up to
  eight hops) as non-scoring metadata. Sampling bounds (100 invocations per
  caller, 2,000 invocations and 2,000 STS assumptions per run) mark lineage
  `partial` without marking the scan incomplete; invalid timestamps and
  conflicting event IDs mark it incomplete. Exact duplicate event IDs no longer
  inflate caller counts, and offline records with other event names are
  ignored. Live `LookupEvents` retrieves no STS events, so live lineage is
  always unlinked.
- Lifecycle: endpoint and process findings gain a non-scoring
  `lifecycle_observation` with the scan's observation window, runtime coverage
  and historical/current/unknown recency. Samples never name a finding the
  report omits; `observations_omitted` counts them.

Rescan after upgrading and keep earlier reports as historical observations;
lower attribution is not evidence that a workload stopped. See the
[migration notes](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/production-migrations.md#october-14-bounded-evidence-migration-unreleased).
The archived implementation record under
`archive/reviews/evidence-depth-2026-10-14/` is author-written offline evidence;
its full before/after reports were not committed.

### Detection precision, ambiguous app names and scoped correlation (October 14)

Integrates the reviewed parts of three draft pull requests, #216, #203
and #204, into one design. Rollout and migration notes are in the
[deployment guide](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/history/production-change-history.md#october-14-detection-precision-ambiguous-app-names-and-scoped-correlation-unreleased).

- Name signals can be marked `ambiguous: true`. The Google Gemini identity
  signature uses it: a Gemini display name, publisher or description stays a
  possible-product hint (`metadata.potential_frameworks`, tag `ai-name-hint`)
  until a same-product domain, client ID or other non-name signal corroborates
  it. A hint adds none of the signature's tags, capabilities or agent
  indicator, and more generally no match that does not establish its
  signature adds tags, so tag-based risk weights and rules can stop matching
  findings whose technologies are only potential. The generic AI-name hint is
  never listed as a potential product. A corroborated name keeps its full
  weight. Every bundled ambiguous name signal must have a corroborating signal
  type (`tests/unit/test_field_precision.py`).
- OAuth reply and homepage URLs corroborate a product by their parsed
  `http(s)` hostname only. Path, query, fragment and userinfo mentions and
  lookalike hosts no longer count. URL tokens with userinfo, a backslash or a
  control character are skipped (Python and browsers disagree about their
  host). A field holding several URLs, such as a ServiceNow `redirect_url`,
  is split on whitespace, and on a comma or semicolon only where a new
  `http(s)://` URL starts and before the current URL's query or fragment, so
  `?next=a,https://chatgpt.com/` is not a host. Domain matches are counted
  once per app across all of its URLs.
- An app assessed by an identity or SaaS connector with no established AI
  product, provider, LLM-access permission, Entra agent identity or registry
  record has its non-AI observations bounded as one correlated group at 0.35
  (`UNATTRIBUTED_APP_MAX_WEIGHT`, `confidence_group: unattributed-app`). The
  bound is stored in evidence weights, so merging duplicate observations
  reproduces it, and a generic AI-name hint stays separate so it never lowers a
  score. In the bundled demo, five findings change risk score, all within their
  previous severity level; this change keeps the demo at 133 findings (16
  critical, 63 high, 54 medium), and the network change in the bounded
  evidence entry above then removes one (132 findings, 62 high).
- Correlation: `metadata.related` holds only exact identifier links, with
  `metadata.related_details` provenance (identifier type, fields, scope).
  Fully qualified ARNs, GCP resource names, Azure resource IDs and OCI OCIDs
  carry their own scope; AWS-managed policy ARNs and Bedrock foundation-model
  ARNs, which every account shares, are not compared at all, while accountless
  S3 bucket and Route 53 ARNs still link. An Entra application ID reported as
  `app_id`, `client_id`, a Teams `bot_id` or an Azure Bot `msa_app_id` is one
  identifier type that links exactly within one declared Entra tenant. Other
  local identifiers need a shared declared tenant, workspace, cloud account,
  subscription or project; vendor names and gateway labels are not scope.
  Name similarity, and equal identifiers whose shared scope cannot be
  verified, go to `metadata.related_candidates` as review hints with a
  limitation. A declared scope conflict blocks both. Correlation is rebuilt on
  every run, and confidence filtering prunes all three fields. In the bundled
  demo, the three identifier links stay exact, three new same-ARN links
  appear, and the three name or caller-label links become candidates. HTML and
  Markdown reports show candidates on their own line, and the HTML metadata
  dump no longer includes the provenance records.
- `gateway.logs` has a new `internal_model_hosts` option: exact, validated
  hostnames of internal model servers, matched with or without a logged port
  and with no DNS lookup. It is part of the source identity only when set, so
  default-configuration finding IDs do not change. Ollama-style (`/api/chat`,
  `/api/generate`, `/api/tags`) and bare text-generation-inference
  (`/generate`) routes count as model traffic only with a model field, on a
  known or declared model host, or, for the Ollama-style routes, when no host
  was parsed. A help-desk chat widget or a registry on a parsed non-model host
  is no longer a caller. Requests excluded this way are reported in one
  advisory warning (the scan stays complete) with their count and up to five
  of the busiest hosts, pointing to `internal_model_hosts`. User agents never
  exclude a request.
- `cloud.kubernetes` and `cloud.openshift` recognise serving-engine names
  (`vllm`, `ollama`, `sglang`, `llama.cpp`, `text-generation-inference`) that
  start an image's name, its last path component without tag or digest
  (`registry.example/ml/vllm-serving`, also digest-pinned). An engine name
  elsewhere in the path or followed by an exporter, operator, metrics or
  monitor role does not count, and NVIDIA Triton counts only with a
  TensorRT-LLM or vLLM backend tag. GPUs are read from `limits` as well as
  `requests`, and `--model org/name` arguments are recorded without their
  values. A model argument corroborates an AI image or AI resource kind
  (`self-hosted-model-serving` tag and evidence); with only a GPU it never
  makes a workload an agent. A `command` or `args` field that is not a list of
  strings makes the scan incomplete; a `null` one is unset.
- `lowcode.n8n` treats an HTTP Request node as a model step when it POSTs to a
  generation route on a known model host, or to a versioned or namespaced
  route (`/v1/chat/completions`, `/v1/completions`, `/api/generate`) on a host
  that is not a known SMS or messaging API. On such a host `/v1/messages`,
  `/v1/responses` and `/api/chat`, which are also WhatsApp Business and
  help-desk chat routes, count only with an `anthropic-version` header or a
  body with `model` and `messages`, `prompt` or `input`. A bare `/messages` or
  `/responses`, GETs and bodies on other routes never count. `mcp` in a node
  type counts as its own token: custom `mcpClient`, `MCPServer` and
  `mcp_bridge` nodes are AI steps, part numbers and words containing it are
  not.
- `lowcode.servicenow` reports a flow only with a ServiceNow AI marker or a
  name that establishes an AI product or provider; the generic AI-name hint
  ("Copilot" licence administration) or an ambiguous product name (a Gemini
  account sync) no longer qualifies a flow.
- `saas.notion` inventories a bot with an established AI product or provider,
  or an AI-name hint in its name (a generic AI word such as "LLM Agent" or
  "Support GPT", or an ambiguous Gemini name kept as a potential product); a
  name whose only hint is the word "bot" does not count, since every Notion
  integration is a bot user, and a bot's id is not matched as a name.
  `saas.slack` matches the app ID as the app's client ID, so a rule pack can
  bind a reviewed Slack app. Wudpecker and Tactiq are recognised as meeting
  note-takers by name and domain (benchmark-derived: Wudpecker is the
  ShadowBench estate positive the 2026-10-11 run missed, and Tactiq was added
  with it). `identity.auth0` keeps a client attributed
  only by a model provider. A GCP Cloud Run service or Cloud Function name or
  description establishes an unambiguous product (a function described as
  using Anthropic Claude); an ambiguous Gemini name there stays a hint.
- Finding ids do not change, except for `gateway.logs` sources that set
  `internal_model_hosts`.
- Not carried from the draft pull requests, with reasons in the integration
  commits: a global name-weight cap, signature `negative_context`, the
  `not_ai` inventory exceptions, Okta weight cuts, per-connector confidence
  clamps, User-Agent and audit-read gateway exclusions, the browser-only
  AI-app recast, Kubernetes agent-named environment and model-mount
  heuristics, the n8n graph-reachability agent rule, the Lambda Bedrock agent
  change, a benchmark-derived Slack client ID, and Slack `assistant:write` as
  an LLM-access scope (it designates an assistant app and grants no model
  access).
- The bundled evaluation corpora and the ShadowBench estate replay are
  author-written offline inputs. They show the intended behaviour on known
  cases; they are not measured production precision, independent review or
  live tenant acceptance. Several of these changes (ambiguous Gemini names,
  Notion bots, gateway `/api/chat` and `/generate` routes, Kubernetes
  serving-engine images, n8n HTTP model calls, ServiceNow flow names,
  Wudpecker) were made with the 2026-10-11 ShadowBench estate run's
  ShadowScan errors in view, so a ShadowScan run on that estate after them is
  in-sample: replayed on it, seven of that run's twelve ShadowScan errors no
  longer occur, which is no evidence of better field accuracy. Rescan and
  rebuild comparison baselines after upgrading: signature and scanner
  fingerprints change.

### Kubernetes discovery and Atlassian approval scope (October 14)

- Kubernetes and OpenShift object limits now distinguish an exhausted export
  from unread objects, including arrays of `List` envelopes. An unread suffix
  marks collection incomplete instead of producing a complete partial report.
- Kubernetes resource identities retain the full object name. Names exceeding
  the 253-character resource-name bound are rejected with incomplete coverage;
  distinct valid names no longer merge because they share a shortened prefix.
- CronJob analysis reads `spec.jobTemplate.spec.template.spec`, including image,
  privilege, environment, GPU and volume evidence. Malformed nested templates
  remain incomplete and cannot substitute an unrelated top-level template.
- Atlassian app approvals require an explicit site/account constraint. Discovery
  without a usable site retains its evidence with incomplete coverage and
  produces an unbound inventory stub. Existing unscoped cards need a reviewed
  `discovery.accounts` binding before they can register app installations.
- Added offline regression fixtures and boundary, identity and approval tests.
  These establish implementation behavior, not live tenant acceptance.
- A Kubernetes `List` page with a non-empty `metadata.continue` or a
  `metadata.remainingItemCount` above zero (a chunked API page) now marks the
  scan incomplete (exit 3), for a single `List` and for `List` envelopes in a
  JSON array or JSONL. Its observed objects are still reported. Malformed
  values of either field are also incomplete.
- Kubernetes namespaces are no longer shortened to 160 characters, and a
  non-string namespace is no longer replaced by `default`. A namespace that is
  not an RFC 1123 DNS label (lowercase letters, digits and inner hyphens, at
  most 63 characters) is rejected with incomplete coverage, so distinct objects
  cannot merge into one resource identity, including through a `/` in the
  namespace.
- Atlassian finding IDs change on upgrade for exports scanned without a
  configured `site` and for a `site` with an uppercase host or an explicit
  `:443` (a trailing slash was already ignored). A `site` that is not a plain
  HTTPS origin, such as a Data Center context path, now stops the connector
  with exit 3. Without a site, IDs are bound to each export file's
  resolved path, so two sites' exports in one directory input stay separate
  findings. Configure the canonical site, keep one site per input, rescan and
  establish a fresh baseline.
  Carried from #218.

### Redaction review fixes (October 14)

- A run at the start of the line after a `Bearer`, `Basic` or `SSWS`
  credential that holds no value (`--insecure`, `---`, `=Section=`, also
  after blank lines) is no longer removed from a text that has no run glued
  to the credential. The step that withholds a glued run ran on every text
  and deleted such a run without a marker, so an excerpt lost a curl flag, a
  YAML separator or a README option and did not show that anything was
  withheld. A later-line run that holds a value is still removed, as before:
  returning the established reading there would show option values that the
  previous rules withheld. In a text with a glued run, a run at the start of
  a later line is still withheld, now with a marker in its place where the
  rest of the line is unchanged.
- Where the two readings of a text with a glued run do not pair up line by
  line, the whole text is still withheld, keeping its line breaks. Keeping
  the lines both readings show alike was tried and not carried: those lines
  included values the previous rules withheld.
- The scheme pass, called outside `sanitize_text` and `sanitize`, withholds a
  glued run with its credential again, as the established rules did. With no
  reading set it left the run in the text for a later step that only those
  two entry points run. Their output was not affected.
- The merge of the two readings is tested directly: hypothesis properties for
  `sanitize_text` and `sanitize` check that each output line is a line of one
  reading, that line with a marker, or a withheld line, and shows only what
  both readings show; unit tests cover the line comparison, the line merge
  and the read-again caps, and pin tests keep value-holding later-line runs
  withheld. Unreachable bytes and set branches in the merge helpers and a
  duplicated glued-run pattern are removed, and `docs/production.md` states
  the merge rule as above.

### ShadowBench review fixes (October 14)

Fixes from the agent-run review of #199, carried on the integration branch.
That review is not independent human review.

- Cases scoring: on the code surface a negative case where a tool reported
  anything outside the fact taxonomy is now a case-level false alarm instead
  of a true negative; such reports still earn no credit on a positive case and
  stay neither true nor false positives at entity level. The code-surface
  adapters (AgentDiscover, `agent-discovery`, vet, ShadowScan), which drop
  hits that map to no fact, count them in each row's `out_of_taxonomy`, and
  the scorer counts them as if passed on; it refuses a count that is not a
  non-negative integer or sits on a non-code row. `metrics.json` reports
  `case.out_of_taxonomy_alarms` per tool. `tools/discovery_benchmark`'s
  ShadowScan normalizer records the findings it maps to no fact as
  `detail["unmapped"]`, LLM-provider credential findings included.
- Re-scored the 2026-10-11 cases run from the unchanged rows: only
  AgentDiscover changes. Its 16 out-of-taxonomy keys on the encode/httpx
  control (`code-checkout-017`) are now its one code false alarm: code case
  specificity 90% (9 of 10; was 100%), in-scope case specificity 25 of 26
  (was 26 of 26), case-level balanced accuracy 62% (was 64%), and the McNemar
  comparison with ShadowScan 23 against 1 (was 22 against 1). The October 12
  entry below now limits the statement that out-of-taxonomy code keys are
  neither true nor false positives to entity level.
- The run manifest now records each `<tool>.jsonl`'s SHA-256
  (`rows_sha256`), and `score` refuses a results file whose digest differs
  unless `--force`; before, only per-status row counts were checked, so an
  edited or swapped file with the same statuses was scored. Tools whose
  manifest entry has no digest, every tool of the 2026-10-11 run, are listed
  in `metrics.json` under `rows_unbound`, and the report says their rows are
  bound to the run only by status counts. The cases `REPORT.md` for a
  manifest without harness fields now also states that its rows come from
  earlier adapters under weaker isolation and were scored with rules revised
  after the run.
- Cases runner: version probes run in their own PID namespace with a fresh
  `/proc`, under a root shell that stays the namespace's init, so a process a
  probed binary detaches dies with the probe or its timeout instead of
  staying on the host as uid 65534 with access to later work trees. After a
  stage, `work/` is handed back to root with group and other write removed
  before escaping symlinks are swept, so a uid-65534 process outside the stage
  can no longer plant a symlink after the sweep and have the adapter read a
  root-only file through it. Each stage gets its own IPC namespace and a fresh
  tmpfs over `/var/tmp` and `/dev/shm`, and the runner refuses scratch or tool
  paths under them; the host's `/tmp` is still shared between cases and
  tools.
- Cases `fetch_code` runs git without the system or global git configuration
  and with `* !filter` in `.git/info/attributes`, so a repository's
  `.gitattributes` can no longer start git-lfs or another operator-configured
  filter driver on checkout; a proxy or CA bundle must come from
  `HTTPS_PROXY` or `GIT_SSL_CAINFO`. The fetched commit is checked before
  checkout. An existing checkout is kept only when this fetcher made it, its
  origin is the pinned URL and it holds the pinned tree and nothing else;
  `materialize` refuses a checkout with untracked, ignored or modified files
  or a populated submodule directory.
- The ShadowScan adapter records `-dirty` after the commit when `shadowscan/`
  or `pyproject.toml` differs from it, and `unknown` when its version probe
  exits non-zero.
- `benchmarks/shadowbench/cases/README.md` no longer calls the author-written
  benchmark "standardized".
- Estate scoring fails closed on malformed `runs.json` rows: `score` exits 2
  without writing anything when a result row has no tool, has no unit or a
  unit other than `estate`, `sim`, `code:<name>` or `home:<name>`, or
  repeats a (tool, unit) pair. A row without a unit was read as a
  whole-estate run, which reached every entity, turned every unflagged
  in-scope negative into a true negative and hid the missing code and home
  units; a repeated row counted its unattributed predictions twice.
- The estate Numbat wrapper fails the unit when `numbat agents` exits with
  any status other than 0 or the documented empty-inventory 1, even if it
  printed a report. A crash that had printed `[]` was recorded as a complete
  empty inventory.
- The estate vet wrapper checks a code repository's `vet.json` before the
  code-surface adapter reads it: an unparseable report, one that is not a
  list, or a list without a vet record (such as `{"error": ...}`) is an
  adapter error, not an empty inventory. No report, an empty one, `null`
  and `[]` still read as nothing found; `tools/discovery_benchmark` is
  unchanged.
- The estate README's rename erratum says the renamed artifacts and the
  ShadowScan harness configuration still name Adatum tenants on real SaaS
  parent domains (offline data that no harness contacts), and each estate
  `tokens.txt` entry in `tools/secret_allowlist.json` gives a reason that
  describes its own synthetic token.
- None of these changes the committed 2026-10-11 estate results: the
  committed `runs.json` re-scores to the committed `metrics.json` and
  `REPORT.md` byte for byte.

### Repository rename, source distribution and README matrix: review fixes (October 14)

- `docs/testing.md` lists the build lock under `make install` and
  `make install-dev`, CONTRIBUTING says why the release-evidence tests need it,
  and a consistency test requires both CI test jobs and both Makefile install
  targets to install it, the documented gates to start from `make install`,
  and `docs/testing.md` to name it. An environment made before this change
  needs `make install` again.
- README benchmark summary: the code-surface row says that 4 of the 22
  controls and near-misses reported clean came from incomplete runs, and
  that an incomplete clean run is not a clean result; it no longer
  qualifies only recall. The README test derives that count from the
  committed `metrics.json` and `corpus.json`.
- The former-repository-name check accepts the former slug only in listed
  forms (the 0.1.2 `gh attestation verify --repo` command, "formerly",
  "renamed from ... to", "attested as ... before the rename", a recorded path
  marked "(the former name)" and the governance test constant), removed from
  the line before checking, instead of any line that mentions "0.1.2",
  "renam" or "former". It checks the Unreleased section of `CHANGELOG.md`,
  exempting only released entries, and also matches the `%2F`-encoded slug.
- `docs/production.md` again names the request path recorded in the
  2026-10-02 08:05 UTC ruleset observation, under the former repository name
  and marked as such, instead of a request under the new name that was never
  made.
- `tools/release/distributions.py` rejects a `.` or `./` sdist member as an
  unsafe path; it previously failed with an uncaught `IndexError` and a
  traceback. Tests also cover the member-count and member-size bounds for
  both archives.
- README detection matrix: the generator fails on an MCP dependency
  ecosystem it has no display name for instead of leaving it out, lists
  `**/` file globs once without the prefix (adding `.well-known/mcp.json`),
  shows dependency name prefixes as `prefix*`, and says that hosts matching
  the `protocol.mcp` regular expression are recognized too.

### Dependency refresh and repository hygiene (October 14)

- Dependabot's #200 and #201 are carried. #200 bumped nine reviewed inputs in
  `requirements-ci-constraints.txt` (ast-serialize, filelock, hypothesis,
  iniconfig, platformdirs, rpds-py, tomli, types-requests, virtualenv) but
  cannot refresh the hash locks: `requirements-ci.lock` is regenerated with the
  documented uv command, the docs lock's platformdirs follows the CI pin, and
  the mypy pre-commit hook pins the new types-requests. #201 moves
  upload-artifact to 7.0.2, download-artifact to 8.0.2 and codeql-action to
  4.38.3, by full commit SHA in the workflows and `examples/`.
- The macOS test legs install `requirements-build.lock` as the Linux job does;
  the release evidence records the build frontend's version since #202.
- Navigation: READMEs index `examples/`, `benchmarks/sab_realworld/`,
  `benchmarks/sab-holdout/` and `archive/reviews/`; the four benchmarks that
  were all titled some variant of "real-world" have distinct titles;
  `.github/workflows/README.md` lists every workflow, its triggers and what it
  may write; the docs site groups assurance evidence and maintainer runbooks
  separately, adds API pages for signatures and reporters, and each connector
  surface package's docstring names its modules.
- Labels: `.github/labels.yml` adopts GitHub's `duplicate`, `invalid` and
  `wontfix`, adds `breaking-change` and `do-not-merge`, and a policy test
  checks that Dependabot and the stale workflow only use defined labels.
- Developer commands: `make help` prints targets by section, `make
  check-fast` runs the offline gates without tests, `make evaluate` writes its
  reports to a temporary directory, `make install` fails fast on an
  unsupported Python, pytest shows its summary line again, and CONTRIBUTING,
  the pull request template and `docs/testing.md` list one gate set. The
  coverage gate's inventory-mismatch error says what to run.
- Consistency tests check that tracked files already pass the pre-commit
  whitespace hooks, that the mypy hook excludes what pyproject excludes, that
  `archive/` links resolve, and that anchors linked in pages the docs site
  renders are ones both GitHub and MkDocs generate.
- `.gitignore` covers local credential stores (PKCS#12 bundles, `.netrc`,
  `.pypirc`, `.envrc`, Terraform state); `.editorconfig` and `.gitattributes`
  leave frozen benchmark data and archived reviews exactly as committed.

### Repository rename, source distribution and README detection matrix (October 14)

- The repository is renamed from `aisecnomad/Project-Nexus` to
  `aisecnomad/Nexus-ShadowScan`, so that the repository URL, the
  `NexusShadowScan` distribution, the `shadowscan` command and the
  *Nexus ShadowScan* name match; "Project Nexus" also collided with unrelated
  projects in search. Every live link, badge, clone command, issue form,
  `pyproject.toml` URL, `CITATION.cff`, `NOTICE`, the Dockerfile source label,
  the docs site configuration, the SARIF `informationUri` and `helpUri` and the
  CycloneDX VCS reference follow. Retained reviews, frozen benchmark results and
  their harnesses, the recorded ruleset responses and released changelog
  entries keep the former name; a consistency test rejects it elsewhere
  except in a few listed forms that say it is the former name or the name 0.1.2
  was attested under; the Unreleased section is checked too.
- OCSF `metadata.product.vendor_name` is `Nexus ShadowScan` instead of
  `Project Nexus`. The SARIF and CycloneDX tool name stays `ShadowScan`, so
  GitHub code scanning keeps matching existing alerts to the same tool.
- The scheduled governance audit job runs on the immutable repository ID
  (`github.repository_id`) instead of the repository name, which a rename would
  have turned into a silently skipped job. `tools/governance/rulesets.py`
  expects the new name in each ruleset's `source`; the dated observed
  snapshots keep the name GitHub returned at the time, and the tests read them
  as GitHub now returns them.
- Releases upload a source distribution beside the universal wheel. The
  release workflow runs `python -m build --no-isolation` on the clean
  `git archive`, which writes the sdist and then builds the wheel from it with
  the hash-locked backend; `requirements-build.lock` pins `build` 1.6.1 and
  `pyproject_hooks` 1.2.0 with the hash of every published file. The new
  `tools/release/distributions.py` requires one `py3-none-any` wheel and one
  sdist of the same version, byte-identical core metadata and package files,
  an sdist of regular files under one root and no test suite in it. The
  evidence manifest requires the pair, the SBOM is attested for both, and the
  publication input, gate and publish job each require exactly one of each.
  0.1.2 was published as a wheel only. CI and `make build` build the same way.
- `MANIFEST.in` keeps `tests/` out of the sdist: setuptools otherwise added the
  top-level `tests/test*.py` modules without the fixtures, conftest and tools
  they need.
- README: a name table, an abridged SARIF result from the offline demo, a
  detection matrix and a benchmark summary at the top. `tools/readme_matrix.py`
  (`make readme-matrix`) generates the matrix of frameworks by ecosystem, MCP
  evidence and the identity, gateway, low-code, SaaS and network connectors
  from the signature packs, the endpoint client locations and the connector
  classes. Tests fail when the matrix is stale, when the SARIF excerpt stops
  matching the demo's first result, or when a benchmark number differs from the
  committed `metrics.json`. The benchmark section states that the maintainer
  wrote the corpora, labels and harnesses, and that the code-surface run left 43
  of 87 repositories incomplete.
- The publishing runbook gains the rename steps: update the PyPI and TestPyPI
  trusted publishers, republish the Pages site, and verify attestations signed
  before a rename under the former name.

### ShadowBench, the nine-surface discovery benchmark (October 12)

- `benchmarks/shadowbench/` and `tools/shadowbench/`: two benchmark tracks
  that measure shadow AI agent discovery across all nine surfaces, from #193
  and #194 (the `tools.shadowbench` cases/estate entry point, now retained in
  [the companion](https://github.com/aisecnomad/Nexus-ShadowBench/tree/main/tools/shadowbench)). #195
  landed them as `synthetic` and `estate`; the track it called `synthetic`
  is `cases` here, since both tracks are synthetic, and this entry describes
  both tracks after the review fixes below. The *cases* track generates
  platform-native inputs from written rubrics (346 cases: 738 expected
  entities, 735 decoys, 26 pinned public repositories on the code surface),
  with loopback mock
  services and inert live processes for tools that only work live. The
  *estate* track is one authored fictional organization, Adatum Logistics,
  whose 139 frozen files span the nine surfaces with 137 labeled entities
  (87 positive, 27 control, 23 near-miss). Both are author-written: neither
  is independent review, field precision or a verdict on another vendor.
- Integration: each track keeps its own harness under `cases/` or
  `estate/`; the estate's authored files moved under `estate/artifacts/`
  without a change to any frozen digest; the rename and the data errata below
  then changed the affected files' digests, and `FREEZE.json` and the four
  synthetic-JWT allowlist digests were recomputed. The vendor letter grades (`grades.json`,
  `GRADES.md`) and the two PDFs are not carried: the grades were a judgment
  over author-written corpora, and neither PDF could be rebuilt from the
  repository. The estate's fictional organization is renamed from Vantor,
  since 2025 a real company's name, to Adatum in every file, token and
  recorded prediction; the replacement has the same length, so re-scoring
  gave identical results.
- Data errata: the estate artifact
  `home/dev-laptop-02/marcus/.vscode/extensions/github.copilot-1.388.0/package.json`
  was frozen and scored but never committed, because `.gitignore` excludes
  `.vscode/`. It is replaced by a minimal manifest (the label rests on the
  directory name), `.gitignore` re-includes estate `.vscode/` trees, and a
  test fails when any frozen file is untracked. `services.json` names the
  live-sim host by its real path.
- Cases scoring fails closed: an error, a missing row or a run the tool marks
  incomplete never earns a true negative; a results file the run manifest
  does not vouch for, or a corpus digest mismatch, is refused unless
  `--force` is given, and an unknown status, a duplicate row or an unknown
  case is always refused. A
  reported directory no longer earns credit for the files under it, a
  positive case counts as found only with a true positive, code keys
  outside the fact taxonomy are neither true nor false positives at entity
  level (246 of AgentDiscover's 247 code "false positives" were such keys;
  the review fixes above make one on a negative case a case-level false
  alarm), and McNemar
  with no shared case reads n/a. Decoys an adapter declares it never passes
  to the tool (AWS IAM roles for ShadowScan) earn that tool no true
  negative. `verify` always rebuilds the corpus and compares the cases (it
  derived 38 cases per surface instead of 40, and plain `verify` compared
  only the header digest), the generator digest covers the code corpus, and
  case inputs are validated before the runner stages them. The generator's
  `--seed` had no effect: each stream's seed kept only the end of its
  modality name, and four pairs of modalities shared a stream. New corpora
  record a hash-based stream scheme; the committed corpus keeps the legacy
  one, so it still rebuilds exactly, and its README states the
  consequences.
- Cases runner: tools run as uid 65534 with `no_new_privs` in fresh
  network, PID and mount namespaces with `/root` and `/home` hidden; a
  timeout kills the whole namespace; scratch directories must be private;
  mock services bind loopback only, on unprivileged ports; adapters fail
  closed on empty or malformed output, run version probes with a scrubbed
  environment and a timeout (as root, dropped to uid 65534 with `/root` and
  `/home` hidden, or not at all), and fetch pinned repositories without hooks,
  submodules or non-HTTPS remotes. `install_tools.sh` states that installs
  are version-pinned, not hash-locked. The run manifest records the harness
  commit and a dirty flag and each tool's `tools.json` version, and a
  failed static build of the inert process binary refuses the run (exit 2).
- Estate scoring: in-scope entity metrics count only the entities on a
  tool's declared surfaces, with estate-wide detection a separate column;
  a unit whose run failed, timed out, was incomplete, exited with a code
  its adapter does not accept, or was never reached earns no true
  negatives; attribution is restricted to the prediction's surface and
  unit and prefers the entity that expects the fact; the report counts
  every multi-candidate attribution and lists up to 15 per tool
  (`metrics.json` keeps up to 50); a surplus generic fact no longer adds a
  true positive. The live-sim run reaches only the hosts `services.json`
  mirrors, so AI-Infra-Guard earns no true negative for runtime entities it
  was never shown; `score` exits 2 without `services.json` unless
  `--allow-missing-services` is given, and a malformed scan target makes its
  run incomplete. `score` refuses a run whose recorded freeze drifted or
  differs from the current `FREEZE.json` unless `--allow-freeze-mismatch`
  is given; F1 is computed from counts, not rounded precision and recall;
  per-surface value tables include unattributed false positives; and the
  report's provenance sentence follows the README protocol (labels before
  any tool ran, one audit pass of every runnable tool, then the freeze).
- Estate runner and adapters: each unit runs on a private copy of the
  estate, a drifted freeze refuses the run, and `runs.json` records the
  harness commit and freeze digest; Snyk Agent Scan, Numbat and vet
  reports of the wrong shape are adapter errors, not empty inventories;
  freeze and validate reject symlinks;
  validate reports anchor collisions (`--strict` fails on them); wrapper
  scripts quote every corpus-derived value and propagate exit codes; the
  Cisco and Snyk wrappers refuse common MCP server launchers; `run` resolves
  its paths before any command starts. AI-Infra-Guard predictions no longer
  carry text taken from the answer key: the adapter records which loopback
  target each came from, and the scorer attributes it through
  `services.json` as a harness attribution the report counts and discloses.
- Re-scored runs (raw rows unchanged): on the cases track ShadowScan's
  estate recall is 619 of 738 (was 622) and in-scope F1 82% (was 83%), and
  AgentDiscover's code precision is 96% (was 9%); on the estate track
  single-surface tools are scored on their own surfaces (AgentDiscover 5 of
  6 positives in scope, not 5 of 87), vet's in-scope value precision is
  100% (was 86%), and Agentic Radar's units whose commands all exited 1
  without output are incomplete. Each track's `REPORT.md` has the numbers.
- Repository: pre-commit's whitespace and end-of-file fixers skip
  ShadowBench data and the mypy hook skips the estate's sample
  repositories; `.gitattributes` reaches nested benchmark results;
  `AGENTS.md` lists benchmark corpora and artifacts as untrusted;
  `tools/README.md` indexes the repository tooling, and the README links
  the benchmarks with their limits.

### Documentation aligned with the code (October 12)

Documentation only; no scanner behaviour changes.

- `docs/architecture.md` describes the scan pipeline in the order
  `Engine.run()` executes it: runtime and lifecycle correlation, MCP registry
  provenance, vendor registry reconciliation, the sanitization budget and
  opt-in LLM triage were missing. It gains execution and isolation controls,
  the post-scan report commands, and a package layout that covers every
  module (`comparison`, `incremental`, `plugin_process`, `triage`,
  `mcp_registry`, `endpoint`, the shared connector helpers, per-surface
  packages and the code scanner's helper modules). The CLI list includes
  `controls`. The plugin identity rules name all nine reserved namespaces;
  `endpoint`, `network` and `runtime` were missing. The connector example
  imports `HttpClient`.
- README: a "How it works" overview, a documentation map, `--diff-base` in
  the quick start, `--job-deadline-seconds` beside the host job timeout
  advice, process plugin execution and pinned approvals under "Extending", and
  signatures that were recognized but not listed (Agency Swarm, Devin,
  Embedchain, Instructor, Koog, Microsoft.Extensions.AI, MLflow AI Gateway,
  Rivet, Browserbase, Transformers Agents, Voyage AI). `make check` is
  described as the local quality gates; CI also validates packaging and
  containers.
- `docs/index.md` names all nine surfaces and the autonomy, mapping, fleet,
  dashboard, control evidence and LLM triage features; the quick start adds
  workstation scanning, fleet merge, the dashboard, `controls` and the
  CycloneDX AI-BOM; the configuration guide documents `workdir`; the code
  connector guide documents `--triage`, which always exits 3.
- API reference pages for `comparison`, `incremental`, `triage`, `governance`,
  `mappings`, `mcp_registry`, `fleet`, `dashboard`, `controls`,
  `connectors.offline` and `connectors.common`.
- ADR-005 records its status: still proposed, with `FilesystemConnector` at
  about 3,860 lines and 118 methods.
- A check of the rewritten architecture page against the code corrected it
  before release: analysis runs inside each collection job, not after
  collection; setup refusals exit 1 with no report rather than 3; an engine
  hook's exception marks the connector incomplete before construction;
  `gateway.otel` also uses the run identity key and `endpoint.inventory` also
  reports its scanned home directories; three policy tables outside the
  engine name built-in connectors; and the incremental, correlation,
  dashboard, job-deadline and registry-type statements say what the code
  does.
- `ROADMAP.md` separates the live endpoint collection that exists from what
  remains, and the `shadowscan` package docstring lists all nine surfaces.

### Post-merge review fixes (October 11)

- A plain `Bearer`, `Basic` or `SSWS` credential containing `--` or `=` plus
  a letter is again withheld whole, and one after the `token` word, whose
  tail was shown, now is too. The October 11 integration applied the
  token-word rule's glued-text guard to every scheme credential, so such a
  token's tail after the glue was left in sanitized text. A text with such a
  run is now read twice. In one reading every rule reads the run, as in the
  October 11 rules, so a name in it withholds the value after it
  (`=x--password v`, `--auth v`, `--pat v`, which the October 12 rules
  showed); the run is withheld only after every rule, and in `sanitize`
  after the values nested in credential fields are removed from the other
  fields too, and a text that changes is read once more. In the other the
  scheme pass withholds the run with its credential, as the October 12
  rules did. Each reading is read again, as a later sanitization would read
  it, until it stays the same, since evidence is sanitized more than once.
  Each line then shows only what both readings show: where one line
  shows nothing the other does not, that one is kept, and otherwise the
  whole line is withheld. Where the October 12 rules joined the credential's
  line to the scheme's (a name kept after a credential on the line after
  its scheme), the readings' lines no longer pair up and the whole text is
  withheld, keeping its line breaks. A run stays only when it is one name of
  plain words that a rule reads (`--password v`, `=password: v`), beside the
  value it withheld. The regression tests over all three schemes are drawn
  from differential runs and fuzzing against both earlier rule sets.
- `shadowscan run --set credentials_file=<value>` (and the other credential-file
  keys) warns again when the value is an opaque credential rather than a file
  location. Judging those keys by value had delegated to rules that recognize
  only known token formats, so a bare hexadecimal or generic opaque token
  pasted in place of the path drew no command-line warning. A value shaped
  like a location stays quiet even when its file name is random (a mounted
  `/run/secrets/<hex>`, a downloaded `<project>-<hex>.json` key).
- A Workato recipe whose Workbot trigger line carries no trigger name records
  no initiation instead of reading as event-triggered: the name is what
  separates a command a person operates from an event trigger, and the
  connector no longer guesses when the export omits it.
- The AI review gate's published review now states when findings named files
  outside the pull request's diff and were dropped (the gate already failed
  `stale_findings`; the drop was silent in the rendered body). The cancelled-
  publication test delivers a real `SIGTERM`, so the handler registration in
  `main()` is pinned. The publishing runbook's rebuild recipe guards `TMPDIR`
  (`${TMPDIR:-/tmp}`), so it runs on a stock Linux shell, and the low-code
  connector guide states that Workato classifies by provider and trigger name.

### Command-line and documentation corrections (October 11)

- `signatures list --category`, `signatures test --ecosystem` and
  `inventory stubs --kinds` reject values they do not know instead of silently
  matching nothing; `code --mode` without a remote target is a usage error;
  `-v`/`-q` typed after the command say where they go; `merge -o` refuses a
  directory and `merge -f` shows its default; eight options gained help text
  and `run` and `signatures test` readable one-line summaries.
- AI review gate: the publication sanitizer withholds a private key quoted
  without its footer on one line, with escaped line breaks (LF or CRLF), in a
  Markdown blockquote, or encrypted with Proc-Type and DEK-Info headers;
  before, only real line breaks were recognized and the base64 body was
  published. Every rule now also matches the original text, so a key body
  can no longer hide a URL password or account key that follows it. The
  rules still also run in turn, each earlier match replaced by the marker,
  with the current key rule and with each earlier one, each set again until
  it matches nothing more, as repeated redaction would: a long token between
  a key's header and its footer still brings the footer within the key
  rule's 8 KiB search, and a URL whose password holds an Azure key or other
  URLs, however deep, is withheld on the first pass after a quoted key
  header, whose wider run would take the URL's scheme. A long blank run
  after a key header is scanned in linear time; it was quadratic.
- Documentation: least-privilege rows for the five live low-code connectors;
  `cloud.azure` and `cloud.gcp` need no SDK extra with a pre-issued token and
  `cloud.kubernetes` and `cloud.openshift` are offline only (the sentence said
  every cloud connector needs its extra); `saas.generic` marks the scan
  incomplete on any unnamed record, as the code does; `SLACK_TEAM_ID` and
  `GITHUB_API_URL` are named in the key help; the eight offline inventories
  have entries of their own in the connector summary; the Kubernetes guide no
  longer advertises `allow_instance_credentials`, which those connectors
  reject.

### Integration review corrections (October 11)

- `shadowscan run --set` no longer warns that a credential is on the command
  line when the value is a credential file's location (`credentials_file`,
  `service_account_file`, `token_file`), the documented way to pass one. A
  credential-looking value under those keys, and `tokens`, still warn, and the
  locations stay withheld from configuration representations.
- An incremental cache entry whose `warnings` list holds anything but text is
  a cache miss and the input is rescanned. Before, an unkeyed entry with such
  a list loaded and the objects reached the report's warnings.
- AI review gate: the workflow also runs when a label is added or removed, so
  `ai-review: blocked` takes effect without a new push; a run that a newer
  push cancelled publishes nothing instead of a fail-closed review against the
  superseded head; and when a finding names a file outside the diff, the
  findings on files inside the diff stay in the review (the gate still fails
  `stale_findings`; before, every located finding was left out).
- `make build` and CI's wheel build stamp the archive entries with the HEAD
  commit time (`SOURCE_DATE_EPOCH`), as `release.yml` already did, so a rebuild
  of a commit reproduces the released bytes; the publishing runbook gives the
  rebuild-and-compare recipe. The pre-commit mypy hook type-checks against the
  locked PyJWT, rich and urllib3 as well as click and no longer ignores missing
  imports, so it agrees with CI. `requirements-ci-constraints.txt` names the
  `colorama` pin the universal resolution adds on Windows, and the consistency
  tests require every CI lock entry to come from a reviewed input.
- The optional Black Duck and Checkmarx One workflows skip Dependabot pull
  requests, which receive no repository secrets, as the Semgrep workflow
  already did, and the three share CI's concurrency rule: a newer pull-request
  push supersedes the older run while main and scheduled runs finish. A
  dispatched discovery benchmark runs in its own group and no longer cancels
  the weekly run.
- Bug report form: the exit-code options follow the CLI (1 is an invocation or
  configuration error, 2 a completed scan that reached `--fail-on`), the
  surface list names all nine surfaces, and the version field accepts a
  release version with its artifact identity as well as a commit SHA. The pull
  request template lists `make coverage-gate` and `make evaluate` among the
  gates for every change. The README quick-start note names step 7 for the
  report it reads, its development block uses the hash-locked `make install`
  and `make check`, and its project-status recommendation links the deployment
  install section. SECURITY.md opens with the private reporting route. The
  consumer example workflows carry UTC cron comments and the code-scan example
  a concurrency group.

### Review corrections after the October 10 integration

- The Semgrep workflow runs `semgrep ci` in the `semgrep/semgrep` image pinned
  by registry digest (tag 1.180.0) instead of the deprecated
  `returntocorp/semgrep-action`, whose commit pin still ran a mutable image tag
  and which did not declare the `publishDeployment` input the workflow passed.
  Dependabot pull requests are skipped like fork pull requests. The Checkmarx
  One action is pinned to release 2.3.45 instead of an untagged 2022 commit,
  Black Duck moves to v2.11.0, every cron has a UTC comment, and
  `tests/test_repository_policy.py` requires a release comment after every
  commit pin in the repository's and the example workflows (quoted pins
  included, with every pin in the parsed workflow counted) and reads the
  tag comment of every use of a container or service image.
- The Checkmarx step passes an empty `github_token` and `pr_number`: the
  action's defaults sent the job's `security-events: write` token to the
  Checkmarx tenant for a pull-request decoration the job cannot perform. A
  policy test keeps them empty. The Semgrep, Checkmarx and Black Duck
  workflows cancel a superseded pull-request run, as CI and CodeQL do, so a
  quick series of pushes no longer ships the source to each vendor once per
  push. The Black Duck action still downloads the vendor's current Bridge
  CLI; pin it with `bridgecli_download_version` once a release is reviewed.
- The drift CronJob example carries `shadowscan-mode: live`: it collects live,
  and the example NetworkPolicy grants egress to that label only, so the
  earlier `drift` label left the pod with no egress.
- `docs/concepts/risk.md` says governance factors weigh 0 and are omitted
  from `risk.factors` under `risk_basis: danger`, as the code and its tests do;
  `docs/operations/drift.md` says a fleet report keeps `shadow: null` for
  findings no source assessed (not `true`); `docs/connectors.md` names
  `agent-registry:BatchGetDiscoverableRegistryRecord`, the operation
  `registry_arns` calls.
- `cloud.gcp`: an invalid Discovery Engine engine name, or a project-number
  lookup that failed or answered for another project, made the live scan
  incomplete but left no trace in the `--dump-records` export, so a replay
  reported a complete scan. The collector records the engine as an incomplete
  `assistants` listing (`registry-coverage`, `complete: false`) and a failed
  lookup as a `project-number` record with a null `project_number`; offline
  analysis warns once for each and the replay is as incomplete as the live scan.
  A domain-scoped project id (`example.com:my-project`) is kept whole in live
  scope templates and partitions instead of being split at its colon. An Agent
  Registry skill names only a publisher listed in its own project; any other
  reference keeps the publisher id from the skill's record and no tier.
- `cloud.azure` reads listing diagnostics through the public
  `diagnostics_recorded()`, so an error recorded during the subscription
  listing also leaves the live principal unattested.
- The `plaintext_transport` marker for an MCP URL that redaction hid now
  reaches as far as the `mcp-plain-http` risk factor it recovers, which scores
  every plaintext scheme, loopback included: a loopback `http://` URL whose
  scheme redaction withheld keeps its factor.
- Low-code triggers a person operates no longer count as autonomy evidence:
  n8n `manualTrigger`, `chatTrigger` (and its original `manualChatTrigger`
  type), `formTrigger` and `evaluationTrigger` nodes, Workato Workbot
  commands, menus, buttons, modals and shortcuts, and
  Zapier Chrome extension or Interfaces steps add neither the `autonomous`
  capability nor an initiation tag. Neither does a Make scenario scheduled
  `on-demand`, which a person or a call (the API, another scenario, an AI
  agent or an MCP client) can start, so it records no initiation either way.
  A Workbot event trigger reacts to workspace events, a bot's messages
  included, and is `event-triggered`. A schedule trigger is tagged
  `scheduled` only. Make reads `scheduling.type` and webhook modules instead of
  the first module's name; Workato reads the provider of the recipe's trigger
  line instead of its keyword, which is `trigger` on every recipe and had made
  every recipe event-triggered; the `scheduler` body heuristic now backs up
  only a recipe whose trigger line classified nothing, so a scheduler named in
  an action step no longer turns a Workbot command into schedule evidence.
  n8n's `Respond to Webhook` reply step is no longer read as an event trigger
  of the chat or form workflow it answers. ServiceNow tags a scheduled use-case trigger
  `scheduled`, records no initiation for a use case without a trigger, carries
  `tool-use` only when the export holds the agent's `sn_aia_tool` records and
  `saas-actions` only when one of them is not a retrieval tool, and needs the
  `autonomous` flag or an `agent_type` of exactly `autonomous` for the
  `autonomous` capability. Salesforce `RecordBeforeDelete` flows carry the
  `autonomous` capability like the other record and platform-event triggers.
  The gateway `always-on` tag is initiation evidence only when
  `metadata.activity.always_on_corroborated` is true; the tag alone stays
  informational. It still explains a caller's `autonomous` capability as
  cadence, never as an approval bypass, so a fleet merge (which keeps the
  first observation's metadata and every observation's capabilities) gives
  the same autonomy interval in either report order. The README demo now
  shows 63 high and 54 medium findings.
- `code.filesystem`: an oversize coding-agent settings file skipped with a
  warning while the scan stayed complete (a fixture under a test path with
  `include_tests` and `scan_secrets` off, or a name matched by
  `oversize_skip_globs`) was never recorded as unread, so the readable settings
  beside it could claim an `every-action` approval gate. Such a file now adds a
  `settings-file = unreadable` entry and the project's gate reads
  `some-actions`.
- `code.github`, `code.gitlab`: a truncated GitHub tree listing, or a listing
  with entries that name no path, warned that coverage was partial but left
  every project's approval gate at `every-action`; every gate of such a
  repository now reads `some-actions`. Settings paths from an API tree listing
  that the snapshot did not write were handed to the filesystem scan
  unvalidated, so a traversal or absolute path made the project lookup list
  directories and probe `setup.py` outside the checkout and recorded the path
  in the finding. Such paths are checked like fetched ones before any download:
  traversal, absolute and `.git` paths abort the repository, and the
  filesystem connector refuses any unread settings path that is not confined
  to the scanned root, marking the scan incomplete and the tree's gates
  partial. A settings file at a backslash or drive-like path cannot be
  materialised here but is still one the agent on the scanned workstation
  reads, so it marks the listing incomplete with a warning (gates read
  `some-actions`) instead of being left out. A GitLab tree listing that ends
  with fewer entries than the server's `X-Total` promised is read as cut
  short: coverage is partial and no gate of the project claims every action,
  as for a truncated GitHub listing.
- `shadowscan merge` keeps only the match state of the sources whose
  registration verdict it adopts: a shadow finding keeps the reason and
  suggestions of the sources that found it unregistered, a registered finding
  the assurance and `registry-identity-unverified` tag of the sources that
  matched it, the first such source winning per key. Clearing removes every
  occurrence of the tag, so a report that duplicates it cannot carry a
  non-adopted registration's flag through the merge. When two source blocks
  raised an autonomy bound equally above the merged classification,
  `metadata.autonomy.basis` listed only the first report's rules; a widened
  bound now keeps the basis rules of every block that set it, in rule order,
  so the output no longer depends on argument order.
- The CSV report labels a finding only inventory-less sources assessed
  `unassessed` when the report has an inventory, as the table, Markdown and
  HTML reports do, and leaves the cell blank when no inventory was involved.
  The reporters read inventory presence from `inventory_present` (or a
  reconciled verdict on any finding), as the merge, the dashboard and the
  control evidence do; a bare `inventory_size` from a report written before
  the field existed no longer labels its findings `unassessed`.
- `identity.entra`: a pre-issued `access_token` whose `tid` is not a
  `tenant_id` given as a tenant ID now skips the connector before any request
  (exit 3) in every configuration, not only with `include_agent_registry`. A
  decodable token is bound to its own tenant when `tenant_id` is unset or a
  domain name, which the coverage marker records; a domain `tenant_id` cannot
  be compared and an agent collection then reads the records as another
  tenant's, so give the tenant ID with a pre-issued token. A standalone
  deprecated card manifest in a foreign-tenant export leaves its registry
  record unattributed to `tenant_id`, as every other record site does.
- The AI review gate workflow runs only for pull requests whose changed files
  include `.github/ai-review/**`: it failed closed on every ordinary pull
  request for want of evidence, and on the pull request that introduced it
  because its base ref had no `tools.ai_review` modules.
- AI review gate (`tools/ai_review`): the findings directory from the pull
  request head was enumerated with `glob()` before symlinked files were
  rejected, so a committed directory symlink made the trusted job list an
  arbitrary runner directory. Evidence directories are opened without following
  any symlink component and listed through that descriptor with the artifact
  limit applied while iterating; a symlinked directory or parent is malformed
  evidence and fails closed before anything is listed. The redaction patterns
  now cover the AWS secret access key family that `tools/check_secrets.py`
  detects, and the sanitizer test compares its sample families against
  `check_secrets.PATTERNS` so the two lists cannot drift. A finding or diff
  path containing a line break (`\n`, `\r`, U+0085, U+2028, U+2029), which
  would read back as two paths from the one-per-line diff list, is rejected.
  A title containing any of those breaks is rejected the same way, and a
  fingerprint carrying one is dropped for the computed identity, so a finding
  cannot forge a line of the review body such as the decision header. The
  workflow also runs on `labeled`/`unlabeled` events of evidence-carrying pull
  requests, so an `ai-review: blocked` label takes effect without a push, and
  the label's description says what it does. The policy test for container
  image tag comments reads the Nth occurrence of a duplicated image instead of
  handing the first occurrence's comment to both.
- AI review gate: review bodies were unbounded (nine maximum-size findings
  exceeded GitHub's 65,536-character limit and publication failed). The body
  is budgeted: full findings in severity order while they fit, then one line
  per finding (severity, title, `path:line`) and a count of omitted bodies;
  located findings show their path and line. One aggregate limit of 20
  findings files is enforced before files are copied, so six-role evidence
  that validates always synthesizes instead of failing with
  `bypass_unavailable`. The diff digest is persisted before validation, so
  evidence that fails validation posts the fail-closed `malformed_findings`
  review instead of raising, and a late preflight-failure or blocked-label
  override restates the `Decision` header so the review and the check run
  agree. Every review is posted as `COMMENT`: a bot that never approves must
  not leave a sticky `REQUEST_CHANGES`; the check run's `failure` conclusion
  carries the verdict, and `decide()` returns `(conclusion, reason)`.
- `shadowscan dashboard` and `shadowscan controls` read a report written
  before `inventory_present` existed as `shadowscan merge` reads it: refused
  with "rescan before merging" (exit 1) when it records registration (a shadow
  verdict, a registry match or an inventory size), and as having no inventory
  when it records none. The dashboard guide had said such a report counts as
  having an inventory, and the controls module read its shadow values as one.
- MCP configuration parsing (`code.filesystem`, `endpoint.inventory`): a server
  whose `env` table is not an object or whose `args` list holds a non-string is
  marked `launch_unidentified` (the field is still reported and dropped), so its
  record names no package and matches no MCP Registry entry; before, the launch
  that remained after the drop could identify the package. The redaction
  linearity suite covers the `Bearer token <credential>`, credential-named
  setter call and `*_value` patterns added in #187.
- `shadowscan controls` and the single-report dashboard read a source's
  inventory presence from its own `inventory_present` alone, as a merge records
  it: a report that says it had no inventory but carries an `inventory_size`
  above zero or shadow values no longer reads as reconciled, and a non-boolean
  value is refused. The dashboard's legacy-fleet note and guide now describe
  every pre-`fleet-merge/v2` merge (per-source presence and connector runs
  unrecorded; shadow status kept as written when the merge recorded an
  inventory) instead of claiming such a report never records one.
- A plugin distribution pin (`name=module:Class@distribution==version`) is
  refused as `distribution-mismatch` when the installed distribution's metadata
  lacks `Name` or `Version`; the missing header had compared as the string
  "None", and whether the pin was refused depended on the interpreter's warning
  filters. A connector name that an approval list names twice is refused as
  `conflicting-approval` by the registry itself (configuration validation
  already refused it): a later bare name had replaced an earlier pin, so the
  order of the entries decided whether a typosquatting distribution loaded.
  The triage injection canaries fail when finding text reaches any
  turn other than the one user turn (a prefilled assistant turn passed every
  case before), as the guide already said they do, and when a canary's title
  or evidence did not reach the user turn at all. The canary corpus is read
  as the evaluation corpus is (no symbolic links, 1 MiB cap, duplicate JSON
  keys refused, every case validated) and an empty corpus is refused instead
  of passing vacuously.
- The last-resort redaction of random-looking literals in evidence snippets
  also withholds a literal that an excerpt cut before its closing quote (the
  160-character line trim appends an ellipsis), so the secret's prefix no longer
  reaches the report, and has no upper length bound. Its module joins the
  redaction namespace, so `policy_token()` changes when one of its rules does
  and a finding verified clean under the earlier rules is sanitized again.
- The `auth` block rule withholds a list of credentials under `value`, `key`
  or `credential`, learns the opaque values there so a copy in a sibling
  field is withheld too (a label such as `header` is not learned), and no
  longer takes precedence over the environment rule: an
  `env` table inside an auth block withholds every value, as it does anywhere
  else (a regression of the rule's first extension on this branch). Every
  other member of the block keeps the mapping rules, so a numeric or boolean
  `password` or `client_secret` there is withheld as before (#190).
- `tests/test_repository_policy.py` requires every workflow job `container:`
  and service image to be pinned by sha256 digest, with the reviewed tag named
  in a comment on the line above, as the Semgrep container is.

### AI-assisted review gate

- Add a deterministic, fail-closed AI Review Gate with read-only preflight,
  base-commit-only synthesis, and narrowly scoped review/check publication.
  Missing or malformed specialist evidence blocks the gate. AI cannot approve
  or merge; the human approval and status checks the rulesets require remain
  the merge gate (the rulesets do not require code-owner review).
  This is not independent human review and does not authorize a release.
- The gate's evidence is committed by the pull request's author, so it can
  block a change but never pass one: with no blocking finding the check
  concludes `neutral` (`advisory_only`), never `success`. Do not make it a
  required check; GitHub counts `neutral` as passing.
- `python -m tools.governance_check`, and the ruleset preparation and release
  checks built on it, refuse a ruleset whose required status checks include
  `AI Review Gate`, `AI review publication` or `preflight`
  (`advisory_check_required`); ruleset preparation refuses it on every ruleset
  of `main`, `Protect main` included, and a test reads every committed and
  observed ruleset. A test keeps that list equal to the checks the workflow
  creates, and another pins the workflow's `.github/ai-review/**` paths filter.
- Gate hardening from review: evidence JSON nested too deeply for the decoder
  (a `RecursionError`) is `malformed_findings` with a failure review instead of
  a crash that left the check in progress; a quoted private key is withheld
  as a whole block, not only its header line, however the quote breaks its
  lines, while prose after a quoted header is kept; the publication job runs
  on `!cancelled()` instead of `always()`, so a run superseded on the same
  head before it publishes posts no contradictory review, and one cancelled
  while it publishes completes its check as a failure (`cancelled`) instead
  of leaving it in progress; the evidence paths no longer make every gated
  diff high risk, while a rename out of another path into them still counts
  (and is bound by the digest); and the `ai-review: blocked` label no longer
  claims the gate requests changes.

### Fleet dashboard and inventory export

- Add `shadowscan dashboard REPORTS... -o dashboard.html`: a static,
  self-contained page with no external assets and one hashed script. The
  coverage panel comes first (completeness per source and connector,
  last scan and staleness); a connector a source did not run reads
  "not collected", never 0. Then counts by inventory status, risk level,
  surface, kind, provider, account and owner; autonomy floor against shadow
  status with the shadow L4 and L5 cells marked and linked; vendor registry
  reconciliation per registry; threat and control reference counts
  ("Evidence references, not compliance determinations."); and the AI
  systems table. Every table reads without JavaScript.
- One report is read as `merge` reads a source, so it shows what it would
  show among others: each applicable finding's autonomy interval is
  classified again (a report written before autonomy tiers shows its tiers
  and priority quadrant), and a source's inventory presence is its report's
  own `inventory_present`: a report that says it had none has its shadow
  values cleared, whatever its `inventory_size`, and a report written before
  `inventory_present` existed is refused (exit 1, "rescan before merging")
  when it records registration, as `merge` refuses it. A finding of an
  applicable kind without a valid
  interval reads "not classified" (unknown, counted and warned about in the
  priority section), not "not applicable".
- Coverage has no column for scan-level `engine.*` records, stores a cell
  only for the connectors each source ran (the document grows with the
  runs, not with sources times connectors) and shows at most 100 connector
  columns, with a note for the rest. An incomparable `--baseline` opens the
  page with its own banner, and the coverage drift class counts reasons.
- `--inventory-json FILE` writes the same data as the versioned
  `shadowscan.inventory/v1` document for BI and SIEM tools. Credential
  findings are counted and left out; records carry no evidence snippets,
  evidence attributes, permissions or raw metadata.
- `--baseline FILE` adds drift computed as `diff` computes it; missing
  findings stay unknown unless the comparison is comparable.
  `--history DIR` adds per-report totals and drift between comparable
  consecutive reports (at most the newest 104; a non-comparable pair is a
  gap, never zero). History counts drift without exporting findings
  (`comparison.drift_counts`); 104 synthetic reports of 10,000 findings
  took about 74 seconds. `--as-of TIME` sets the staleness reference, which
  otherwise is the newest source's last scan, never the wall clock.
- Exit 3 when an input or source is incomplete or the baseline comparison is
  not comparable (the files are still written); exit 1 on invalid input.
  Outputs are written with mode 0600 and never through a symbolic link.
- `merge` now records `started_at`, `finished_at`, `inventory_present` and
  each connector run's status for every source, under
  `collection_scope.fleet.schema` `shadowscan.fleet-merge/v2`, and sets the
  merged report's `inventory_present` when any source supplied an
  inventory. The scope fingerprint is unchanged.
- The dashboard reads shadow status as `shadowscan merge` records it
  (registration only from sources with `inventory_present: true`), labels a
  finding that inventories matched to different agents, and notes that a
  fleet report merged before `shadowscan.fleet-merge/v2` records neither
  per-source inventory presence nor connector runs (coverage unknown), reads
  its AI systems as no inventory when it records none and keeps their shadow
  status as written when it records an inventory, with a note to merge its
  sources again.
- Add authored tests for each view, escaping of hostile report values,
  coverage, determinism, private outputs, a 20,000-finding linear-time
  render budget and a linear-time history budget.
  They use synthetic reports and do not establish acceptance on a live fleet.

### Triage, plugin identity, redaction and cache integrity hardening

- LLM triage refuses a reply that names a `verdict` key more than once (for
  example one quoted from injected finding text beside the model's own,
  whether or not either object is strict JSON, nested or repeats the key)
  as `status: unparseable`. The one key must lie in the one object that
  decodes with a verdict, so an injected key spelled with escapes is refused
  too, and a repeated key anywhere refuses the reply.
  Requests send no sampling parameters, which current Claude models reject,
  and OpenAI requests bound the reply with `max_completion_tokens` instead of
  the deprecated `max_tokens`, which the o-series reasoning models reject. The
  bound is 4,096 tokens on both providers: thinking and reasoning tokens count
  toward it, and the earlier 400 ended responses before any verdict on models
  that think; the verdict text is still refused over 16 KiB.
  `options.llm_triage.structured_output: true` asks the provider to constrain
  the reply to the verdict JSON schema (`output_config.format` or a strict
  `response_format`); it is off by default because not every model supports it.
  `python -m tools.evaluation.triage_canaries` runs author-written injection
  canaries offline (in the unit tests), with and without structured output,
  to check that injected text stays data in the user turn (no other turn or
  request field carries it) and cannot change a finding; `--live` sends them
  to a model, unpublished, and exits 3 when any case got no parsed verdict.
- `--allow-plugin` and `options.plugins` accept `name=module:Class`.
  A pinned approval refuses a plugin whose entry point resolves elsewhere
  (`target-mismatch`); a bare name keeps the previous behavior. Duplicate
  approvals for one name are refused. `name=module:Class@distribution==version`
  also requires the entry point to come from that installed distribution and
  version (`distribution-mismatch`), checked from metadata before import.
- Redaction withholds the value in `Bearer token <value>`, keys ending in
  `secretvalue`, `tokenvalue`, `passwordvalue` or `apikeyvalue`, opaque
  literals passed to setter calls such as `setProperty("openai.key", ...)`
  (any string literal when the name is a credential outright, such as
  `openai.secret` or `AzureOpenAI:Secret`),
  and `value`, `key` and `credential` fields inside an `auth` mapping, at any
  depth of the mapping and inside lists under it, whatever their shape (a
  list, set or record there is withheld whole). In `Bearer token <value>` an
  opaque value is withheld wherever it sits, before a colon or on the next
  line included, while a credential name followed by an assignment
  (`Bearer token postgres_password_1: v`) is kept for the assignment rules,
  which withhold its value; the credential stops before a glued `--option` or
  `=name`, so that name too stays whole for the rule that withholds the value
  after it. An opaque value in an auth field, or nested in one, is also
  removed from the record's other fields; a label, placement or URL there
  ('header', 'in', a Postman token request's `resource` record) is not, so it
  cannot withhold unrelated fields or keys; nor is the value of an environment
  entry inside the block, which the environment rule withholds (learned as a
  credential, a value such as `1` had withheld every sibling field containing
  it). A setter-call path whose name
  alone identifies a credential (`m.put("openai.token", ...)`, `"Azure:Secret"`,
  `"app.jwt"`) withholds any literal, as the same names do in settings files;
  paths whose last word names one (`"openai.key"`) keep withholding only an
  opaque literal. Every other member of an `auth`, `authentication` or
  `authn` mapping keeps the mapping rules, so a numeric or boolean `password`
  or `client_secret` there is withheld as on 0.1.2, and the environment rule,
  so an `env` block inside one has every value withheld.
  Evidence snippets also get a last-resort pass that withholds a quoted
  literal that looks generated (20 or more token characters mixing upper
  case, lower case and digits, with frequent class switches and high entropy),
  whatever name or call surrounds it. Hex digests, UUIDs and ordinary
  identifiers keep their text. A Hypothesis property test covers both sides.
- `shadowscan jwt TOKEN...` and `shadowscan run --set` with a credential value
  print a warning that command-line arguments are visible in process listings
  and shell history. The value is never echoed, a `--set` key that is not a
  plain identifier (a token pasted into the key position) is shown as
  `<withheld key>`, and the scan still runs. The warning goes to stderr: a
  wrapper that parses `2>&1` as a report breaks and must read stdout or
  `-o FILE` alone.
- With a stable identity key, incremental cache entries carry
  `payload_hmac_sha256` under a key derived from it, and entries without a
  valid MAC are rescanned. The MAC covers the entry's slot, input fingerprint
  and cache format as well as its payload, so a clean entry's payload and MAC
  cannot be moved into another slot to replay an empty result. Existing keyed
  entries miss once. Unkeyed caches keep the SHA-256 checksum, which detects
  damage, not tampering.
- Incremental Git fingerprinting reads `git` output through the bounded
  metadata reader, so repository-controlled refs cannot exhaust memory.
- The HTTP destination policy judges a well-known NAT64 address
  (`64:ff9b::/96`) by the IPv4 address it embeds, so IPv6-only runners
  behind DNS64 can reach public APIs. NAT64 forms of private, loopback,
  link-local and metadata addresses stay refused, as does the local-use
  prefix `64:ff9b:1::/48`.
- `shadowscan merge` sets the fleet `finished_at` to the latest source time
  compared as an instant, not the lexically largest string. A source value
  that is not an offset-aware ISO 8601 time is ignored.

### Redaction on CPython 3.12.0 to 3.12.3

- Fixed: on CPython 3.12.0 to 3.12.3, redacting a long single line could
  take quadratic time. Those versions' `tokenize` builds a new copy of the
  whole physical line for every token; 400,000 characters of `cookie=a, `
  took 16 to 19 seconds against 0.1 on 3.12.4, 3.11 or 3.13, and
  `test_hostile_repetitive_input_is_matched_in_linear_time` failed there. CI
  runs a later 3.12, so it never showed. Ubuntu 24.04 ships 3.12.3.
- On the affected versions only, each token's line copy is charged to the
  Python assignment work budget, so a hostile line now ends in
  `SanitizationLimitError`: the finding is omitted and the scan is incomplete
  (exit 3) instead of stalling. A regression test forces that path on every
  interpreter. Use Python 3.12.4 or later to avoid these limit errors.

### Integration review corrections (#178)

- Add optional Checkmarx One (#179) and Semgrep (#180) scan workflows that
  upload SARIF to code scanning. Unlike the templates they came from, both
  pin every action by commit SHA with `persist-credentials: false`, set a
  timeout, run only when opted in (`CX_BASE_URI` or `SEMGREP_ENABLED=true` as
  repository variables, with their secrets) and skip pull requests from
  forks, which receive no secrets and a read-only token.
- The Black Duck security scan workflow added on `main` (#182 and this
  branch) pins `actions/checkout` by commit SHA with
  `persist-credentials: false`, keeps every permission read-only (the action
  gets no token, so it neither comments nor uploads SARIF), sets a timeout,
  runs only when a Black Duck SCA, Coverity, Polaris or SRM service is
  configured as a repository variable, and skips pull requests from forks,
  which receive no secrets. Before, it failed every run.
- Agent settings readers no longer crash on a list or object where a string is
  expected (Claude Code `permissions.defaultMode`, Codex `approval_policy` at
  the top level or in a profile, OpenClaw `gateway.customBindHost`). The
  TypeError aborted `endpoint.inventory` and the rest of the file's code
  analysis; such a value now configures no approval gate, as an unknown string
  already did.
- `shadowscan merge` refuses an autonomy block whose basis has a non-string
  rule or bound, or a value outside its bound's vocabulary (a level for floor
  and ceiling, a listed value for oversight and initiation), with the usual
  "rescan before merging" error instead of a traceback. The basis therefore
  never carries free text into a merged report.
- Endpoint replay that drops a malformed approval or posture entry from a
  record no longer records an every-action approval gate from the entries
  left: the dropped one could have loosened it. The gate is `some-actions`.
- LLM triage treats a budget that is not a positive finite number as spent,
  and a NaN deadline as reached, so a `TriageSettings` built in code (which
  skips option validation) cannot turn off both the budget and the job
  deadline. Triage is skipped instead.
- The autonomy guide states the merge rule for declared levels as the code
  applies it: a source scanned without an inventory does not count either way.
- The fleet guide says that a scan configured with `options.trusted_registries`
  counts as having an inventory: it reports unmatched findings as unregistered
  even when no registry produced records, and that wins in a merge.
- A Bedrock action group with malformed function entries no longer records an
  every-action approval gate from the readable ones, and the scan is marked
  incomplete with a warning. `shadowscan merge` ignores an unreadable
  `approval_gate.scope` instead of raising.
- Endpoint replay that skips a whole malformed settings record of a client
  keeps that client's gate at `some-actions` (all clients' gates when the
  skipped record's client cannot be read).
- A settings file that could not be read (invalid syntax, a symbolic link the
  scan does not follow, a non-regular entry, or a file over the size limit or
  that cannot be decoded) adds a `settings-file = unreadable` approval entry for
  its client in `code.filesystem` and `endpoint.inventory`; a problem with one
  MCP server entry in a file that parsed does not. The entry records no gate on
  its own and keeps a gate from the client's readable settings at
  `some-actions`, live and on replay.
- Diff-scoped code scans (`--diff-base`) always read coding-agent settings
  files, as they read dependency manifests and `.env*` files, so an unchanged
  settings file still bounds a changed one's approval gate. A settings file
  the code scan skips because the connector deadline was reached, and one that
  a `code.github` or `code.gitlab` API snapshot does not include (a link, too
  large, past the sample cap or not downloaded), counts as unreadable.
- `identity.entra` attests a live collection scope only for app-only
  credentials. An `access_token` issued to a user (it has `scp`, or its
  `idtyp` is not `app`) or that cannot be decoded lists only what that user
  may see, as a delegated token does, so its scan is no longer attested even
  without agent collections. It still completes, with an advisory warning, and
  `shadowscan diff` reports such a comparison incomplete instead of resolving
  findings that a user with a narrower view did not see.
- Repository policy tests check the egress example's default deny, its
  live-only allowance and the private and metadata ranges it excludes.

### Operational controls guide

- Add `docs/operations/operational-controls.md` (from #175): external process
  supervision with correct systemd (`Type=oneshot` with `TimeoutStartSec=`),
  Kubernetes and CI deadlines; network egress, including that ShadowScan's HTTP
  client ignores proxy environment variables and rejects an explicit proxy,
  so live host allowlists belong in a
  transparent, name-aware egress layer; the plugin trust model; detection
  expectations; and SBOM and provenance as the release-evidence workflow
  actually produces them (a runtime SBOM and wheel attestations, no container
  image attestation).
- Add `examples/k8s-network-policy.yaml`: a default deny-all egress policy
  for every pod labelled `app.kubernetes.io/name: shadowscan`, and a
  live-collection baseline for pods that also carry `shadowscan-mode: live`
  (cluster DNS and HTTPS to public addresses; private, CGNAT, link-local and
  Azure wire-server addresses denied). A live pod without the mode label is
  denied, not unrestricted. The comments give the IPv6 exceptions for
  dual-stack clusters and the metadata endpoints the policy blocks.
- Pin that an LLM triage reply steered by scanned content cannot change a
  finding's risk, shadow status, kind or tags.
- Ignore `*.pyo`, `*.egg` and `*.whl` build artifacts (from #176).

### Fleet shadow status, triage budget and CI corrections

- `shadowscan merge` no longer reports findings from scans made without an
  inventory as unregistered. It turned `shadow: null` ("no inventory
  supplied") into `true`, so a merge of such reports claimed every finding as
  shadow, and the HTML and Markdown reports said "N shadow (unregistered)".
  Shadow status now merges in three states, whatever the order of the
  sources: `true` when any source found the finding unregistered, `false` when
  a source matched it to the inventory that scan was given, and `null` when no
  source that reported it had an inventory. A shadow or unassessed finding has
  no `registry_match`. The merged report carries `inventory_present`
  (true when any source had an inventory, even an empty one), and a source
  whose `inventory_present` is not a boolean is refused (exit 1). A source
  without `inventory_present` (reports from the v0.1.x releases, which share
  the finding identity schema) is refused (exit 1) when it records any
  registration (`shadow`, `registry_match` or a nonzero `inventory_size`):
  reading the missing key as "no inventory" silently turned its shadow
  verdicts into `unassessed` and lowered the fleet's shadow count. Rescan
  such sources before merging.
  The terminal table, Markdown and HTML reports label such a finding
  `unassessed` and count them in the summary when the merged report has an
  inventory, instead of leaving a blank cell that reads as registered.
- Registration claims need an inventory. A scan without an inventory or
  trusted registries passed through the `shadow` and `registry_match` a
  connector or plugin set, and `merge` then counted such a finding as
  registered. The engine now clears that match state (`shadow` and
  `registry_match` become `null`), and `merge` reads registration only from
  sources whose `inventory_present` is true and treats `shadow: false` without
  a `registry_match` as unassessed. Sources that matched a finding to
  different agents make it ambiguous, as two matching inventory entries are in
  one scan (`shadow: true`, `registry_match_reason:
  ambiguous-resource-approval`, the candidates in `registry_suggestions`),
  instead of the first source's match winning.
- LLM triage is bounded. `options.llm_triage.budget_seconds` (default 300,
  1 to 3600) limits one triage run, and the HTTP client's retries,
  `Retry-After` waits, connection set-up and response reads stop at the same
  time. A run stops after three consecutive failed requests. Selected findings
  a run does not reach are recorded as `metadata.llm_triage.status: skipped`,
  with a warning on `engine.llm-triage` that names the reason. Under a CLI job
  deadline (`--job-deadline-seconds` or `options.job_deadline_seconds`),
  triage ends 10% of the deadline before it (at least 5 s, at most 60 s) or is
  skipped, so triage no longer uses up the time reserved for writing the
  report.
  Library callers pass the deadline as `Engine.run(job_deadline=...)`, a
  finite `time.monotonic()` value checked before collection starts;
  `JobDeadline.expires_at` exposes the CLI's.
  Triage stays advisory: risk, shadow status, completeness and `--fail-on` are
  unchanged.
- A triage reply is located in linear time, and a reply longer than 16 KiB is
  refused unread as `status: unparseable` (the response body is capped at
  64 KiB, down from 256 KiB). A greedy pattern over a hostile reply of
  unmatched braces took about 23 s, held the interpreter past the job
  deadline and lost the report. An unexpected error during a request is now
  recorded as `status: failed` like any other failure, so every selected
  finding keeps a triage status.
- CI's container job adds Google's Docker Hub pull-through cache
  (`https://mirror.gcr.io`) to the runner's Docker daemon and pulls the
  Dockerfile's digest-pinned base image before the build. Anonymous Docker Hub
  pulls from shared runner addresses failed with HTTP 429, which failed the
  job on recent pushes to `main`. The digest pin keeps the base image identical;
  the daemon falls back to Docker Hub when the mirror fails.
- A new test checks that every `python -m` module shown in the documentation
  exists. (The README classifier and command fix it guards is logged with
  the #172 entries.)
- `make install-dev` followed by `make typecheck` no longer fails without the
  cloud SDKs: the mypy overrides list the `google` namespace package, which
  `import google.auth` also binds. A new test type-checks every optional SDK
  import with installed packages hidden.

### Control evidence report and declared governance facts

- Add `shadowscan controls REPORT.json [...]` (`--format markdown|csv|json`,
  `-o`, repeatable `--framework`). For every entry of the NIST AI RMF,
  ISO/IEC 42001, EU AI Act and AIUC-1 catalogs it lists the findings whose
  control references name it, split by risk level, with up to 10 examples
  (highest risk first), an evidence status and the scope behind it (report
  and connector completeness, whether an inventory was supplied). Several
  reports are merged as `merge` merges them; a finding counts as shadow only
  when a report reconciled with an inventory says so, and a report's own
  `inventory_present: false` is believed over its shadow values and over its
  `inventory_size`. A report that `merge` produced is refused (exit 1): pass
  the source reports.
- A control no finding references reads `not observed` only when every report
  is complete; otherwise it reads `unknown (scan incomplete)`, and counts of
  referenced controls are marked as lower bounds. An incomplete input still
  writes the output, with an `INCOMPLETE SCAN` banner (a first
  `SCAN-INCOMPLETE` row in CSV), and exits 3. A control no finding references
  reads `unknown (inventory not supplied)` when a finding whose shadow status
  is unknown could reference it through a rule that reads shadow status or
  declared facts (so `GOVERN-1.6`, ISO/IEC 42001 `A.4.2` and AIUC-1 `E` never
  read `not observed` from a scan without an inventory), and
  `unknown (risk class not declared)` when a finding without a declared EU AI
  Act class could reference it through a declared-class rule. Controls no rule
  maps read `not mapped`. The CSV has an `inventory` column (`supplied`,
  `partial` or `not supplied`). The output never says a control is met and has
  no score.
- Every output carries the notice "Evidence references, not compliance
  determinations. Mappings are author mappings and have not been
  independently reviewed." Catalogs gain a required `review` field whose only
  accepted value is `author`; the validator rejects anything else, and the
  generated catalog reference shows it. CSV cells use the CSV reporter's
  spreadsheet-injection protection, a `|` in a Markdown table code span is
  escaped, and output files are written with mode 0600 and never through a
  symbolic link. The JSON schema is `shadowscan.control-evidence/v1`.
- Capability Cards with `schema_version: 2` accept an optional `governance:`
  block: `eu_ai_act_risk_class` (`prohibited`, `high`, `limited`, `minimal`,
  `gpai`, `gpai-systemic`, `unknown`), `intended_purpose`,
  `oversight_measures`, `aiuc1_certificate` and `iso42001_scope`. Unknown keys,
  malformed values and a block on an earlier card fail inventory validation.
  `inventory check` lists the declared class, and `inventory stubs` writes a
  `governance: {eu_ai_act_risk_class: unknown}` placeholder.
- A finding registered by such a card records `metadata.declared_governance`
  (the block plus `source`, the card's agent id). The value is rebuilt on every
  reconciliation pass, so a connector, plugin or earlier run cannot plant it;
  `merge` drops it from findings that are shadow, refuses a report with a
  malformed block, and refuses a registered finding whose reports carry
  different blocks instead of keeping the first report's. A report's block is
  checked without the card's length limits, because export redaction can
  lengthen a declared value. HTML and Markdown reports show the facts as
  declared and not verified.
- Mapping rules gain the `declared_risk_class_any` condition and two control
  rules: a declared `high` class references EU AI Act Articles 12, 14 and 26,
  and a declared `limited`, `gpai` or `gpai-systemic` agent, bot or AI
  application references Article 50. Declared facts count only for registered
  findings and never change risk, matching or approval.
- Add authored positive and negative regressions for every format, the
  incomplete and no-inventory statuses, framework selection, spreadsheet
  injection, card validation and the declared rules. The declared facts and
  the mappings are not verified against any tenant, and regression passes do
  not supply independent human review.

### Drift classes, baseline pinning and weekly drift templates

- `shadowscan diff` labels every changed field with a drift class
  (`inventory`, `capability`, `autonomy`, `governance`, `coverage`) and
  whether it is adverse. Each `changed` entry gains `drift`, and the
  document gains `drift_summary`, `adverse` and `baseline` (`sha256`,
  `pinned`, `age_days`). Existing keys, `changed_fields` names and the text
  header line are unchanged; text output adds a `drift:` line and appends
  the classes to each changed line.
- `diff` now also compares `metadata.autonomy` (floor, ceiling, oversight,
  initiation), an MCP tool's `metadata.tool_definition_sha256` and
  `metadata.registry_reconciliation.status`. A change to one of them alone now
  reports the finding as changed. Reading a report (for `diff`, `merge` and
  `inventory stubs`) now rejects a finding whose metadata is not an object,
  or whose value at one of these paths is malformed.
- Adverse drift: new findings and changed kinds; added permissions,
  capabilities, frameworks, model providers, models and tags (MCP registry
  status tags included); a removed mitigating tag (`disabled`, `inactive`,
  `suspended`, `expired`, `asks-user`, the `*-code-only` and `docs-only`
  scope tags, `pending-request`, `managed-secret`, `mcp-registry-published`),
  whose addition is not adverse; a changed or lost tool definition digest; a higher
  autonomy floor or ceiling, oversight moving towards `bypassed` and
  initiation moving away from `human`; a lost owner, a finding becoming
  shadow, a lost or changed registry match, a reconciliation status becoming
  `observed-not-registered` or leaving `registered-and-observed`, and an
  added `autonomy-understated` tag. Risk changes stay unclassified.
- Add `diff --fail-on-drift CLASSES` (exit 2 on adverse drift in a listed
  class; an unknown class exits 1; an incomplete comparison still exits 3,
  so `coverage` never yields 2), `--baseline-sha256 HEX` (refuse, exit 1, a
  baseline whose raw file bytes have another SHA-256, before parsing or
  printing it) and `--max-baseline-age-days N` (an expired, undatable or
  future baseline, or one that started after the current scan, makes the
  comparison incomplete, exit 3; the limit is at most 36500 days).
  `--fail-on-new` is unchanged.
- A fleet report's `started_at` is now the earliest source start time
  compared as instants, not as text (sources that start or finish at the
  same instant break the tie on the text, so the fleet times never depend on
  report order). When any source lacks a valid
  timezone-aware start time, the fleet's `started_at` is `null` instead of
  the merge time, so an age limit cannot pass an undated fleet baseline.
- Add `read_policy_bytes` and `load_report_with_digest` so the pinned digest
  and the parsed report come from one bounded, link-refusing read.
- Add the weekly `examples/github-action-drift.yml` workflow and
  `examples/k8s-drift-cronjob.yaml` CronJob. The workflow has no pull request
  trigger, top-level `contents: read`, `id-token: write` on its one job, a
  named environment, pinned actions and `persist-credentials: false` on both
  checkouts. It writes only counts per drift class to the job summary and
  keeps reports as 14-day artifacts. Both templates fail with the scan's own
  exit code 2 (`options.fail_on`) or 3 when the comparison exits 0. Repository policy tests check both
  templates. Add the scheduled drift detection page, which covers the record
  and replay pitfalls.
- Add authored regression tests for each drift class and the baseline
  lifecycle. They use synthetic reports and do not establish live tenant
  acceptance or measured precision of the drift classes.

### Threat and control references

- Replace `metadata.compliance` with `metadata.threats` and
  `metadata.controls`. References are now edition-qualified
  (`<framework>-<edition>:<entry>`, for example `owasp-llm-2026:LLM03`,
  `mitre-atlas-2026.09:AML.T0053`, `nist-ai-rmf-1.0:GOVERN-1.6`) and come from
  validated catalogs and rules under `shadowscan/mappings/data/`. They are
  evidence references and author mappings, not compliance determinations, and
  have not been independently reviewed. Consumers reading `metadata.compliance`
  must switch; the key is no longer written, and a value in an older report is
  dropped when it is read for `diff` or `merge`.
- Correct the earlier references: `exposed-llm-server` and
  `unauthenticated-mcp` no longer map to LLM07 (System Prompt Leakage in the
  2025 list, Misinformation in 2026); privilege tags, `code-exec` and
  `saas-actions` no longer map to ASI08 (Cascading Failures); credential tags
  map to Sensitive Information Disclosure and Identity and Privilege Abuse
  instead of supply-chain entries. `code-exec` and `saas-actions` are matched
  as capabilities; as tags they never matched a finding.
- Map a `secret` finding to Sensitive Information Disclosure (LLM02) and
  Unsecured Credentials (AML.T0055) only when an exposure tag such as
  `hardcoded-credential` or `unmasked-ci-variable` supports it. Credentials in
  AWS Secrets Manager, SSM SecureString, Google Secret Manager, OCI Vault,
  GitHub Actions secrets and masked GitLab variables are referenced only as an
  identity (ASI03, MAESTRO layer 6).
- Add MITRE ATLAS 2026.09 techniques for agent tool poisoning, unsafe
  artifacts, credentials in agent configuration, escape to host and exposed AI
  services; CSA MAESTRO layer attribution; and control references for NIST AI
  RMF 1.0, ISO/IEC 42001:2023 (identifiers and own-words labels only), the EU
  AI Act and AIUC-1 domains. Rules can also read autonomy and registry
  reconciliation metadata; malformed or missing values match nothing.
- Threats and controls are derived at export and never read back, so they
  cannot change finding identity, risk, `diff` change detection, merging or
  the incremental cache. HTML and Markdown reports show each reference with
  its title, SARIF results and rules carry them as properties and rule tags
  (at most 20 tags per rule), and CycloneDX entries carry
  `shadowscan:threats` and `shadowscan:controls`.
- Add `python -m shadowscan.mappings.validate` (`make mappings`, part of
  `make check` and CI) and the generated catalog reference page
  (`make mapping-reference`). Each catalog records a `checked` date (when its
  entries were compiled and last checked, not a retrieval date) and the source
  its verification level names; the OWASP Agentic list links the OWASP LLM
  2026 Appendix A its names were checked against.
- The container build context includes the mapping catalogs, without which
  image scans could not write reports, and `.yml` signature packs. A
  repository test checks that the context carries every file the wheel ships.

### Vendor registry records and trusted registries

- Define the vendor registry record contract in `shadowscan/registries.py`:
  `metadata.registry_record` (`shadowscan.registry-record/v1`) with a registry
  type from a closed set, the exact registry and record ids, a closed status
  vocabulary, up to 64 exact-resource bindings with collection coverage, and
  `listing_complete`. A malformed record is ignored and makes the scan
  incomplete (`engine.registries`, exit 3). Record evidence
  (`registry:<type>`, confidence group `registry-record`) has weight 0.5.
  `cloud.aws`, `cloud.gcp` and `identity.entra` emit records (see their
  entries below); no other built-in connector does.
- Only a built-in connector that declares the new `emits_registry_records`
  engine hook may emit records. The engine drops `registry_record` from other
  connectors' findings, including cached ones and those of a plugin that
  declares the hook, and notes the drop in their stats.
- The engine writes `metadata.registry_reconciliation`:
  `registered-and-observed` and `registered-not-observed` or `not-comparable`
  on records, and `registered-and-observed` or `observed-not-registered` on
  observed agents, workflows, bots and MCP servers. Matching is by exact
  binding identity, never by name. `registered-not-observed` requires in-scope
  collection coverage, and `observed-not-registered` requires a complete
  listing of that registry. Statuses do not change shadow status or risk.
- New `options.trusted_registries` lists registry instances by type and exact
  id; wildcards, duplicates, unknown keys and types, and ids that redaction
  would change are rejected, and the list is revalidated before every run. Only
  for those registries does an approved record register its own finding and
  approve its exact bound resources (glob characters escaped) under the usual
  inventory rules. Other statuses and untrusted registries never approve, and a
  card and a trusted record approving the same finding are ambiguous, while
  bindings of one record that cover the same finding are one approval.
  Approvals are rebuilt every scan, so revocation applies on the next run.
  `inventory_present` is true when the option is set, `inventory_size` counts
  the approved records of trusted registries, and a trusted registry without
  records gets an advisory `engine.inventory` warning.
- `Inventory.match` accepts extra entries for a single call; extra entries with
  the same agent id and source count once.
- The record contract adds status `registered` (listed in a registry without
  an approval workflow), `approval_mode` (`auto`, `manual`, `none`,
  `unknown`) and `listing_scope` (`registry` or `caller`; a caller-scoped
  listing is never complete). A trusted registry's approved records with
  `approval_mode: auto` or `unknown` approve only when its entry sets
  `allow_auto_approved: true` (by default only `manual` approvals count),
  and `registered` records only with
  `allow_registered_only: true`; declined records are counted in an advisory
  `engine.inventory` warning. The deprecated `entra-agent-registry` source
  cannot be trusted.
- A connector that emits records also declares the registry types it reads
  (`registry_record_types` engine hook); records of other types are removed.
- Records replayed from an offline export no longer approve. They counted for
  `trusted_registries` exactly like live records, so a forged export line (an
  approved, auto-detected record with `DETECTED_FROM` provenance naming any
  runtime) sanctioned that runtime. The engine now records which findings came
  from a job with `input`, so a connector cannot present them as live; such
  records still reconcile, and approve only for a trusted entry that sets the
  new boolean `allow_offline_records: true`. A replayed record that would
  otherwise approve is counted in an advisory `engine.inventory` warning, and
  a record read both live and from an export in one scan counts as replayed.
- An approved record of a trusted registry registers its own finding through
  an inventory entry for exactly that finding, matched with the loaded
  inventory. It was registered before inventory matching, so a card that also
  approved the record finding was not ambiguous, contrary to the documented
  rule; it now is, and the record finding is held to the same fail-closed
  identity rules (a redacted resource is not registered).
  `TrustedApprovals.approve_record` is removed; `candidates()` offers that
  entry to the record finding alone.
- `min_confidence` no longer removes registry record findings. Their evidence
  has a fixed weight of 0.5, so a threshold above 0.5 dropped every record
  from the report while the approvals they conferred stayed in force.
- Only `approved`, `registered` and `pending` records register what they bind.
  A `draft`, `rejected`, `deprecated`, `blocked` or `unknown` record bound to a
  running agent made it `registered-and-observed`, hiding
  `observed-not-registered` and the `registry-gap` control rule; such a record
  is now `not-comparable` (`reason: record-status`) and its bound agent counts
  as unregistered. AWS registries report absence only for the resource types
  their records can bind (AgentCore runtimes and gateways), so a Bedrock agent
  in an account with a bound runtime is no longer `observed-not-registered`.
- The records in the tests are synthetic; nothing was validated against a live
  registry.

### MCP registry provenance and approved MCP catalogs

- Add `options.mcp_registries` (empty by default): up to 16 MCP Registry
  snapshots, each opted in by its own `id` and pinned by the SHA-256 of the
  file; `approved: true` marks the organisation's approved MCP catalog. Every
  scan reads each snapshot again without following symbolic links, checks the
  pin and validates every entry's structure, name, version and status. A
  missing, changed, oversized, malformed or incomplete snapshot is not used and
  makes the scan incomplete (`engine.mcp-registry`, exit 3). A package or
  remote URL no configured server could match (templated, with user
  information, unparseable, however long, or on another package registry) is
  not indexed and does not reject the snapshot, so one publisher cannot block
  every snapshot. A scan never contacts a registry.
- Add `shadowscan mcp-registry snapshot`. It lists every server version of a
  registry that serves the MCP Registry API v0.1 (default the official
  registry, deleted versions included) over the shared HTTPS client, keeps the
  fields matching reads (packages keep `registryBaseUrl`), validates the result
  as a scan would and writes it
  with mode 0600, printing the SHA-256 to pin. A failed or refused request, an
  invalid page, a repeated cursor or a page, entry or size limit exits 3 and
  writes nothing. The client never uses a proxy.
- After correlation, and before registry reconciliation and scoring, the engine
  matches the MCP servers of `mcp-server` findings (code and endpoint client
  configurations, and `endpoint.mcp` tool findings by server URL) by what the
  client fetches or connects to, with one identity and no fallback: a command
  by its launched package (npm, PyPI or OCI identity), a remote transport by
  its URL, a `server.json` manifest document by every package and remote it
  declares. A launch with a source-changing option or environment variable
  (`--registry`, index flags, `--with`, `--pip-args`, more than one or a
  foreign `-p` command, `--entrypoint`, an unknown option, `npm_config_*`,
  `UV_*INDEX*`, `PIP_*`, `DOCKER_HOST`), an npm alias or Git, URL or file
  source, a shell command line, a URL with user information or an unknown
  transport with both a command and a URL has no identity. A manifest's own
  name gives provenance hints only. Servers get `registry` entries; findings
  get `metadata.mcp_registry` (with an `unidentified` count) and the review
  tags `mcp-registry-published`, `mcp-unpublished`, `mcp-registry-deprecated`,
  `mcp-registry-deleted`, `mcp-registry-version-unpublished`,
  `mcp-registry-outdated` and `mcp-registry-unidentified`, with zero-weight
  evidence. The tags weigh 0, so a configured registry changes no score by
  itself, and publication never lowers risk. Disabled servers add no tags.
  There is no name-similarity matching.
- Add the governance factor `mcp-not-in-approved-registry` (15). It applies
  only when an approved registry is configured and every approved registry
  loaded, to MCP findings with an enabled server that no approved registry
  lists by its identity, that one lists only as deleted, or that has no
  identity: an allowlist cannot vouch for what it cannot identify. A catalog
  package with a `registryBaseUrl` other than its type's public registry
  approves no launch. Like the other governance
  factors it is excluded from `danger_score` and weighs 0 under
  `risk_basis: danger`; `risk_weights.governance` accepts it, and its error
  message now lists every governance key.
- `shadowscan.connectors.mcp_risk` gains `server_package` and
  `registry_package`, the package identity of a launch and of a registry
  listing, on a launcher parser shared with the existing risk checks. The
  shared parser also changes those checks: `npx.cmd`, `uvx.exe` and other
  Windows launcher names are assessed like the plain launchers, `npx
  --loglevel <level>` and the `docker run` value options it did not know (such
  as `--gpus`) no longer have their value read as the package or image, and
  `name@<url>` with an `@` in the URL is no longer read as pinned.
- A `server.json` manifest's parsed server record gains `packages` (registry
  type, identifier, version and registry base URL of each declared package);
  client configuration records are unchanged. A manifest package without a
  string type and identifier, or more than 16 packages, is a parse error that
  makes the scan incomplete.
- The collection scope fingerprint covers the configured registries' ids, pins
  and approval flags, and only when the option is set: fingerprints of scans
  without it are unchanged.
- CycloneDX MCP services carry `shadowscan:mcp:registry-name`,
  `registry-version`, `registry-status` and `registry-source`.
- Map `mcp-unpublished` and `mcp-registry-deleted` to OWASP LLM04:2026,
  ASI04 and ATLAS AML.T0010.005, and to NIST AI RMF GOVERN 6.1 and ISO/IEC
  42001 A.10.3, as author-written evidence references. The governance factor
  is not mapped, because mapping rules cannot read risk factors.
- A launch is no longer identified when something outside its package
  arguments can change what runs: a launcher named by a relative path
  (`./npx`, `tools/uvx`, `.\npx.cmd`) or a UNC path; a `cwd`,
  `workingDirectory`, `envFile` or `env_file` field (kept in the server record
  as `launch_context`, field names only); an environment variable in a
  launcher, package manager, interpreter or container namespace (`NODE_*`
  other than `NODE_ENV`, `BUN_*`, `YARN_*`, `PNPM_*`, `COREPACK_*`, every
  `UV_*`, `PYTHON*` other than output settings, `DOCKER_*`, `CONTAINERS_*`,
  `PODMAN_*`, `REGISTRY_*`), or one that moves the program search path, home,
  configuration or temporary directory, loader or TLS trust (`PATH`, `HOME`,
  `USERPROFILE`, `APPDATA`, `XDG_*`, `TMPDIR`, `LD_*`, `DYLD_*`, `COMSPEC`,
  `SHELL`, `SSL_*`, `REQUESTS_CA_BUNDLE`); a `docker run` or `podman run` mount,
  `--volumes-from`, working directory, `--env-file`, or `-e` of such a
  variable (`-e NODE_OPTIONS=...`); and a `cmd /c` command line or batch-file
  (`npx.cmd`) arguments holding `%VAR%` or `!VAR!`, which cmd.exe expands
  before it reads operators. Such servers are `mcp-registry-unidentified` and
  count toward `not_in_approved`. Containerized servers that mount a data
  directory are unidentified too: a mount can replace the code the image runs.
  A repository `.npmrc`, `bunfig.toml`, `.yarnrc.yml`, `uv.toml` or `pip.conf`
  in the directory a client starts a server in is still not read.
- A server with both a command and a URL now has no identity, whatever its
  transport says: a client that ignores `type` would run the command beside an
  approved URL, or connect to the URL beside an approved command.
- A package or URL several names of one registry list counts as listed in an
  approved catalog only when one of those names lists it, other than as
  deleted, in the version it would be matched to; an unrelated active version
  of a colliding name no longer approves a package listed only as deleted.
- `mcp-insecure-transport` also flags an `http://` or `ws://` URL whose
  authority holds a backslash or user information (redacted when parsed),
  since an HTTP client can read another host from it
  (`http://remote.example\@localhost/` reaches `remote.example`); its evidence
  then names no host.
- Identity and transport checks no longer read only the sanitized record.
  Parsing redacts every `env` value of a file wherever it appears and keeps
  twelve arguments, which could hide the `NODE_OPTIONS` or `PATH` name, the
  `cmd /c` operator or `%VAR%`, or the `docker run -e` value that leaves a
  launch unidentified, and let the approved catalog vouch for it. The parser
  now decides on the configured values and marks a server whose record would
  name a different package `launch_unidentified: true`, and a plaintext URL
  that redaction hid `plaintext_transport: true` (it keeps the
  `mcp-insecure-transport` tag and the `mcp-plain-http` factor); neither
  marker holds a value. A record with a redacted env name, `docker run -e`
  value, or `cmd /c` or batch-file argument names no package.
- A local walk cut short (`max_files`, `max_entries`, the enumeration
  deadline, a symbolic-link check at the deadline, or a directory that cannot
  be listed) keeps every approval gate of that scanned root at
  `some-actions`, as a truncated API listing already did; other roots of the
  same scan keep their own gates. `code.github` and `code.gitlab` clone mode
  delegate to this walk. A strict settings file read before the limit had
  claimed an every-action gate while a bypass beside it went unread.
- Coding-agent settings files are recognized as a case-insensitive file
  system resolves them, ignoring the trailing dots and spaces Windows drops:
  macOS and Windows clients read `.CLAUDE/settings.local.json` or
  `.claude/SETTINGS.LOCAL.JSON` as their settings file, which a scan had read
  as no settings file at all, so a bypass there left a strict sibling
  claiming an every-action gate on a complete scan, and a variant with no
  exactly spelled sibling produced no finding. Such a variant now establishes
  its client as the documented spelling would.
- A launcher under `/proc` or `/dev` (`/proc/self/cwd/npx`) counts as a
  relative path, and `PREFIX` and `DESTDIR`, under which npm reads its global
  npmrc and so its registry, leave a launch unidentified. A launcher path that
  starts with any two separators (`/\host\share\npx.cmd` included) is a UNC
  path on another host and names no package.
- A remote server with `remotes[]` beside its URL is matched by every
  endpoint it lists, which one registry name must list together; before, only
  the first URL was compared.
- `mcp-insecure-transport` and `a2a-plaintext-interface` read a URL as WHATWG
  URL parsers do: tab, CR and LF removed, leading control characters stripped,
  and `http:/host`, `http:\\host` or `http:///host` taken as a plaintext
  remote host (`http:///host` was not flagged before).
- The tests use a synthetic snapshot shaped like the live registry API. No
  live registry fetch or tenant acceptance is part of the test suite.

### Google Agent Registry and Gemini Enterprise catalogs in cloud.gcp

- New opt-in `cloud.gcp` options `agent_registry` and `gemini_enterprise`
  (both default false). `agent_registry` reads Google Agent Registry agents,
  MCP servers and endpoints in projects with `agentregistry.googleapis.com`
  enabled (`agent_registry_version` `v1`, or experimental `v1alpha`, which also
  reads skills and publishers; `agent_registry_locations` limits the
  locations). `gemini_enterprise` reads the agents of Gemini Enterprise apps
  through the Discovery Engine `v1alpha` assistants API. With both off and
  `discovery_collections` unset, no new API calls are made; the engine
  metadata and enabled-APIs changes below still apply. `cloud.gcp` now
  declares the `emits_registry_records` hook for `google-agent-registry` and
  `gemini-enterprise`.
- Each listed item becomes a registry record finding (`agent-registry-agent`,
  `agent-registry-mcp-server`, `agent-registry-endpoint`,
  `agent-registry-skill`, `gemini-enterprise-agent`). Agent Registry records
  are `registered` with `approval_mode: none`; Gemini Enterprise records map
  `ENABLED` to `approved` (`approval_mode: manual`), `PRIVATE` with a
  rejection reason to `rejected`, and other states to `draft`, `blocked` or
  `unknown`, and are caller-scoped, so never a complete listing. Registry ids
  are `projects/<project-id>/locations/<location>` and the Gemini Enterprise
  engine name, with project numbers replaced by ids from the same scan.
- Records bind only to the exact reasoning engine or Dialogflow CX agent they
  reference, rendered as the observed finding's resource; binding coverage is
  `in-scope` only after a complete Vertex AI or Dialogflow CX listing of that
  project and location. Runtime identity and endpoint URL matches are hints
  (`metadata.registry_join_hints`), not bindings. An Agent Registry listing is
  complete only when its locations were enumerated and every location's
  listings completed. `metadata.catalog_presence` compares the two catalogs on
  agents; absence from Gemini Enterprise is never reported.
- New export record kinds `registry-coverage` and `project-number` record
  listing completeness and project numbers. Any record that analysis cannot
  read, anything that makes an offline replay incomplete (such as an invalid
  JSON line or a provider error record that the loader drops), and any
  registry record whose name carries the number of a project other than the
  one it was listed in (dropped with a warning) void every completeness claim
  of that scan: no binding is in scope, no listing is complete and nothing is
  reported absent. Listed items are reduced when collected: agent cards become
  summaries, interface URLs lose userinfo, query and fragment, and icons,
  prompts, assistant instructions and authorization values are dropped.
  `cloud.gcp` `_pages` now reports whether a listing completed.
- New option `discovery_collections` (default `default_collection`). Discovery
  Engine engines keep their kinds (chat engines are `agent`, others
  `cloud-resource`) and record `app_type`, `associated_agent_registry` and
  `subscription_tier`, reasoning engines `effective_identity`, when present.
  Agent Registry counts as an AI API, so a project whose only AI API is Agent
  Registry now has an enabled-APIs finding.
- Replaying the record dump of a scan whose Agent Registry, Gemini
  Enterprise, Vertex AI or Dialogflow CX listing failed is incomplete again
  (exit 3, one warning) when a `registry-coverage` record says a listing did
  not complete; it voids only the claims of those listings, as the live scan
  did. Such a replay previously reported a complete scan.
- A record binds only resources of the project it was listed in. A Gemini
  Enterprise agent's reasoning engine or Dialogflow agent, or an Agent
  Registry `RuntimeReference`, in another project binds and approves nothing,
  even in a trusted registry, and is recorded as a `cross-project-reference`
  join hint; an Agent Registry that holds such a reference is not a complete
  listing of its own project. Bindings always carry the record's own project.
  Previously a trusted app could approve another project's engine, and a
  complete registry made another project's unbound engines
  `observed-not-registered` even when that project's own registry listing
  failed.
- An Agent Registry `RuntimeReference` on a Vertex AI or Dialogflow host that
  is not a plain resource name (an `https:` URL, an API version segment, a
  trailing slash) makes that registry's listing incomplete and the scan
  incomplete (exit 3, one warning). It was previously ignored, so the engine
  it registered could be reported `observed-not-registered`. So does a nested
  name under a reasoning engine or Dialogflow agent (`agents/<id>/flows/<id>`).
  A plain nested name of a collection the scan does not observe (a publisher
  model, `publishers/google/models/<id>`) names no engine and is read like a
  Vertex AI endpoint; it previously made every such scan exit 3.
- A publisher record must be named as a publisher of the project and location
  it was listed in (`_project` and `_location` are now required), and one named
  with another project's number is dropped like a foreign record, so it can no
  longer replace another project's skill publisher or tier. Analysis bounds
  the text fields of replayed registry records to the lengths collection
  uses.
- The fixtures and transports in the tests are synthetic, written from
  Google's API discovery documents; nothing was validated against a live
  project.

### AWS Agent Registry and AgentCore registry records in cloud.aws

- New opt-in `cloud.aws` service `registry` reads AWS Agent Registry
  (`agent-registry-control`) and AgentCore registry
  (`bedrock-agentcore-control`) registries and records of every status
  through `ListRegistries`, `GetRegistry`, `ListRegistryRecords` and
  `GetRegistryRecord`, in every scanned region. `services` now defaults to
  every service except `registry`, so existing configurations make no new API
  call, need no new permission and report no new finding after upgrading.
- Each record is a finding with `metadata.registry_record` (registry types
  `aws-agent-registry` and `aws-agentcore-registry`, registry id = registry
  ARN). The resource is the record ARN and the resource type
  (`agent-registry-record` or `agentcore-registry-record`) is fixed per
  namespace, so identity does not change with the record's status or type.
  Statuses map onto the contract (`CREATING`, `UPDATING` and failed states
  become `unknown`); MCP and gateway records are MCP servers, agent and A2A
  records agents, skill records agent configurations and custom records cloud
  resources. `cloud.aws` declares both registry types through the
  `emits_registry_records` and `registry_record_types` hooks.
- The `DETECTED_FROM` provenance of a record the registry created by
  auto-detection binds the exact AgentCore runtime or gateway ARN it was
  detected from; the binding is in scope only when the `agentcore` service ran
  without a warning or error in that region for the scanned account (an
  export that rejects a runtime or gateway record counts) and every runtime and
  gateway finding of that region could be reported. An auto-detected record
  binds whatever its status: a `DRAFT` nobody submitted registers nothing
  (core reconciliation reports it `not-comparable`, `record-status`), but its
  binding keeps the registry's account in scope, so the runtime or gateway
  behind a registry of drafts only reads `observed-not-registered` when the
  listing is complete. Stripping the draft's binding had left such a registry
  without scope and its runtimes without any reconciliation.
  Provenance on a record created through the API is the publisher's assertion
  and binds nothing, and a provenance relation this release does not recognize
  binds nothing and makes the scan incomplete.
- `approval_mode` reflects the registry's approval configuration at scan time:
  `auto` when an Agent Registry holds any auto-approval rule or an AgentCore
  registry sets `autoApproval`, whatever other settings sit beside it;
  `manual` when neither does and nothing else is set; `unknown` when the
  registry details were denied, and for an approval configuration this
  release does not recognize, which also makes the scan incomplete.
  Auto-approval is not human review: an approved record's evidence says that
  the registry currently auto-approves records and that the record may not
  have been reviewed by a person (a configuration change applies only to
  records submitted after it, so the scan cannot tell how a record was
  approved), and it approves through `trusted_registries` only with
  `allow_auto_approved`.
- `listing_complete` is set only for a record listing that finished without
  denial, a failed or truncated page, a skipped malformed record or the new
  `max_registry_records` cap (default 1000 per region and namespace). Denials,
  throttling, unsupported regions, missing SDK services, malformed responses,
  failed record details and invalid descriptors make the scan incomplete
  (exit 3), and replaying such an export is incomplete again. Gaps that leave
  no record behind survive the export too: each registry's record carries
  `_listing_complete` and `_detail`, and each listing writes an
  `aws-registry-coverage` record (export only), so a denied `ListRegistries`,
  `ListRegistryRecords`, `GetRegistry` or `ListDiscoverableRegistryRecords`,
  an unsupported region, a missing SDK service and a cap used up by an earlier
  registry replay as incomplete. Registry records from exports written before
  these markers replay as incomplete; regenerate them.
- Descriptors are parsed as bounded strict JSON during collection and kept
  only as a sanitized summary (A2A 1.0 cards contribute their
  `supportedInterfaces`; capability and security scheme names are redacted and
  cut to 64 characters); raw descriptor documents, authorizer settings and
  OAuth `customParameters` are never exported or reported, and descriptor URLs
  never become finding resources.
- New `registry_arns` reads the approved records of other accounts'
  registries through the discovery API (`ListDiscoverableRegistryRecords`,
  `BatchGetDiscoverableRegistryRecord`). Those records carry
  `registry_coverage: approved-only`, never set `listing_complete`, have no
  bindings and `approval_mode: unknown`, and keep their registry's account
  without being marked unresolved. Batch errors report only their codes.
- AgentCore gateway findings are named by the gateway ARN, read through
  `GetGateway` (already covered by `bedrock-agentcore:Get*`): `ListGateways`
  returns no ARN, so live gateway findings were named by their id and a
  registry binding to the gateway ARN could never match, reading the record
  `registered-not-observed` and the gateway `observed-not-registered` in a
  complete scan. Only the ARN and URL are kept from `GetGateway`. A failed
  call, or details without an ARN, makes the scan incomplete; a gateway
  replayed from an older export without its ARN takes its region's bindings
  out of scope. A runtime or gateway without its ARN also withdraws every
  record's `listing_complete`, so it is never read as `observed-not-registered`,
  and the scan warns and is incomplete (exit 3), live or replayed alike (a
  runtime whose listing names no ARN had withheld the claims silently on a
  live scan). Live gateway finding ids change: re-baseline them.
- A runtime, gateway or registry record that analysis rejects, that an export
  rejects or a replay drops, or whose finding `run` omits for failing
  sanitization now withdraws the registry claims it could undercut: every
  record's `listing_complete` becomes false and every in-scope binding
  `unknown`. Surviving records had kept `listing_complete` and replay had kept
  the exported in-scope coverage, so an incomplete scan still reported
  `observed-not-registered` or `registered-not-observed` as facts.
- Analysis bounds the text of a replayed registry record to the collection
  limits (names, display names, status reasons and registry names to 300
  characters, record versions to 64, provenance to the exported fields,
  creation and update times to 64, and `createdByAutoDetection` to a
  boolean) and rebuilds its descriptor summary with the collection limits and
  fields; an edited export had carried unbounded text into titles and
  metadata.
- The registry responses and `tests/fixtures/cloud/aws_registry_records.jsonl`
  are synthetic, modeled on the installed SDK models; nothing was validated
  against a live account. The README demo export is unchanged.

### Microsoft Agent 365, Entra Agent ID and delegated Graph auth in identity.entra

- `identity.entra` gains two opt-in collections, both off by default.
  `include_agent_registry` lists the Microsoft Agent 365 package catalog
  (`agent_registry_api`: `v1.0` by default, or `beta`; `CopilotPackages.Read.All`)
  and reads each package's details, bounded by `max_package_lookups`. Each
  package is a `microsoft-agent-365` registry record finding
  (`entra:copilot-package:<id>`, resource type `copilot-package`) with registry
  id `tenant_id`, a status mapped from `isBlocked`, `requestStatus` and
  `availableTo`, `approval_mode: manual` only for an organization's own package
  whose request was approved, and bindings to the objects it may own in the
  tenant: the agent identity it names only when that id is a listed agent
  identity, and the app registration only for an organization's own package.
  A package never binds another service principal, and a Microsoft or partner
  package never binds an app registration of the tenant, so publisher-declared
  ids cannot approve tenant objects. Unknown enum members become `unknown`;
  both enum spellings Microsoft's pages use are accepted. Member lists are stored as
  counts only; the package file and element definitions are not kept.
- `include_agent_identities` lists Entra Agent ID agent identities from the
  Graph beta API. An agent identity enriches the service principal finding of
  the same id (tag `entra-agent-identity`) or stands alone as `entra:sp:<id>`
  with resource type `service-principal/AgentIdentity`; the finding id is the
  same either way. Agent identities, and service principals and app
  registrations a package binds, are reported even without AI signals. Each
  listed agent identity's app role assignments are read, within the
  `max_app_role_lookups` budget, also when the service principal listing does
  not return it.
- Records of the deprecated Entra agent registry (`agentInstance`,
  `agentCardManifest`) are accepted from offline exports only, as
  `entra-agent-registry` records with status `deprecated` that never approve.
- `identity.entra` declares the `emits_registry_records` hook for
  `microsoft-agent-365` and `entra-agent-registry`.
- Live collection with an opt-in appends an `agentRegistryCoverage` record, so
  a replayed export keeps listing completeness and binding coverage and reports
  incomplete collections again. Denied, failed, capped, conflicting or malformed
  package listings make the scan incomplete and the listing not complete; an
  export without the marker has unknown coverage.
- New credential policy: `auth_mode: delegated` reads a signed-in user's Graph
  token from the environment variable named by `delegated_token_env` (default
  `GRAPH_DELEGATED_TOKEN`). There is no configuration key for the token itself.
  Delegated mode requires `tenant_id`, refuses `access_token`, `client_id` and
  `client_secret`, never falls back to app-only credentials, checks the
  unverified `tid`, `scp`, `idtyp` and `exp` claims before any request, and never
  refreshes the token; a token that expires during the scan makes it
  incomplete. Delegated package listings are caller-scoped: the reported
  record has `listing_complete: false` and every binding `unknown` coverage.
  With `include_agent_registry` and `tenant_id`, a pre-issued app-only
  `access_token` must be a JWT whose unverified `tid` equals `tenant_id`, so a
  token of another tenant never produces records attributed to the trusted one.
  `ConnectorContext.secret_env` reads such a variable and registers its value
  for redaction.
- Delegated tokens, and pre-issued `access_token` values whose claims decode
  when an opt-in collection is on, must carry a Microsoft Graph audience
  (`aud` `https://graph.microsoft.com`, with or without a trailing slash, or
  `00000003-0000-0000-c000-000000000000`); a same-tenant token for another
  resource skips the connector before any request is sent.
- A signed-in user's token passed as the app-only `access_token` (it has `scp`
  or no `idtyp: app`), or one that cannot be decoded, no longer reports a
  complete registry listing when an opt-in collection is on: the coverage marker
  and records are caller-scoped (`listing_complete: false`, `unknown` binding
  coverage) and a fixed warning, which names `auth_mode: delegated` and never
  the token, makes the scan incomplete (exit 3).
- A delegated scan with `include_agent_registry` or `include_agent_identities`
  now warns once that it lists only what the signed-in user can see and is
  incomplete (exit 3), so an empty caller-scoped listing never reads as an
  empty catalog. A replayed caller-scoped export is incomplete too.
- An Agent 365 package whose detail call failed, was throttled or was beyond
  `max_package_lookups` is `unknown` with no bindings instead of `approved`:
  `requestStatus` is read from the details, so the package may have a pending
  request.
- An organization's own package (`custom`, `shared` or `lob`) with no approval
  request, such as an agent a user shared, is `registered` instead of
  `approved`. A trusted tenant entry accepts it, with the app registration and
  agent identity it binds, only with `allow_registered_only`;
  `allow_auto_approved` no longer approves it without a reviewer. Only a
  Microsoft or partner package (`type` `microsoft` or `external`) with no
  request is `approved`; a package with no request whose `type` is missing or
  any other member (such as `unknownFutureValue`, which Graph returns for a
  member added later) is `unknown`, so `allow_auto_approved` does not sanction
  it or the agent identity it names.
- A binding's coverage is `unknown` instead of `in-scope` when any record of the
  export was rejected as malformed, so a present but malformed app registration
  or agent identity is not reported `registered-not-observed`. In a replay, a
  record the offline loader dropped (an invalid or truncated JSON line, a
  duplicate key, a provider error record) counts as rejected too: binding
  coverage is `unknown` and `listing_complete` is `false`.
- The coverage marker records the tenant the credential is bound to
  (`tenantId`). A replay whose `tenant_id` differs from it is incomplete and its
  records get an empty registry id and no bindings, so they cannot be trusted
  and cannot mark the configured tenant's objects `registered-and-observed`. A
  pre-issued token's decoded `tid` is recorded also when `tenant_id` is not set
  or names another tenant, and a run whose tenant is unknown writes
  `tenantId: null`, which a replay with `tenant_id` treats as unattributed and
  incomplete; only an older export without the field replays as before.
- The fixtures and Graph payloads in the tests are synthetic, modeled on
  Microsoft's Graph reference pages; nothing was validated against a live
  tenant.

### Autonomy tiers and Capability Card schema version 2

- Classify agents, agent configurations, MCP servers, workflows, bots, gateway
  callers, AI apps, runtime processes and AI cloud resources on the L0 Chatbot
  to L5 Fully Autonomous scale. Each such finding carries
  `metadata.autonomy` (`shadowscan.autonomy/v1`): the floor its evidence
  proves, the ceiling positive evidence has not ruled out (L5 without such
  evidence), oversight, initiation and the rules behind them. Credentials,
  grants, identities, infrastructure, stored models and network contacts carry
  none. The interval is not part of finding identity.
- The `autonomous` capability counts as approval-bypass evidence only where it
  means no person approves each step; low-code and cloud triggers and gateway
  cadence count as initiation evidence instead.
- Agent Capability Cards gain a top-level `schema_version`. Version 2 declares
  `autonomy_profile.level` (an integer from 0 to 5); a level outside that
  range, a non-mapping `autonomy_profile` or a `schema_version` other than 1
  or 2 makes the inventory invalid. A version 1 card's level is ignored as
  undeclared, with the advisory warning
  `autonomy_profile.level ignored: card has no schema_version 2` from
  `inventory check` and under `engine.inventory`. Simple and CSV inventories
  accept `autonomy_level`. The bundled `agent-card.yaml` and example
  inventories declare levels on the new scale.
- A declared level below the observed floor adds the `autonomy-understated`
  tag (risk weight 10). `options.risk_weights.autonomy` (`L0` to `L5`, all 0
  by default) can weigh the observed floor; unknown keys are rejected. No
  other default weight changes.
- `inventory stubs` writes `schema_version: 2` cards whose level is the
  observed floor.
- `code.filesystem` and `endpoint.inventory` record Claude Code, Codex and
  Goose settings that make a person approve actions as
  `metadata.approval_gate`; `cloud.aws` records Bedrock action-group function
  confirmation the same way; `cloud.azure` Logic Apps record
  `metadata.trigger_types`. Claude Code allow rules in any settings file
  (`settings.local.json` included), a sandbox that auto-allows Bash, and
  `PreToolUse` or `PermissionRequest` hooks make the gate partial
  (`some-actions`); the sandbox and hook settings never record a gate on
  their own. Replayed endpoint records keep only approval entries the settings
  reader could have written for that record's client and file, and drop any
  other entry with a warning that makes the scan incomplete.
- `merge` classifies each merged finding again and widens the interval to
  admit what every source's block admits (highest floor and ceiling,
  `bypassed` over `unknown` over `gated`); it rejects a source whose block is
  malformed.
- `merge` applies the combination rules across sources. Bounds widened one by
  one skipped them, so approval bypassed in one source and a schedule trigger
  in another merged to L4; the merged finding is now classified with the
  widest oversight and initiation any source recorded and reaches L5
  (`self-initiated`), with the matching basis entries. A registered merged
  finding keeps the lowest level any source declares for its agent instead of
  the first source's, so `autonomy-understated` no longer depends on the order
  of the reports.
- An L2 ceiling rests on recorded approval settings: it is configuration
  evidence, not proof of how a run behaves.
- The rules and fixtures are synthetic and author-written; they do not
  establish live tenant acceptance or measured precision.

### A2A Agent Card probe and card signatures

- `endpoint.mcp` gains an opt-in live probe. `agent_card_urls` lists HTTPS card
  URLs or agent origins (an origin is fetched at
  `/.well-known/agent-card.json`, then `/.well-known/agent.json` only after a
  404); `max_agent_cards` (default 100) refuses a longer list instead of
  truncating it. Entries are checked when the connector is built. Fetches use
  the shared HTTPS client: same-origin redirects only, private and loopback
  addresses refused unless `options.allow_private_origin`, a 1 MiB body cap,
  strict JSON, and `ca_bundle` for a private CA. URLs declared inside a card
  are never fetched. Without `agent_card_urls` the connector behaves as
  before. A job that sets both `input` and `agent_card_urls` is refused
  (exit 3): a replay never probes, so the listed agents would go unchecked.
- Each fetched card is one `a2a-agent-card` finding (`provider` `a2a`,
  identity discriminator `a2a-card`, resource the card URL without query or
  fragment, framework `protocol.a2a`). Every fetch, HTTP, size, JSON or card
  validation failure is a connector error and the scan is incomplete; a
  card-shaped but incomplete card is an `incomplete-agent-card`
  framework-usage finding. Card records replay from `--dump-records` exports
  and are validated again; an unknown `record_type` is dropped with a warning
  that makes the scan incomplete. MCP tool-list records are unaffected. The
  export also withholds the userinfo of scheme-less `user:password@host:port`
  addresses (gRPC interfaces), which the shared sanitizer does not recognize.
- `code.filesystem` and the probe share one `metadata.agent_card` projection.
  A2A 1.0 `supportedInterfaces` now supply `url` and `protocol_version`, which
  were empty for 1.x cards; `interfaces` lists up to 20 interfaces as scheme,
  host, port and path; projected strings are bounded. A card that declares a
  protocol version other than 0.x or 1.x (top level or on an interface) is
  still reported, with a warning that makes the scan incomplete, in both
  connectors.
- `metadata.agent_card.signature` records `absent`, `present-unverified`,
  `verified` or `invalid`. Verification runs only against the operator's
  `agent_card_jwks_url` (fetched once per run; a failure is an error and
  leaves signatures unverified), as an RFC 7515 JWS over the RFC 8785
  canonical card without `signatures`. Signers drop different empty values
  first, so each signature is checked against three payloads: the card as
  served, the card without any empty string, array or object (the A2A Python
  SDK's form), and the card without empty members other than those the A2A
  1.0 schema marks REQUIRED or `optional` (the specification's section 8.4.1
  example). They differ only by empty values. Key locations a card or
  signature header names (`jku`, `jwk`, `x5u`, `x5c`) are never used; only
  RS256, PS256, ES256 and EdDSA are accepted; critical header extensions and
  unencoded payloads are refused. A card holding an integer beyond 2^53, or
  signed by a signer that also drops `false` or `0` defaults and served with
  them, reports `invalid`. `verified` never approves or registers a finding.
- New risk tags `a2a-plaintext-interface` (10; an `http://` or `ws://`
  interface to a host other than loopback) and `a2a-card-signature-invalid`
  (10), with threat references ASI07 and AML.T0118.001, and ASI07 and ASI04.
  Card files with such interfaces or malformed signatures now score higher.
- A verified card is projected and tagged as the form its signature covers,
  not as served. Empty values added after signing
  (`"securitySchemes": {"oauth2": {}}`, `"authentication": {"schemes": []}`)
  left the card `verified` but removed `no-auth-declared` and showed a security
  scheme; they now change nothing. `signed_forms` returns each form with its
  payload, and `verify_card` returns the form a signature verified.
- An interface URL with user information or a backslash before its host is
  left out of `metadata.agent_card.interfaces` and of domain matching:
  `http://agent.example\@localhost/a2a` was projected as
  `http://localhost/a2a` (HTTP clients reach `agent.example`) and suppressed
  `a2a-plaintext-interface`. The tag now reads each declared URL and fires for
  such an `http://` or `ws://` interface.
- The cards, keys and HTTP exchanges in the tests are synthetic, modeled on
  the A2A specification; nothing was validated against a live agent.

### Attested collection scope for live cloud.aws, cloud.azure, cloud.gcp and identity.entra scans

- Live scans by `cloud.aws`, `cloud.azure`, `cloud.gcp` and `identity.entra`
  can now attest a comparable `collection_scope`, so `shadowscan diff` can
  resolve findings between two complete live scans instead of always exiting
  3. Each connector records, during collection, the principal its provider
  reported (the STS account, never the caller ARN; the tenant
  `GET /organization` returns, for app-only scans; configured GCP projects
  confirmed by their enabled-services listings, or the project set a complete
  `projects.list` returned; Azure subscriptions read with
  `GET /subscriptions/{id}` or listed by `GET /subscriptions`), its non-secret
  options as resolved, the
  regions, projects, locations or subscriptions it covered, and the outcome
  (`ok`, `denied`, `throttled`, `truncated`, `unavailable` or `failed`) of
  every listing whose request does not depend on earlier responses. Detail
  calls per discovered resource, counts, identifiers and timestamps are never
  fingerprinted, so new agents and extra pages keep the scope.
- The scope fingerprint is now computed after collection. A live entry attests
  only when its connector completed, every listing succeeded and the principal
  was confirmed; otherwise the scope is not comparable with the new reasons
  `live collection was not verified or was incomplete` or `live principal
  could not be verified`. A timed-out job, a plugin and every other live
  connector are never attested. `collection_scope.live` publishes each live
  entry's record, outside the fingerprint. The collection scope schema stays
  `shadowscan.collection-scope/v1` and static inputs are fingerprinted as
  before; as with any scanner change, collect new baselines after upgrading.
- `identity.entra` reads `GET /organization` after authenticating
  (`Organization.Read.All` or `Directory.Read.All`, or `User.Read` delegated).
  A denied or ambiguous answer is an advisory warning that leaves the scope
  unattested; a tenant other than a GUID `tenant_id` stops the scan. A
  delegated scan is never attested: its listings return only what the
  signed-in user may see, so another user in the tenant could see less
  without any error.
  `cloud.azure` reads `GET /subscriptions/{id}` for configured subscriptions
  (covered by `Reader`) with the same rules.
- New engine hooks `attests_live_scope` and `scope_options` and the
  `ConnectorContext` methods `attest_principal`, `attest_partition`,
  `attest_operation` and `scope_record`. Only built-in connectors are
  attested.
- The transports in the tests are mocked; nothing was validated against a live
  account or tenant.

### Scan evidence, completeness and replay corrections

- Report only the exception type when a connector, or one `code.github` or
  `code.gitlab` repository, fails unexpectedly inside third-party code, so
  opaque SDK exception text cannot reach reports. Exceptions raised by
  ShadowScan code keep their fixed or sanitized message, such as the HTTP
  layer's transport and read-deadline diagnostics. Plugin-metadata error paths
  are no longer excluded from coverage, and regression tests pin each path
  (from #171).
- Restore the package classifier and the signature-validation command in the
  README, both mistyped on `main`.
- Lint, format-check and type-check `benchmarks/` with the rest of the tree in
  `make`, CI, pre-commit and CONTRIBUTING.md. `benchmarks/README.md` indexes the
  seven benchmarks, and `.gitattributes` marks their corpora, labels and stored
  runs as generated.
- Resolve supported Go SDK import aliases before publishing credential-bearing
  source evidence, and keep excerpts aligned with LF-based source locations when
  literals contain carriage returns. Reports remain confidential; dynamic call
  resolution is limited.
- Treat VPC Flow Log `SKIPDATA`, invalid and contradictory logging statuses as
  incomplete coverage. `NODATA` remains a valid no-traffic observation.
- Attribute network flows by connection identity before aggregation, preserving
  non-AI TLS evidence and refusing conflicting or ambiguous associations.
- Bind hosted-agent invocation evidence to the HTTP method, provider and
  execution operation from the same event. Management requests no longer imply
  runtime activity; invocation attempts do not establish success or tool use.
  Caller names and cadence remain hints rather than independent capability or
  agent-execution evidence.
- Accept ordinary Rust multiline string literals and supported JSX in `.js`,
  `.mjs` and `.cjs` while retaining incomplete results for unresolved syntax.
- Enforce strict JSON and replay byte limits on record exports; reject a failed
  replacement atomically and retain valid live analysis. Empty successful exports
  use an explicit empty record envelope that can be replayed.
- Document baseline migration, paired review controls and repository-level field
  acceptance. These regression changes do not establish live tenant acceptance
  or independently measured field precision.

### Discovery classification and lifecycle identity corrections

- Resolve supported positional SDK credential arguments before publishing
  source evidence, including supported import aliases; retain confidential
  report handling and bounded sanitization.
- Keep standalone .NET tool definitions and unrelated Go receivers as
  framework usage. Recognize supported import-bound .NET automatic tool
  invocation and Go agent construction without claiming runtime execution.
  Shadowed C# tool-mode names cannot borrow an SDK type or alias's automatic
  invocation meaning.
- Keep Microsoft.Extensions.AI `UseFunctionInvocation()` middleware as an
  agent indicator with tool use, still requiring matching import or dependency
  evidence. Clients that this middleware configures, including
  dependency-injected ones, provider constructor chains and target-typed
  options remain agents, as before these corrections. An explicitly
  constructed `FunctionInvokingChatClient` is not a lexical indicator: when it
  is registered through dependency injection or held in fields, the per-file
  proof cannot follow it and the project is reported as framework usage,
  where an `AIFunctionFactory.Create` tool previously made it an agent.
- The C# tool-loop proof reads target-typed `new()` in a local declaration of
  an SDK type and in a response call's options argument, so an explicit
  `FunctionInvokingChatClient` with `ChatOptions options = new() { Tools = ... }`
  remains an agent.
- C# files that never name `Microsoft.Extensions.AI` skip the tool-loop proof,
  so a large file calling an unrelated `GetResponseAsync` no longer exhausts
  its token budget and marks the scan incomplete.
- A Go function type declared on the preceding line, such as
  `type Option func(...)` or one whose result ends in `interface{}` or
  `struct{}`, no longer hides a parameter that shadows the imported
  LangChainGo agents package, and its own parameters no longer shadow the
  package in the function that follows.
- Exclude Python comprehension results and later clauses that cannot execute
  because a literal iterable is empty or a preceding filter is false.
- Match lifecycle observations by the complete case-insensitive device value.
  Different DNS domains and short/FQDN spellings no longer implicitly alias;
  repeated correlation clears stale derived endpoint activity tags.
- Export size, strict-JSON and sanitizer rejections abort dump publication and
  preserve a prior file. Valid records omitted for export size or encoding
  remain analyzed; records exceeding sanitizer safety limits remain skipped.
- Add authored positive and negative regressions. Regression passes do not
  supply independent human labels or live tenant acceptance.

### Discovery attribution and review assurance

- Resolve a bounded subset of local Python import-only re-exports without
  importing or executing scanned code. Unsupported or ambiguous bindings retain
  their existing conservative classification. Shim budgets apply only to modules
  that may be import-only, so large ordinary local modules no longer make their
  importers incomplete; consumers that resolve through no shim keep the
  single-file bindability proof. Queued consumers are matched lexically during
  the walk; their import binding starts only within the walk's deadline budget
  and margin, and any left unbound keep that lexical evidence and are reported
  incomplete.
- Separate the scheduled governance audit's visible-policy checks from complete
  policy assurance. Withheld bypass settings remain explicitly unknown; release
  verification still requires a complete policy readback.
- Add regression coverage and reviewer guidance for these boundaries. These
  checks do not establish human-reviewed field accuracy or live tenant acceptance.

### Verified discovery review corrections

- Join Python exception and pattern-match branches conservatively so an import
  or alias from one alternative cannot establish another path's agent binding.
  Literal unreachable alternatives stay excluded; uncertain bindings remain
  framework usage rather than a proved construction.
- Withhold supported AWS CLI positional credential settings in command text
  and argument arrays, including nested copies used in evidence and caches.
  Preserve variable references and documented placeholder values.
- Export all permissions in CSV, and show inventory reconciliation in table,
  Markdown and HTML reports when a supplied inventory contains zero agents.
  JSON reports now carry the additive `inventory_present` field.
- Add opt-in `agent_granularity: source` for separate supported named Python
  construction identities. Existing project aggregation remains the default;
  source identity is static evidence, not a count of deployed runtime instances.
- Preserve Python AST coordinates across literal control and Unicode separators,
  so registered-tool execution evidence stays attached to the correct source
  construction in both project and source inventory modes.
- Reuse the scheduled governance observation implementation from PR #163:
  visible policy drift fails, withheld bypass settings remain explicitly
  unknown, and complete release verification stays strict. Retained observations
  bind the inspected policy and snapshot to their digests and observation time.
- Add synthetic regressions and migration/reviewer guidance. Independent human
  field labels and scoped live tenant acceptance remain deployment requirements.

### Source identity, guarded import and AWS command review fixes

- Resolve the tool regions of every verified construction in a file in one
  pass that reads each tool body once. A module registering many named agents
  with a shared `tools=TOOLS` list of branching tools no longer exceeds the
  per-file deadline in `agent_granularity: source` mode and drops to an
  incomplete file.
- Keep a tool's execution evidence on the project finding when anything other
  than a named construction's literal tools list can reach it: an unresolved
  or unpacked construction, a computed tools value (`get_tools()`,
  `[lookup] + extra`, `[*EXTRA]`, `Box.tools`, a conditional or comprehension),
  a positional list, another call that receives the function
  (`bind_tools([lookup])`), a method, lambda or local decorator, a decorator or
  method registration, a dispatch loop, or `globals()`, `eval` and `exec`.
  Approving a named source binding no longer hides that capability from the
  shadow project finding. Tools that only named literal lists and direct calls
  reach still move to the named findings; a positional model string
  (`Agent('openai:gpt-4o')`) no longer keeps every tool on the project.
- Restore guarded optional imports after the try/except join correction: a
  name only that try statement binds agrees with handlers that leave it
  unbound, handlers ending in `sys.exit()`, `os._exit()`, `exit()` or `quit()`
  do not continue, and alternative import paths of one package symbol agree.
  Other bindings of the name in the module, handler rebinding, star imports
  and same-named builtins stay uncertain.
- Bind each notebook code cell's statements on their own. A cell that stops
  Run All (`raise SystemExit`, `sys.exit()`, `exit()`, `quit()`) no longer
  makes the constructions in later cells unreachable; Jupyter still runs them.
- Withhold `aws configure set` credential values after unlisted or newer global
  options (`--no-paginate`, `--cli-binary-format`), in other letter cases and
  for `aws.cmd`, across PowerShell and cmd continuations, with comments or
  string prefixes between source argv elements, after a bare `--`, and when
  the executable is passed apart from its argument list (`spawn("aws", [...])`,
  `args=[...]`, `["aws"] + [...]`, Rust `Command::new("aws").args([...])`).
  Reading the separators of commented source argv stays linear: hostile text
  with `aws` in every comment of a long block no longer stalls sanitization.

### Endpoint, fleet and instruction-content corrections

- Endpoint profile discovery fails incomplete (exit 3) when a known location
  cannot be inspected safely, including symbolic links and denied access. The
  other locations are still scanned and reported in the same incomplete
  report; before, one linked file (a stow-managed `~/.claude/settings.json`)
  discarded the whole profile. A linked directory on the way to the known
  locations (a stow-folded `~/.config`) is a coverage gap only when one of
  them exists through it; `code.filesystem` `include` walks pass over such a
  link otherwise, without following it.
- `shadowscan endpoint` reads Windows locations from the profile's own
  `AppData/Roaming`, never from the scanning process's `%APPDATA%`. A mounted
  Windows profile scanned with `--home` was reported complete and empty while
  its Claude Desktop or VS Code configuration went unread, and with `APPDATA`
  set the operator's own configuration was reported under the target's label.
  A scan of the user's own profile (no `--home`) whose `%APPDATA%` is
  redirected outside it (folder redirection to a file share) is incomplete
  (exit 3): the clients keep their configuration there, and the scan does not
  read it.
- `shadowscan endpoint` covers every configuration file location of
  `endpoint.inventory` (LM Studio, Aider, OpenClaw, Goose on Windows, Cline and
  Roo inside Cursor). Its include list no longer depends on which locations
  exist, so a profile without AI clients gets a comparable collection scope
  (a fleet including one stayed non-comparable and `shadowscan diff` exited 3),
  and a client configured or removed later is a new or resolved finding rather
  than a scope change. The default profile resolves symbolic links in `$HOME`.
  `docs/scanning.md` describes how the command relates to `endpoint.inventory`.
- A `code.filesystem` scan with `include` is no longer served from the
  incremental cache, whether its root is given as `path`, `paths` or `input`:
  fingerprinting the root read and hashed every file below it, so
  `shadowscan endpoint --incremental` read the whole home directory.
- In a `code.filesystem` scan with `include`, a file link whose target is not
  selected (a `.claude/CLAUDE.md` linked to an unselected `AGENTS.md`) is a
  coverage gap (incomplete). It counted as covered by its target, which the
  walk never reads, so the scan was complete without the target's content.
- `shadowscan merge` refuses a finding id that another report uses for a
  finding with another identity (exit 1); a report that reused ids could fold
  other machines' findings into its own. Sources are named by their path below
  the reports' common directory, so `<host>/report.json` collections stay
  attributable.
- The hidden-comment check reports HTML comments of any length, and a comment
  that is never closed where Markdown passes it through as HTML (at the start
  of a line, below a list or quote marker, or in raw HTML), which before were
  skipped beyond 4,000 bytes. An unclosed `<!--` in a paragraph or code span
  is shown as text and is not reported; `<!-->` and `<!--->` are empty
  comments. A zero-width joiner inside an emoji sequence, and the tag
  characters of a subdivision flag (England, Scotland, Wales), no longer count
  as invisible text.
- Instruction content checks inspect the original confined file snapshot;
  exceeding their 512 KiB budget marks coverage incomplete.
- Fleet merging validates source completion, counts and collection fingerprints.
  An incomplete source stays incomplete even alongside healthy reports. Duplicate
  findings retain the highest observed source risk and any shadow observation;
  risk is not recalculated using an unknown source policy.
- Preserve the existing CycloneDX AI-BOM semantics when adding endpoint and
  fleet commands: credentials remain in JSON/SARIF, and MCP inventories remain
  services linked to their technologies.

### October 8 benchmark follow-ups

The head-to-head benchmark in `archive/reviews/head-to-head-2026-10-08.md`
compared ShadowScan with ten open-source discovery tools on a synthetic
estate. These changes close the gaps it measured; the benchmark is
author-written and not independent review.

- `shadowscan endpoint` scans a workstation profile at the well-known
  locations of AI client configuration (Claude Desktop and Claude Code,
  Cursor, Windsurf, VS Code and its Cline and Roo extensions, Gemini CLI,
  Codex CLI, Kiro, Amazon Q, GitHub Copilot CLI, Zed, Continue, Goose,
  OpenCode and a generic `.mcp.json`), including user-level skills, sub-agent
  definitions, hooks, rules and instruction files, without walking the whole
  home directory. Findings carry an `endpoint:<hostname>` resource prefix
  (`--label` overrides it) so fleet reports keep provenance; `--list` prints
  the locations that exist. A profile without any location is a complete,
  empty scan with a warning, not a setup error. The `code.filesystem`
  connector gained the `include` option that implements it: a list of paths
  relative to each root that limits the walk to those files and directories.
- `shadowscan merge` combines JSON reports from several machines or scans into
  one report. Findings with the same identity merge like repeated observations
  inside a scan; every finding records the reports it came from in
  `metadata.merged_from`; `collection_scope.fleet.sources` lists the sources.
  The merged report is comparable with `shadowscan diff` only when every
  source was complete and comparable, and its own completion (exit 3) follows
  the sources. Reports with another finding identity schema are refused.
- The existing `--format cyclonedx` AI-BOM supports endpoint and fleet
  reports with its established component, service, credential-exclusion and
  completeness rules; see `docs/operations/ai-bom.md`.
- Coding-agent configuration findings now inspect the instruction files they
  report (skills, `CLAUDE.md`-style files, sub-agent definitions, rules and
  hooks) for content that a rendered view hides or that executes fetched
  code: an HTML comment holding sentences, a network fetch piped into an
  interpreter, an inline blob decoded into one, and invisible or
  bidirectional control characters. Hits add `content:*` evidence with the
  file and line (never an excerpt) and the tags `hidden-instructions` (20),
  `remote-code-fetch` (15) and `invisible-text` (10), which raise the
  finding's risk. `metadata.instruction_content` lists the rules and files.
- A project whose executable code constructs and serves an MCP server (the
  SDK plus a server-construction idiom outside test code) is reported through
  the `mcp-server` capability, `metadata.mcp_server` and an "MCP server in"
  title (see "October 8 MCP server capability and model id attribution" under
  "Candidate change history" in `docs/production.md`). The finding kind,
  resource and identity are unchanged; `mcp-server` findings remain MCP
  configuration inventories.
  MCP client code stays as before.
- Spring AI: `ChatClient` builder chains that register concrete tools with
  `defaultTools(new ...)` after setting a system prompt or advisors, and
  per-request `prompt().tools(new ...)` chains, now establish an agent; Spring
  Boot injects the builder, so the previous pattern (`ChatClient.builder(...)
  .defaultTools(...)` in one expression) rarely matched real services.
- `provider.databricks` no longer treats a bare `mlflow` or `mlflow-skinny`
  dependency as Databricks Model Serving evidence; mlflow's LLM flavors and
  the Databricks packages still match. A classic-ML training project no
  longer produces a low-confidence LLM-usage finding.
- Evaluation corpus: six cases cover the typing changes (mlflow tracking
  versus the LLM flavor, Spring AI with and without tools, a Go MCP server
  and a TypeScript MCP client).

### Change-scoped scans, path context, corroboration and new ecosystems

These change confidence, risk, kind and the set of findings against existing
baselines; rebaseline before comparing (see `docs/production.md`).

- `code.filesystem` option `diff_base` (`shadowscan code PATH --diff-base REF`)
  scans the files committed between the merge base with `REF` and HEAD, plus
  dependency manifests and `.env*` files. Findings carry the `diff-scan` tag and
  `metadata.diff_scan`; the report is not comparable and is never cached. It
  needs Git 2.45 or later and falls back to a full scan with a warning.
- Path context discounts code evidence. Inside a project, documentation
  directories (`docs/`, `guides/`, `tutorials/`, ...) and example directories
  (`examples/`, `samples/`, `templates/`, `recipes/`, ...) scale evidence weight
  by 0.5; generated files (`*_pb2.py`, `*_pb2_grpc.py`, `*.generated.*`) by 0.4.
  When every non-test observation of a project is discounted, the finding is
  tagged `docs-only`, `example-code-only` or `generated-code-only`, its
  confidence is capped at 0.85, 0.85 or 0.7 (`metadata.confidence_cap`) and the
  new default risk weights subtract 8, 8 or 10. `metadata.negative_contexts`
  and `attributes.negative_context` record the context. `include_tests`
  disables the discount, as it does for test code.
- A project finding whose evidence spans independent signal types gains a
  synthetic `corroboration:cross-signal` evidence item of weight 0.10 (library
  and code) or 0.15 (three or more signal types) and
  `metadata.cross_signal_corroboration`, raising confidence and likelihood.
- A mention-only data file with fewer than four products is a catalog when its
  name spells `blocklist`, `denylist` or `blacklist` as one word or two
  (`ai-blocklist.yaml`, `deny_list.json`), so its mentions alone yield no
  finding.
- `import` and `code` signals accept the languages `c`, `cpp`, `elixir`, `r` and
  `lua`; `conda` dependency signals cover the OpenAI, Anthropic, Hugging Face,
  LangChain and LlamaIndex packages. New signatures: Agency Swarm, Rivet, Devin, Bumblebee/Instructor
  (Elixir), LangChain (Elixir), R LLM clients, Lua LLM clients, Rust AI crates,
  Homebrew AI tools (heuristic), MLflow AI Gateway and Cloudflare AI Gateway.
  Several coding-agent, Dify, Flowise, Langflow and SageMaker signatures gained
  patterns and file names.
- An authored 130-case benchmark under `benchmarks/sab_realworld` exercises
  these changes. It is author-written, not independent validation.

### PR review: incremental scan and evidence verification

- Preserve whitespace and newlines in changed Git paths so incremental scans
  inspect the actual filenames.
- Keep semantic rejections and lexical corroboration checks authoritative when
  a signature signal declares an agent indicator.
- A `diff_base` (`--diff-base`) scan of `code.filesystem` is no longer a
  comparable inventory. Its `collection_scope` is `comparable: false` with
  the reason "diff-scoped collection is not a repository inventory", so
  `shadowscan diff` lists earlier findings outside the diff window as unknown
  instead of resolved. The connector warning now says that unchanged files were
  not scanned, even when the report holds no finding.
- `--incremental` never reuses a diff-scoped result. The cache fingerprint
  covers the working tree, not HEAD or the base ref's merge-base, so a squashed
  or rebased branch with an unchanged tree replayed a stale change set.
- `--diff-base` applies only to local PATHS. Combined with `--github-*` or
  `--gitlab-group` it previously crashed with a configuration traceback; remote
  repositories in the same run are now scanned in full, and `--diff-base`
  without PATHS is a usage error.
- A changed path that is not valid UTF-8 now takes the documented full-scan
  fallback instead of failing the connector with no findings.
- A small data file is a catalog by name only when a whole word of its stem
  (split at `.`, `_`, `-`), or two adjacent words, spell `blocklist`,
  `denylist` or `blacklist`. The earlier substring rule also matched
  allowlists, whitelists, egress and ingress policies, which permit the traffic
  they name, and unrelated names such as `oracle_endpoints.yaml` (`acl`) or
  `security_agent.yaml`, dropping their project findings. A bare `block`,
  `deny`, `firewall` or `waf` no longer counts either: a firewall or WAF rule
  set is a default-deny policy with allow exceptions, and
  `infra/firewall-rules.json` opening egress to `api.openai.com` and
  `api.anthropic.com` reported no finding and a complete scan. The scan note
  now says when a file was discounted for its deny-list name.
- Generated code is recognized by file name only (`*_pb2.py`, `*_pb2_grpc.py`,
  `*.generated.*`). A directory named `codegen`, `generated` or `autogenerated`
  and `*.auto.*` files (Terraform `*.auto.tfvars`) are ordinary source again, and
  discounted generated evidence keeps its capabilities. A shell-executing agent
  under `services/codegen/` had lost `code-exec`/`tool-use` and dropped from
  medium to low risk.
- Documentation and example directories discount evidence only inside the
  file's project. A directory that is itself a project root with a manifest
  (`services/templates/requirements.txt`) is a deployable unit and keeps full
  weight, confidence and risk.
- The Elixir and R signatures have no dependency signals, and the schema has
  no `hex` or `cran` ecosystem: nothing parses `mix.exs`, `DESCRIPTION` or
  `renv.lock`, so those signals could never match. Their import patterns name
  LLM libraries only (Bumblebee and Instructor; openai and ellmer):
  `import Nx`, `library(reticulate)`, `library(torch)` and `library(keras)` are
  numerical or general ML code and no longer report LLM usage. The Rust
  signature no longer matches the `candle-core` and `candle-nn` tensor crates
  (`candle-transformers` remains), and the code patterns of the Elixir, R, Lua
  and Rust signatures apply only to files of their language.
- `platform.mlflow-ai-gateway` no longer matches a bare `mlflow` or
  `mlflow-skinny` dependency, so mlflow experiment tracking again yields no
  finding, or a file named `gateway_config.yaml`, which any API gateway may
  use. `coding-agent.devin` no longer matches a lowercase `devin.md` anywhere
  (`content/authors/devin.md` is a page about a person). A file glob cannot
  name the repository root alone, so a root `devin.md` is not matched either:
  this is a known recall gap, and the authored benchmark case `rw-repo-057` (a
  root `devin.md`) is now a false negative, lowering coding-agent recall from
  1.00 to 0.90. `DEVIN.md`, `.devin/` and `.devin.json` remain.
- Lua, R and Homebrew patterns write a quote as `'` instead of `\x27`, which
  the required-literal prefilter could not read.
- The evaluation corpus has 22 authored positive and hard-negative cases for
  the signatures added on this branch (Elixir, R, Lua and Rust LLM libraries,
  MLflow and Cloudflare AI gateways, Agency Swarm, Rivet, Devin, Homebrew).
  Homebrew AI tools are a supporting heuristic with no product finding, so only
  its negative case can be labeled.
- The `benchmarks/sab_realworld` harness compared package labels such as
  `crewai` with signature IDs such as `framework.crewai`, so its signature
  recall was always 0. Labels now match a signature whose ID names them, whose
  dependency signal declares them, or a listed alias. The committed results,
  generated before the agent-indicator revert, are regenerated: agent-tier
  accuracy 0.60 (was 0.70), signature recall 0.90. The results remain
  author-written, not independent validation.

### Real-world benchmark follow-up corrections

- Crawler user-agent domain discounts apply only within a complete quoted UA
  value. A provider endpoint in another value on the same line, or a later
  occurrence of the same host, remains detection evidence.
- The crawler user-agent pass tokenizes only lines naming `mozilla/`, in
  linear time. An unclosed quote followed by escaped quotes made the former
  whole-file stdlib regex pass quadratic and outside the per-file matching
  budget: a 60 KB planted file held the walk for seconds and could let the
  connector deadline discard every finding of the tree.

### Real-world robustness: input-defect taxonomy for code.filesystem

- Malformed input — invalid TOML/JSON in committed templates and fixtures,
  invalid structured configuration syntax, invalid agent manifests, or an
  MCP configuration whose servers value is not an object or array — produces
  file-attributed
  **input-defect warnings** that preserve partial findings and still fail
  the scan closed (exit 3). The file and issue are always named in the
  report; nothing is dropped silently. Integrity and ambiguity
  failures (duplicate keys, conflicting dialects, resource-limit hits,
  undecodable analyzable files, unscanned symlink targets) still fail
  closed, because parsers diverge on those and they could hide content.
  `strict_coverage: true` promotes input-defect warnings to errors; both
  settings mark the scan incomplete. There is no completeness exemption for
  malformed templates or fixtures.

### Lexing, matching and walk-order robustness (real-world benchmark fixes)

- The JS/TS/TSX lexer now lexes brace-less JSX elements as attribute values
  (`title=<span>…</span>`), a legal construct that marked real repositories
  incomplete. Malformed JSX still fails closed. How a plain `.js`, `.mjs` or
  `.cjs` file is read as JSX is described under "Real-world benchmark
  follow-up fixes" below.
- Credential detection scales its per-execution regex allowance linearly
  with declared input size (`LINEAR_SECONDS_PER_MILLION_CHARS`, floor
  0.1 s, always inside the per-file wall budget), so keyword-dense
  megabyte files no longer abort the secret pass with MatchTimeoutError.
  `python -m shadowscan.signatures.validate` now enforces a per-pattern
  throughput floor on secret patterns against a pathological corpus:
  patterns slower than the runtime allowance are rejected at validation.
  The floor measures the matching thread's CPU time, so scheduler
  contention on a shared CI runner cannot fail it. An attempt the
  wall-clock guard stops is retried unless its CPU time already exceeds the
  allowance; a pattern fails when it exceeds the allowance or every attempt
  is stopped.
- The filesystem walk buffers and orders entries by signal priority —
  dependency manifests, MCP and coding-agent configuration first, source
  files last, smaller before larger — so a connector deadline cuts the
  largest, lowest-signal tail first, and the deadline diagnostic now
  reports the exact remainder (never "at least N"). Listing stops after half
  of the time in which a file can still start (`connector deadline: listing
  stopped after N entries`), so a large tree or a slow filesystem still
  scans the entries it listed instead of spending the deadline on
  enumeration. Checks of file and directory links are listing work and stop
  with it. A root that starts when no file can start any more lists
  nothing (`listing stopped after 0 entries`), so a later root of a
  multi-root or organization scan cannot run the connector past its deadline
  and discard the earlier roots' findings. The scan stays incomplete
  (exit 3). Rollout: a tree whose listing alone takes more than that half is
  now reported incomplete even when the former interleaved walk would have
  finished; raise `connector_timeout_seconds` for it.

### Classification and precision

- An exported low-code flow whose nodes include a verified agent node (n8n
  `.agent`/`agentTool`/`openAiAssistant`, Dify `agent_mode: enabled`) now
  yields a `kind: agent` finding, matching the lowcode.n8n connector; an
  LLM chain without an agent node stays `kind: workflow`. Finding identity
  is unchanged (`resource_type` stays `workflow-export`); the finding kind
  and title change, and metadata gains `agent_flow`. Evaluation corpora
  were relabeled accordingly.
- Provider domains quoted inside crawler user-agent strings
  (`Mozilla/5.0 (compatible; …-Bot/1.0; +https://provider.example/)`) no
  longer count as provider usage; the discount is recorded as a visible
  note naming the hosts.

### New capabilities

- `--format ocsf`: OCSF 1.1.0 Detection Finding (class_uid 2004) report
  output for SIEM pipelines, with scan completeness marked on the document.
  Each event declares the `datetime` profile in `metadata.profiles`, which
  defines its `*_dt` timestamps.
- `triage: true` (and `shadowscan code --triage`): a fast subset scan of
  manifests, MCP/coding-agent configuration, flow exports and IaC that
  skips source analysis, credential detection and content sweeps. A triage
  scan is always reported incomplete so it can never pass as a full scan.
- `shadowscan diff --shadow-only`: display only findings whose `shadow`
  field is true; counts, incompleteness reasons and exit codes are still
  computed over the full comparison, and the JSON document always carries
  the complete comparison plus a `shadow_only_view` id list.

### Real-world benchmark v2 runner hardening

- The real-world benchmark runner and exit probe refuse privileged execution.
  Outputs use private directories and atomic writes that reject symlink paths.
  User/network/PID namespaces require an externally isolated disposable host;
  they do not establish filesystem isolation. The v2 scorer also validates
  result metadata and boolean detections against the declared corpus.
  Historical result hashes are preserved; rerun the revised code separately.
- The v2 scorer labels the entries added in v2 as held out only for a run recorded
  before commit 7e523ba (9fdaf85 after its sign-off rewrite) tuned the Rust and JSX
  lexer on them, which is the frozen v2 run. A run at any other commit, including
  every run of the merged code, reports them under "Entries added in v2 (not held
  out ...)" with the reason.

### Lexical coverage: two constructs the lexer wrongly called ambiguous

- Fixed: a Rust ordinary double-quoted string may span lines. The lexer ended it at the
  line break and reported `incomplete source lexical analysis`. It now stays open across the
  break, and an unclosed one is still incomplete.
- Fixed: a `.js`, `.mjs` or `.cjs` file with JSX (React code in a `.js` file) was lexed as
  plain JavaScript and reported incomplete. Such a file is now also read as JSX, under the rule
  described under "Real-world benchmark follow-up fixes" below. `.ts` files are never read as JSX.
- Fixed (fail-open in the two changes above): a quote the Rust lexer misread opened an ordinary
  string that now ran across lines to the next quote, masking the code in between while the file
  reported complete. Rust C raw strings (`cr"..."`, `cr#"..."#`) and character literals with a
  `\x7F`, `\u{201C}` or `\u{1_F600}` escape were misread this way; both are now recognized.
- Fixed (fail-open): a `<` right after another `<` no longer opens a JSX element. `<<` is one
  shift token, but in `mask<<shift>limit` the second `<` opened a `<shift>` element whose text ran
  to a later `</shift>`. That masked code, including any construct that made the file ambiguous,
  and the file reported complete. This affected `.js`, `.mjs`, `.cjs`, `.jsx` and `.tsx` files.
  The code after such a shift now stays visible, and a file it leaves ambiguous stays incomplete
  (exit 3). A `<<` elsewhere in a file (`"<<SYS>>"`, `<<EOF`, `1<<n`) does not change how its JSX
  is read.
- Measured on the v2 real-world repositories (a tuning set for this change, not held out): 77 of
  the 100 lexically flagged files, excluding notebook cells, now complete. The bundled regression
  corpora (`make evaluate`) show identical outcomes with timing removed; only the scanner source
  hash differs.
- Not changed: Ruby `#{...}` interpolation in a here-document still marks the scan incomplete. An
  attempt to scan the interpolated code as code reported a Java framework in a Ruby file, because
  the matchers are not Ruby-aware. That change was reverted, and
  `tests/unit/test_source_lexer_benchmark_regressions.py` pins the conservative behaviour. Binary or undecodable
  content, parser failures on configuration files, connector deadlines and notebook cell lexing also
  still mark the scan incomplete.

### Real-world benchmark follow-up fixes

- A `.js`, `.mjs` or `.cjs` file is read as plain JavaScript first. When that
  reading is ambiguous, or the file holds a closing or self-closing tag (`</a`,
  `/>`), it is also read as JSX. When only one reading completes, that reading
  is used. When both complete, only what both mask stays masked: element text
  such as `src/*.js` can no longer open a plain-JavaScript comment that hides
  code up to a later `*/` while the scan reports complete. When neither
  completes, or the JSX reading exhausts its look-ahead budget, the file is
  incomplete (exit 3).
- Fixed: lossy text decoding checks every bounded window, so an ASCII prefix
  cannot hide an invalid or control-character body. Python and notebook files
  with a UTF-8 byte-order mark retain strict decoding of invalid bytes.
- Fixed: real-world benchmark candidate URLs require an exact parsed GitHub
  or GitLab hostname, safe path components and supported transport. Host-like
  text in another site's path or query cannot create false provenance.

### Real-world benchmark follow-ups

Running ShadowScan on 326 public repositories (`tools/benchmark/realworld`)
showed that 28% of scans ended incomplete (exit 3) and that most false alarms
came from two causes. Each item below was reproduced on a specific repository
before it was changed, has a regression test, and leaves finding IDs unchanged.
`docs/production.md` lists the effect on reports.

- Fixed: the JavaScript check that drops an SDK binding shadowed by a method
  parameter ran a quadratic pattern over the whole source. On a 22 KB
  TypeScript file it exceeded the 0.1 s pattern budget, the whole file's
  analysis was lost and the scan was incomplete. It now runs the same pattern
  on the window around each use of the name; a test compares it with the
  original pattern on generated inputs.
- Fixed: the source lexers called these ambiguous (exit 3) and, where they
  mis-read them, treated string text as code: ordinary strings that span lines
  in Rust, PHP and F# (`.fs`; F# scripts are not scanned); PHP 8 attributes (a `#[` line in PHP before 8 is a comment and now reads as code), which were read as comments; F# type
  variables and primed names; C# `@"""` verbatim strings; JSX in `.js` files;
  the TypeScript non-null assertion before a division; and Qt translation files
  named `.ts`. Strings that stay ambiguous (unclosed, Ruby, heredoc
  interpolation) still end the scan as incomplete.
- Fixed: a file with a few stray NUL bytes in otherwise valid UTF-8 text, or
  text that is not valid UTF-8 and has no NUL byte, was skipped whole and made
  the scan incomplete. Both are read now and add a warning; dense NUL content
  and UTF-16/32 without a byte-order mark remain gaps. Content that is mostly invalid UTF-8 or holds
  control characters stays a gap. Notes are one warning per kind; `strict_coverage` treats each as a gap.
- Fixed: agent definition front matter with `: ` in a plain value was
  `invalid agent definition YAML`. It is quoted and parsed again through the
  same strict loader, as coding agents do.
- Fixed: `re:^mcp\.[a-z0-9-]+\.[a-z]+$` matched dotted identifiers such as
  `mcp.translator.translatekey`. It now ends in one of a short list of common top-level domains.
- Fixed: a host on a hosts-file, ad-block, resolver or proxy-rule line counted
  as use of that product. The filter applies to non-source documents only.
- Changed: a `secret` finding with no attributed provider is titled
  `Hard-coded credential in <file>` and tagged `unattributed-credential`
  instead of `LLM provider credential in <file>`.
- Added: `protocol.mcp` recognizes JSON-RPC method dispatch without an SDK, and
  `coding-agent.claude-code` recognizes `.claude/launch.json`,
  `.claude/rules/*.md`, `.claude/output-styles/*.md` and the plugin manifests.

### Shadow AI discovery benchmark follow-ups

- Fixed: the model-identifier literal limit now marks coverage incomplete
  when later literals were not matched. A model beyond the limit can no
  longer produce an empty scan reported as complete.
- Fixed: that limit counts only model-id candidates, literals that carry a
  vendor stem. It counted every quoted string, so an ordinary file with more
  than 400 strings and a stem anywhere in its text (`import.meta`,
  `command-line`) made the scan incomplete (exit 3) with nothing unread.
- Fixed: truncated catalog assignment and data-file reference analysis also
  marks coverage incomplete while preserving the evidence already read.
- Fixed: a truncated data-file reference list marks coverage incomplete only
  when the project discounts a data file as a catalog that an unread reference
  could have named. A non-AI repository whose test loader listed about 200
  fixture JSON paths exited 3 although no result could change.
- Fixed: a file's analysis keeps only the excerpts its recorded matches ask
  for, not every redacted line until emit, so memory follows the number of
  excerpts rather than the size of all matched files. A root-level Python
  re-export consumer analyzed after the walk now keeps its excerpts; its
  evidence had empty snippets unless an earlier pass had excerpted the file.
- Fixed: the discovery benchmark carries incomplete runs (ShadowScan exit 3)
  into scoring, the report and the regression gate. `metrics.json` records
  `incomplete_runs` and a per-repository `incomplete` flag, REPORT.md marks
  those cells `(incomplete)` instead of showing an incomplete control as
  clean (43 of 87 ShadowScan runs in the 2026-10-09 baseline were
  incomplete), and `compare` fails when a repository complete in the
  baseline becomes incomplete. `compare --baseline-runs` reads the flag from
  the `runs.json` of metrics scored before it was recorded. The committed
  2026-10-08 and 2026-10-09 `metrics.json` and REPORT.md are re-scored and
  re-rendered from their `runs.json`: they mark the controls psf/requests,
  ripgrep and Newtonsoft.Json and the near-miss jenkinsci/docker-agent
  incomplete instead of clean, and the benchmark README discloses the 43
  incomplete runs next to its results tables. No other number changed.
- Fixed: a dispatched benchmark run of some repositories (`--repos`) is scored
  and compared over those repositories only. The unselected ones were scored
  as missing, so the gate always reported a recall regression. Its REPORT.md
  lists only the scored repositories; the others showed as `?` or `missing`.
- Docs: the benchmark's isolation is described as it is: a rebuilt
  environment and a dead proxy that clients may ignore, not a network or
  filesystem sandbox; third-party tools need an externally isolated runner.

### Shadow AI agent discovery benchmark

- Add `tools/evaluation/benchmark_followup_corpus.json`, 24 authored synthetic
  cases (16 positives, 8 negatives) that reproduce the shapes behind the
  misses and false positives observed on the 87-repository benchmark: model
  identifiers in code, LiteLLM Bedrock routes, implemented MCP servers in
  Python, TypeScript and Go with exact `mcp-server` and `tool-use`
  capabilities, `AnthropicBedrock`, Voyage AI, OllamaSharp,
  `Directory.Packages.props`, Koog, LangChain4j MCP, devcontainer sample keys
  and a code-loaded `model-settings.yml` carrying `api_base` hosts and
  `api_key_env` names on the recall side (a loaded settings file holding model
  identifiers only is still an open miss, recorded in `docs/evaluation.md`);
  Rust
  `ToolCallback` and `create_agent(`, Hugging Face host mentions, the
  `InferenceClient` call shape, Browserbase without Stagehand, CI images,
  documentation catalogs, a test-defined `handoff(`, `DIFY_API_KEY` and a
  model leaderboard on the precision side. No case carries a `known_gap`
  waiver. `make evaluate`, CI and `docs/evaluation.md` run and describe it;
  `tests/test_evaluation.py` pins its counts. Labels are author-written
  reproductions of public-repository shapes, not independent review.
- Add `tools/discovery_benchmark/`, a harness that runs ShadowScan's
  `code.filesystem` connector and other open-source code-surface discovery
  tools (Trusera ai-bom, NuGuard, AgentDiscover, Agentic Radar, SafeDep xbom
  and vet, Geiger, cdxgen) against the same pinned public repositories as an
  unprivileged user with no network or credentials, normalizes their output
  into one tool-neutral fact taxonomy and scores precision and recall at
  repository, category and value level.
- Add `benchmarks/shadow-ai-discovery/` with the pinned corpus (positives,
  controls and vocabulary near-misses), session-labeled expected facts with
  evidence pointers, the run results and the report. The labels are
  author-written evidence, not independent human review, and the benchmark
  covers the code surface only.

### Signatures

- New capability `mcp-server`: the project exposes tools to other agents over
  MCP. The `protocol.mcp` code signal is split into server idioms that carry
  it (`FastMCP(`, `mcp.server.Server(`, `new McpServer(`, `server.NewMCPServer(`,
  `mcp.NewServer(`, `McpServer.sync(`, `McpServer.Create(`, `.AddMcpServer(`,
  `[McpServerTool`, `impl ServerHandler for`, the server transports and
  `@mcp.tool`), the ambiguous low-level `Server(` class (counted only with
  other MCP evidence in the project) and client idioms that carry no
  capability. `mcp-server` scores the same 5 risk points as `tool-use`, so an
  MCP server project's default risk rises by 5; `risk_weights.capabilities`
  accepts the new key. The default-weight digest in the tests is updated
  and `docs/production.md` carries the migration note.
- Model ids: every `model` pattern is anchored. The families whose prefix is
  a common word are closed with the id's own alphabet (OpenAI's `gpt-*`,
  `o1`/`o3`/`o4`, `chatgpt-*`, `text-embedding-*`, Cohere's `command*`,
  `deepseek-*`), optionally followed by an Ollama/OpenRouter `:tag` or a
  gateway `@region` pin, or gated on a generation or tier (`claude-`,
  `sonar`), so `gpt-4-turbo-docs.md`, `command-line`, `o1ne`, `claude-code-*`
  and `text-embedding-004` (now Gemini only) are no longer OpenAI, Cohere or
  Anthropic ids, while every `gpt-` id (`gpt-35-turbo`, `gpt-image-1`,
  `gpt-realtime`, `gpt-audio`, the tagged `gpt-oss:20b`) still is. The
  `gemini-`, `grok-`, `mistral-`, `embed-`, `rerank-` and `voyage-` prefixes
  stay open-ended. LiteLLM-style routes attribute the routed provider:
  `bedrock/`, `vertex_ai/`, `anthropic/`, `openai/`, `gemini/`, `mistral/`,
  `cohere/`, `cohere_chat/`, `xai/`, `deepseek/` join the providers' id
  signals; `openrouter/`, `together_ai/`, `groq/`, `ollama/`, `ollama_chat/`,
  `huggingface/<org>/<model>`, `perplexity/`, `cerebras/` and `voyage/` are
  new signals at weight 0.6. A route must carry a model id (`bedrock/edition`,
  `xai/README` and a bare `mistral/` do not match). New bare families:
  `voyage-*` embeddings (never `rerank-*`, which is Cohere's), the Cohere
  `command`, `command-r*`, `command-a*`, `command-light*` and `command-nightly`
  ids, the `claude-fable-*` tier and the `deepseek-ai/<model>` Hugging Face
  names. No family is limited to a list of generations: `deepseek-v4-*`,
  `deepseek-flash` and `gpt-5.4` match as the next ids will.
- Claude on cloud platforms: `AnthropicBedrock(` and `from anthropic import
  AnthropicBedrock` attribute `provider.aws-bedrock`, `AnthropicVertex(` and
  its import `provider.google-vertex-ai` (previously both were Anthropic
  code evidence). Bedrock also gains `CLAUDE_CODE_USE_BEDROCK` (0.5),
  `AWS_BEARER_TOKEN_BEDROCK` (0.6), the `BedrockRuntime*` client classes and
  the `"bedrock-runtime"` service name, the `@anthropic-ai/bedrock-sdk`
  package and import, and the Rust `aws-sdk-bedrock*` crates; Vertex gains
  `CLAUDE_CODE_USE_VERTEX` and `@anthropic-ai/vertex-sdk`. The Claude model id
  still attributes Anthropic, so Bedrock Claude ids label both providers.
- JVM provider modules: LangChain4j `dev.langchain4j:langchain4j-<vendor>`
  modules and `dev.langchain4j.model.<pkg>.` imports, and Spring AI
  `spring-ai-starter-model-<vendor>` / `spring-ai-<vendor>` artifacts and
  `org.springframework.ai.<vendor>.` imports attribute the provider
  (Anthropic, OpenAI, Azure OpenAI, Bedrock, Vertex AI, Gemini, Cohere,
  Hugging Face, Ollama, Mistral, Voyage AI) alongside the framework; the
  Spring AI `spring-ai-starter-mcp*` / `spring-ai-mcp*` prefixes and
  `dev.langchain4j:langchain4j-mcp` with `dev.langchain4j.mcp.` imports attribute
  `protocol.mcp`.
- Long-tail SDKs: Voyage AI import, `voyageai.Client(`, npm `voyageai` and
  `voyage-ai-provider`, `VOYAGE_API_KEY` raised to 0.6; Ollama `OllamaSharp`
  (NuGet and `using OllamaSharp`) and the `host.docker.internal:11434` /
  `0.0.0.0:11434` endpoints; Hugging Face `@xenova/transformers` and the
  `@xenova/...` / `@huggingface/...` JavaScript imports.
- New `framework.koog` (JetBrains Koog, Kotlin): the `ai.koog` Maven group and
  `import ai.koog.` lines; agent indicator with `tool-use`.
- Browserbase / Stagehand split: `framework.stagehand` keeps only the agent
  SDK (`@browserbasehq/stagehand`, `stagehand`, `stagehand-py`, their imports
  and `new Stagehand(`); the new `platform.browserbase` owns
  `@browserbasehq/sdk`, `browserbase`, `BROWSERBASE_API_KEY`,
  `BROWSERBASE_PROJECT_ID` and the `browserbase.com` API hosts with
  `browsing` and no agent indicator, so a project that only rents hosted
  browsers is framework usage, not an agent.
- Language gates: the Spring AI (`ToolCallback`, `ChatClient.builder(`,
  `@Tool(`), LangChain4j (`@Tool`), Rig, LangChainGo,
  Microsoft.Extensions.AI, Cloudflare Agents, Inngest AgentKit, Semantic
  Kernel (.NET and Python idioms) and the Go, Java, .NET and Rust MCP server
  idioms declare `languages`, so a Rust `pub trait ToolCallback` or a C#
  `AddMcpServer()` string in a Python file no longer counts. Config
  projections and `shadowscan signatures test` pass no language and are not
  gated.
- `provider.openai`'s bare `chat.completions.create(` / `responses.create(`
  signal is `ambiguous`: it counts only with the openai package, import or a
  specific OpenAI code match in the project. `provider.openai-compatible`
  gains a weight-0.5 code signal for an `OpenAI(` / `AsyncOpenAI(` /
  `new OpenAI({` constructor that sets `base_url` / `baseURL` (bounded to
  the constructor's argument list) and an `ambiguous` weight-0.5 signal for
  the `.chat.completions.create(` request shape, which counts only next to
  such an override; a plain OpenAI SDK project stays `provider.openai` alone
  (the `review_corpus` case `provider-call-only` forbids the second
  provider).

### code.filesystem

- Rust test modules (`tests.rs`, `*_test.rs`, `*_tests.rs`) are test paths, and a
  model identifier inside a test file is a weak mention like a host there: Rig's
  `accounts/fireworks/models/...` fixture no longer adds Fireworks. A literal that
  ends in a file extension (`sonar-project.properties`, `gpt-4-notes.md`) is never
  read as a model identifier.

- Throughput: excerpt lines are cut at emit time for the evidence a report
  keeps. Every file that recorded excerpted evidence is still redacted when
  its analysis ends, so a sanitization limit in a file whose matches are all
  dropped keeps the `structured sanitization incomplete ...; excerpts
  withheld` error and the incomplete scan (exit 3). The Python import binder walks
  a module only when one bounded pass over its import statements finds a
  module a signature can bind (a module that cannot bind is still parsed, so a
  file that does not parse keeps its `source did not parse` warning and its
  lexical framework evidence), and the JavaScript binder skips the call scan
  when no import resolves to a signature (its lexer still runs: the regex
  passes need its comment and string spans, which are their ignore ranges).
  The Python gate keeps the binder for any line naming `import` or `from`
  that is continued with a backslash, holds a form feed or joins statements
  with `;`. The import, code and credential passes of a source file share one
  literal scan and one case-folded copy. A structured file is parsed once: the
  manifest (`package.json`, `composer.json` when strict JSON), configuration
  and MCP passes reuse the document instead of parsing the text again, and
  parse failures stay reported where they were. Findings are unchanged; a
  determinism test compares two scans of a tree.
- Follow-up, not implemented: an opt-in process pool (`workers`) for
  `code.filesystem`. It needs in-order application of per-file results, a
  signature index and confined root descriptor per worker, crash and
  deadline handling that fails closed, and credential values crossing process
  pipes; see `docs/scanning.md`.
- The per-file matching budget (`scan_timeout`) is CPU time of the analyzing
  thread, with an absolute elapsed-time cap of four times the budget clipped to
  the connector deadline, so a scanner descheduled on a busy host no longer
  fails ordinary files with `MatchTimeoutError`; the diagnostic reports both
  figures (`cpu 2.01s of 2.00s, wall 2.40s of 8.00s`). The Python re-export
  pass after the walk clips its binder's cap the same way, and a consumer it
  queues is redacted during the walk, so neither that pass nor emit can run
  past the deadline the walk kept for them.
- Implemented MCP servers are first-class: a Python or JavaScript server
  construction is import-bound (`FastMCP(`, `Server(` from `mcp.server` and
  `mcp.server.lowlevel`, `new McpServer(` and `new Server(` from
  `@modelcontextprotocol/sdk/server/*`, `fastmcp`, `mcp-framework`) and
  recorded as `import-bound MCP server construction` evidence that replaces the
  lexical match of its line, so the low-level `Server` class is told apart from
  `http.server` and Node `http` servers. The ambiguous `Server(` pattern never
  establishes a server, so an MCP client next to an `aiohttp`, `socketserver`
  or `socket.io` server keeps `tool-use` alone, and a lexical `FastMCP(` or
  `new McpServer(` the binder did not resolve counts only in a file that
  imports an SDK server module (a local class of that name does not);
  `registerTool`/`tool` callbacks on a
  low-level `Server` receiver link to their execution bodies like `McpServer`
  ones. The lexical Go, Java, .NET and Rust idioms carry `mcp-server` only
  when the SDK is imported or declared somewhere in the project; otherwise the
  capability is withheld (listed under `metadata.potential_capabilities`) and
  the evidence stays capped `uncorroborated-lexical`.
- The project finding of an implemented server is titled `MCP server in
  <dir>: ...` (finding identity is unchanged; the title is prose) and carries
  `metadata.mcp_server` with `constructions` (`file`, `line`, `construct`,
  `language`, `bound`; at most 50, `constructions_limited` disclosed),
  `languages` and `transports` (`stdio`, `http`). Constructions in test paths
  are left out unless `include_tests` is set. An implemented server with no
  recognized tool names now suppresses vendor-neutral heuristics other than
  execution sinks, as a server with recognized tools already did. MCP client
  configurations keep `tool-use` only.

- Model identifiers are provider evidence. Quoted literals in source files and
  notebook code cells (comments skipped where the lexer masks them) and quoted
  or bare values after a model-ish key (`model`, `model_id`, `default_model`,
  `deployment`, `llm`, `engine`, `OPENAI_MODEL=`) in YAML, JSON, TOML,
  Terraform, Bicep, dotenv, `.cfg`, `.ini` and `.properties` files are handed
  to the anchored `model` signatures when they carry a vendor stem; a route
  such as `bedrock/anthropic.claude-...` attributes both the route's provider
  and the vendor. Each match weighs at most 0.5, lists the whole id under
  `metadata.models` and is kept at most three times per signature per file
  (400 vendor-stem literals per file, with incomplete coverage beyond). A
  model id in source or a notebook anchors a project finding, tagged
  `model-ids-only` with confidence capped at 0.6 when nothing else
  establishes a technology; one in a data or configuration file is a mention
  (`data_mention`) that anchors nothing and keeps leaderboards and pricing
  tables catalogs. Markdown is never read for
  model ids; `amazon.com`, `o1ne`, `tts-config`, `command-line` and
  `gemini-python/1.8.2` match nothing. The last path segment is matched only
  under a known route prefix (`bedrock/`, `openai/`, `openrouter/`, `@cf/`, …),
  so `EleutherAI/gpt-neox-20b` is a namespace, not an OpenAI model; the
  open-ended families are held to the vendor's shape (`gpt-` followed by a
  digit or `oss-`, `o1-`/`o3-`/`o4-` by a variant or release date) and a
  segment that names tooling is rejected, so `gpt-tokenizer`, `gpt-3-encoder`,
  `gpt-4all`, `gpt-engineer`, `o1-visa`, `grok-1-formatter` and `qwen-agent`
  match nothing while `gpt-5-codex`, `gpt-oss-120b`, `o3-deep-research`,
  `grok-code-fast-1` and `qwen2.5-coder-7b-instruct` still do. Dotted
  `.properties` keys (`spring.ai.openai.chat.options.model=gpt-4o`) are read.
  A model id also corroborates the same
  vendor's code pattern (`boto3.client("bedrock-runtime")` beside a Bedrock
  route in `config/agent.yaml`).
- Uncorroborated code patterns establish nothing. A lexical code match, in any
  language, whose signature has no import, dependency, file-name, image, IaC
  or model match, import-bound call, configuration shape, manifest artifact or
  mention of weight 0.3 or more (a host such as `contoso.openai.azure.com`, a
  variable name) anywhere in the project keeps its evidence (0.6 cap, `uncorroborated-lexical`
  group) but joins neither `frameworks[]` nor `model_providers[]`, adds no
  capability or agent indicator and is listed under
  `metadata.potential_frameworks` / `metadata.potential_providers`; the title
  follows the established technologies. A Rust `pub trait ToolCallback` no
  longer titles a crate "Spring AI" (0xPlaygrounds/rig), a Rust `create_agent(`
  is not LangChain (block/goose), `AgentType.Validate(` in C# is not LangChain
  (microsoft/semantic-kernel), `handoff(` in Rust is not the OpenAI Agents SDK
  (openai/codex). A project whose only evidence is such patterns yields no
  finding and a note naming up to five files (never incomplete), so nothing
  disappears silently. `apply_matches` gained `establish: bool`. Elixir
  calls a module by its qualified name without importing it and no parser
  reads `mix.exs`, so `framework.nx-bumblebee` reads a remote call to
  Bumblebee's or Instructor's own entry points (`Bumblebee.load_model(`,
  `Instructor.chat_completion(`) as its import, not as a lexical pattern.
  Elixir source is not lexed, so only a call with its parenthesis and no `#`
  before it on the line counts: a comment or a `@moduledoc` naming
  `Bumblebee.Text` establishes nothing.
- Weak mentions establish nothing. When every match of a signature in a
  project is a host, variable name, display name, data-file model id or CI
  job image below weight 0.3 after the test-path discount, the signature is
  potential, not established: `huggingface.co` (0.15) in a comment, an OAuth
  endpoint or a gallery YAML beside an OpenAI import no longer puts
  `provider.huggingface` into `model_providers[]` (six benchmark false
  positives); `router.huggingface.co` and `api-inference.huggingface.co` (0.8)
  still do.
- Mentions in test data do not anchor. Without `include_tests`, a host,
  variable, display name, model id or CI image under a test path anchors no
  project finding (faisalman/ua-parser-js: `huggingface.co` in
  `test/data/ua/extension/crawler.json` gave a 0.075-confidence provider);
  imports, dependencies and code patterns in tests still do. Dropped projects
  are named in the same note.
- CI job images are mentions. An `image:` in `.github/workflows/`,
  `.gitlab-ci.yml`, `.circleci/`, `azure-pipelines.yml`,
  `bitbucket-pipelines.yml`, `.drone.yml`, `.woodpecker*`, `.buildkite/`,
  `.gitlab/` or a `Jenkinsfile` is recorded at 0.3 of the image weight, tagged
  `ci_image`, anchors nothing, corroborates no lexical code pattern (a workflow
  image beside an unbound Java `McpClient.sync(` does not establish MCP) and
  produces no `infra` finding (pydantic/pydantic `third-party.yml` tested the
  MCP SDK in `modelcontextprotocol/python-sdk` and was reported as
  infrastructure at 0.989); Compose and Kubernetes images keep full weight and
  their infrastructure finding.
- The OpenAI request shape (`.chat.completions.create(`) in a project that
  installs or imports the OpenAI SDK never adds `provider.openai-compatible`
  as a second provider; beside a Hugging Face `InferenceClient` import it names
  neither provider (huggingface/agents-course `scripts/translation.py`).
- Incomplete coverage is reserved for content the scan would have read. The
  remaining lockfiles (`gradle.lockfile`, `Package.resolved`,
  `Cartfile.resolved`, `deno.lock`, `pubspec.lock`, `mix.lock`, `bun.lock`,
  `*.lockb`, `flake.lock`) are never read, and `*.log`, `*.har` and `*.snap`
  join the default `oversize_skip_globs`. Change logs are not on that list: a
  name glob such as `CHANGELOG*` or `HISTORY*` also matches source files
  (`history_store.py`, `changes.ts`) a scanned repository can name freely, and
  credential detection reads change logs like any other prose, so an oversize
  `CHANGELOG.md` stays a coverage gap while `scan_secrets` is on (Mastra's eight
  `CHANGELOG.md` files over 1 MB keep a default scan at exit 3). With
  `scan_secrets: false`, two more kinds of oversize file are skipped with a
  warning and the scan stays complete: a documentation file (`.md`, `.mdc`,
  `.mdx`, `.txt` that is not a manifest, coding-agent instruction document,
  agent definition or file-name-signature match), whose body the technology
  passes never read, `CHANGELOG.md` among them, and, without `include_tests` or
  `strict_coverage`, a file under a test or fixture path (pydantic-ai: 56
  recorded cassettes), whose evidence is discounted; the latter are counted
  in `skipped_oversize_test_fixtures` and summarised in one warning per root.
  With credential detection on (the default) every read file, prose and
  fixtures included, is scanned for credentials, so an oversize README or
  cassette stays a coverage gap (exit 3): a planted key in it is never lost
  to an exit 0. Instruction documents, agent definitions, source and
  configuration over `max_file_size` keep the gap in every mode; see
  `docs/production.md`.
- .NET central package management: `Directory.Packages.props`
  (`PackageVersion`), `Directory.Build.props` and other MSBuild imports
  (`GlobalPackageReference`, `PackageReference Update=`) declare NuGet
  dependencies, so `Microsoft.Extensions.AI` and `OllamaSharp` pinned there
  (autogen, semantic-kernel) establish their technologies.
- The evaluation harness (`tools/evaluation/evaluate.py`) no longer treats the
  connector's informational notes (`evidence not reported because ...`) as an
  incomplete scan.

- `code.filesystem`: the catalog rule no longer discounts configuration that
  names four or more products. Three public repositories showed the cost:
  SWE-agent's `.devcontainer/sample_keys.cfg` (five provider keys, read as a
  catalog, so the project reported LiteLLM alone), the providers aider's
  `models.py` loads from `aider/resources/model-settings.yml`, and those a
  codex-rs crate embeds from `provider_catalog_overrides.json` with
  `include_str!`. Three shapes are configuration now, whatever they name: a
  data file under `.devcontainer/`, or under `config/`, `conf/` or `settings/`
  at the top of the scan or of its project; a data file that assigns a variable
  it names on a line of its own (`NAME=value`, `export NAME=value`,
  `NAME: value`, also in `.cfg`, `.ini`, `.conf` and `.properties` files, which
  have no parser), as a key with a scalar value at any depth, or under a
  `containerEnv` or `remoteEnv` key; and a data file that source code, a
  notebook or a shell script of the same project names in a quoted path literal
  (`open("model-settings.yml")`, `include_str!("../providers.json")`). A
  reference does not reach data under a documentation or website directory
  (`docs/`, `doc/`, `website/`, `site/`, `_data/`, `_posts/`, `_includes/`,
  `blog/`): leaderboards, galleries and pricing tables stay catalogs even when
  a script writes them, and a model identifier found in a data file counts as a
  mention like a domain or a variable name, so a table of model ids is a
  catalog while a model a manifest or IaC file selects still anchors.
  Blocklists, vendor policies and the signature packs are discounted as before,
  and a file named as a deny list (`blocklist`, `denylist`, `blacklist`) stays
  a list under `config/` or when code loads it, since a proxy keeps its deny
  list beside its configuration and loads it; one that assigns the variables it
  names or deploys a Kubernetes or ECS resource is configuration. Since a
  reference cannot exempt a deny list, a truncated reference list beside one
  leaves the scan complete. A vendor policy that names a variable as a value (`key_env: OPENAI_API_KEY`),
  keys a mapping or a list by it in any style (a YAML block or flow mapping, a
  JSON object or array, a TOML inline table) or lists it as a key with no value
  still assigns nothing. The reference exemption is by name and its
  documentation-directory list is fixed, which is the accepted cost: a quoted
  `"settings.yaml"` anywhere in code exempts every data file of that name in
  the project, and published data outside the listed directories (`public/`,
  `static/`) is configuration once a build script names it. The two new passes
  are bounded (10,000 assignment lines per data file, 2,000 quoted literals per
  loader) and run under the matcher's retrying budget, so a file of 100,000
  `X=1` lines is judged on its first 10,000 instead of marking the scan
  incomplete. `metadata.catalog_mentions`, the scan note and finding identity
  are unchanged.

### CycloneDX

- A finding with the `mcp-server` capability (other than an MCP
  configuration) publishes the server it implements as a `services[]` entry in
  group `mcp-server` (`shadowscan:mcp-server:<digest>`), with
  `shadowscan:mcp:implementation=source`, `languages`, `transport` when the
  code names exactly one, `tools` and `files` (capped at 20 and 10, the caps
  disclosed as `tools-omitted`/`files-omitted` and in the `incomplete`
  composition); the project stays an `application` component that depends on
  it. The benchmark adapter maps the capability to the `mcp:server` fact.

### Real-world benchmark follow-ups: fail-closed corrections

Review of the changes above found inputs that made a scan of real AI use look
complete and empty. Each has a regression test; finding IDs are unchanged.

- Fixed: stray NUL bytes read as text were left in the analyzed text, so
  `api.open<NUL>ai.com` or `OPENAI_<NUL>API_KEY` in a shell script, which bash
  runs as `api.openai.com` and `OPENAI_API_KEY`, matched nothing. The code
  connector now matches names in the text without its NUL bytes (line numbers
  are unchanged). Node and PHP keep NUL bytes, and removing one can join
  `/<NUL>*` into a comment opener or `?<NUL>>` into a PHP closing tag that
  masks the code after it, so a source file with NUL bytes is lexed both with
  and without them: only what both readings mask stays masked, and the file's
  lexing is incomplete unless both readings agree.
- Fixed: the JSX walk read valid JavaScript as elements and masked the code
  between them: `yield <a> 1` and `await <a> 1` in a script (where both words
  are names), `of <a> 1` after an operand, a keyword cut out of a longer name
  (`a<ZWNJ>typeof <a> 1`, likewise at a combining mark or a `\u{...}` escape)
  and the second `<` of a left shift (`mask<<shift>limit`; see "Lexical
  coverage" above). Before, the code connector lexed `.js`, `.mjs` and `.cjs`
  files as JSX from the start; they are now read as plain JavaScript first
  (see "Real-world benchmark follow-up fixes" above). In their JSX reading, a
  `<` after a word opens an element only after a reserved word that cannot be
  a name (`return`, `typeof`, `case` and the like) that is not cut out of a
  longer name; after `yield`, `await`, `of` or any other word the reading is
  ambiguous and is not used.
- Fixed: a `.ts` or `.tsx` file that started with `<TS>` or `<tileset` was
  masked whole as a Qt translation or Tiled tileset, although `<TS>expr` is a
  type assertion and `<TS></TS>` a JSX element. Only a file that opens with an
  XML declaration or a document type declaration, has its root's closing tag
  at the end, and parses as well-formed XML with that root (a document that
  declares entities is not parsed) is treated as one.
- Fixed: `#[` in PHP was always read as an attribute, so a PHP 7 comment such
  as `#[TODO] don't call this` opened a string that masked the code after it.
  A PHP file with `#[` is now lexed both as PHP 8 and as PHP before 8 reads
  it, and only what both readings mask stays masked. When only the PHP 7
  reading leaves a string open at the end of the file (a multi-line attribute
  string), PHP 7 cannot run the file and the PHP 8 reading is used alone;
  when only the PHP 8 reading does, the lexing stays incomplete, because a
  PHP 8 construct the lexer misreads can cause it.
- Fixed: a PHP here-document closed only at a marker alone on its line (with
  an optional `;`, `,` or `)`). Since PHP 7.3 code may follow the marker
  (`EOT)]`), so such a file stayed open to its end, which also made the PHP 8
  reading of `#[Attr(<<<EOT` look invalid and let the PHP 7 reading mask code.
  The marker now closes wherever no name character follows it, and the rest
  of its line is lexed as code.
- Changed: the `mcp.<vendor>.<tld>` host form of `protocol.mcp` matches
  country-code domains again (except two-letter codes that are common file
  extensions or property names, such as `py`, `md`, `rs`, `pl`, `ps`, `id` and
  `in`) and more generic ones (`biz`, `digital`, `club` and others, but not
  words that name properties or methods such as `info`, `page` or `live`), so
  `mcp.example.de` is an MCP endpoint again. A `protocol.mcp` host candidate
  followed by a call, an index, an underscore or an assignment
  (`MCP.LOGGER.info("x")`, `mcp.client.is_connected()`, `mcp.session.page = 2`)
  is code, not a host, and in a source file a candidate counts only where a
  string or a URL starts with it (`"mcp.vendor.de"`, `https://mcp.vendor.de`,
  or followed by an `/mcp` or `/sse` path), so `y = mcp.result.no` is not one.

## 0.1.2 — 2026-10-08

### Release tag lookup correction

- Fix the production publication gate to query GitHub with the fully qualified
  `refs/tags/v<version>` ref. The previous `tags/v<version>` lookup returned
  HTTP 422 for the existing annotated tag during release preflight. The gate still
  requires the resolved commit to equal the reviewed workflow commit.
- Execute the gate in regression tests against the accepted API ref format,
  including rejection of the old lookup and of missing or mismatched tags.
- Prepare a new version because `v0.1.1` is already immutable. Its TestPyPI
  upload and fresh installation passed; production preflight stopped before
  any PyPI dispatch or upload. Preserve the tag and the rehearsal evidence.

## 0.1.1 — 2026-10-08

### October 8 release tags without a personal signing key

- Release policy now permits unsigned annotated tags on the exact reviewed
  commit; personal SSH or GPG tag signatures are optional. The default tagging
  command disables automatic signing for that invocation.
- Publishing continues through the existing protected GitHub Actions workflow
  and PyPI trusted publisher, with GitHub provenance, SBOM and PyPI publish
  attestations. Independent review, CI and CodeQL, immutable tag protections,
  digest checks and environment approval remain required.

### October 7 release merge-rule check with an administrator readback

- Fixed: the release-evidence workflow could never pass its merge-rule step.
  GitHub returns a ruleset's `bypass_actors` only to a caller with write
  access to it, the build job reads with its read-only token, and the verifier
  rightly refuses a response without the field. A dispatch of the governance
  audit, which reads the same way, confirmed the omission. The workflow had
  never been run, so nothing had shown the failure.
- The workflow takes a required `ruleset_readback` input: an administrator's
  `gh api repos/aisecnomad/Project-Nexus/rulesets/23913372` output.
  `python -m tools.release.rules verify --live` accepts it only when it equals
  the job's own read in every field that read returned, `updated_at`
  included, so a stale or edited readback fails and the readback can supply
  only the withheld `bypass_actors`. The full policy check then runs on the
  readback. The build job still holds no administrator credential.
- The merge-rule receipt records `bypass_actors_source` and
  `observed_updated_at`; `verify_receipt` and the evidence manifest validate
  both. Receipts without them still verify.
- Field names from a mismatching readback appear in the error only when they
  are plain lowercase names, so a crafted key cannot inject log lines or
  workflow commands.

### October 7 PyPI distribution and publishing

- The distribution is renamed from `project-nexus-shadowscan` to
  `NexusShadowScan`, so `pip install NexusShadowScan` installs the scanner once
  a release is published. The wheel is
  `nexusshadowscan-<version>-py3-none-any.whl` and the container inventory
  check looks for `pkg:pypi/nexusshadowscan`. The command, imports, connector
  entry-point group and report schemas keep the `shadowscan` name.
- The release-evidence workflow gains a `publish` input (`none` by default,
  `testpypi` or `pypi`). A `publication-gate` job requires exactly one wheel
  with matching digests, a public release version and, for `pypi`, the tag
  `v<version>` on the reviewed commit. A `publish` job, whose only permission
  is `id-token: write`, waits for approval in the protected environment of the
  same name, checks out nothing, and uploads that attested wheel with the
  SHA-pinned `pypa/gh-action-pypi-publish` v1.14.2 through trusted publishing,
  which adds PEP 740 attestations. No package-index token is stored.
- The repository policy tests allow that one upload step and no other. They
  pin each gate, and mutation tests show that removing a gate, uploading from
  another job, rebuilding in the publish job or adding a write scope fails.
- Fixed: the workflow's exactly-one-wheel checks were written
  `[ "${#wheels[@]}" -eq 1 ] && [ -f "${wheels[0]}" ]`. `set -e` ignores a
  failure of the first command of an `&&` list, so an artifact with two
  wheels passed. They now fail in an explicit `if`, and tests run the
  committed scripts with one and two wheels.
- README links are absolute repository URLs, because README is also the PyPI
  project description, where relative links resolve against pypi.org. A test
  keeps README free of relative links, and a new test resolves every absolute
  `blob/main` and `tree/main` link in the Markdown files, anchors included,
  against the checkout.
- Fixed a missing space in the README deployment install
  (`pip wheel. --no-deps`), which made the command fail.
- New maintainer runbook, `docs/operations/publishing.md`, for the one-time
  PyPI and environment setup and the per-release steps.

### Incomplete A2A cards, OpenClaw state files and short sk- keys

- An A2A card that fails validation but still names its agent and declares an
  endpoint, skills or capabilities gets its own `protocol.a2a` framework-usage
  finding ("Incomplete A2A agent card: …", tagged `incomplete-agent-card`,
  errors in `metadata.card_errors`) instead of disappearing from the report.
  It never becomes or joins an agent finding, so a valid card beside it keeps
  its single agent finding, and its validation errors still make the scan
  incomplete. An empty or unrelated object under a card file name is still
  not reported. Once the card is complete, the same finding ID reports the
  agent.
- `config.json` in an OpenClaw state directory (`.openclaw/`, `.clawdbot/`,
  `.moltbot/`) and `.moltbot/moltbot.json` belong to `coding-agent.openclaw`,
  so a state directory is one agent configuration finding. #155 placed the
  new paths under `platform.openclaw`; that signature covers configuration
  formats outside a state directory, which already belongs to the
  coding-agent signature alone.
- `heuristic.unattributed-api-key` has a second signal for `sk-` keys of 20 to
  31 characters after the prefix (LiteLLM proxy virtual keys have 22). A value
  is kept when it mixes letters and digits, has at most two separators, passes
  the generic credential's diversity and entropy test and is not already
  covered by a kept generic assigned-credential match, so an `*_API_KEY=`
  assignment keeps its finding and weight. OpenSSH security-key algorithm
  names (`sk-ssh-…`, `sk-ecdsa-…`) never match. Such keys were missed in SDK
  calls, JSON and YAML configuration and `Authorization` headers. A separate
  signal keeps rejected look-alikes from using the longer keys' match budget.
- `examples/inventory/sanctioned.yaml` shows the bare-list inventory form. The
  comment #155 gave it said the `agents:` mapping is not accepted; it is, and a
  test now loads both examples and checks that a name alone only suggests a
  match.
- The default evaluation corpus gains OpenClaw and Moltbot state-file cases, a
  short-key positive (which fails on the previous signatures) and a look-alike
  negative: SSH algorithm names, a spinner class and a ticket branch.
- A redaction test's parameter ID embedded a per-process HMAC, so pytest-xdist
  workers collected different test IDs and `make test-parallel` stopped at
  collection. The case now has a fixed ID.

### README command checks

- A README edit on `main` dropped the space in two copy-paste commands
  (`python -m pip wheel. …` and `shadowscan code. …`, both of which fail),
  misquoted the package classifier as `Development Status:: 3 - Alpha`, and
  indented the `Project status` heading so it rendered inside the preceding
  bullet. The PyPI publishing change fixed the `pip wheel` command and the
  classifier; the rest is fixed here, and the edit's wording and section
  order are kept.
- A repository test now checks that every `shadowscan` and `pip` command in a
  shell block of a Markdown page names a real subcommand, and that the
  classifier the README quotes is one `pyproject.toml` declares. Both checks
  fail on the edit as committed.
- `CITATION.cff`'s abstract named six of the nine discovery surfaces; it now
  names all nine, as the README does.

### Surface descriptions and pre-commit hooks

- The package summary in `pyproject.toml`, `shadowscan --help`, the HTML
  report's subtitle and the connector base docstring also named six of the
  nine surfaces, and the README said only identity, gateway, low-code, SaaS
  and cloud findings group repeated matches of one signal; every surface
  except code does. A repository test now checks that each one-line scope
  description names every `Surface`.
- `pre-commit run --all-files` failed on `main`. The benchmark report writer
  ended `REPORT.md` with a blank line, which `end-of-file-fixer` removes, and
  the mypy hook, which runs with `--ignore-missing-imports`, reported the Open
  Shadow AI helper's `import-not-found` ignores as unused. The writer now ends
  the report with one newline, `REPORT.md` is regenerated (the only change is
  that line), and the helper's ignores also allow `unused-ignore`, so CI's
  mypy and the hook both pass. The benchmark README's regeneration command
  wrote `REPORT.md` to the working directory; it names the committed path.

### October 6 merge-policy audit diagnostics

- The first scheduled merge-policy audit failed with "ruleset response does
  not match the expected repository and ruleset". A response missing a managed
  field produced the same message as a wrong repository or ruleset, and GitHub
  returns `bypass_actors` only to a caller with write access to the ruleset,
  which the read-only workflow token lacks. The verifier now names omitted
  fields separately. The job still fails until an administrator applies the
  reviewed payloads and a complete readback matches them; a complete readback
  taken on 2026-10-06 reports `readback differs from reviewed payload:
  bypass_actors, rules`.
- `docs/production.md` and `docs/operations/merge-policy.md` record that
  readback: both rulesets active again, with the gaps observed on 2026-10-03.

### October 6 head-to-head benchmark follow-ups

- The Goose signature matches the user configuration Goose writes on first
  run (`~/.config/goose/config.yaml`, and
  `%APPDATA%\Block\goose\config\config.yaml` on Windows). The benchmark
  missed all six Goose homes because only `.goose/`, `.goosehints` and
  `goose.yaml` were recognized.
- The Cline signature matches the installed extension directory
  (`saoudrizwan.claude-dev-*` under VS Code, VS Code Server, Cursor or
  Windsurf), so an install without `cline_mcp_settings.json` is found.
- `review_corpus.json` gains both cases and two look-alike negatives; the
  positives fail on the previous signatures.
- MCP configuration findings report static server risks: a package or image
  fetched without an exact version or digest (`mcp-unpinned-package`), a
  filesystem server rooted at `/` or a home directory
  (`mcp-broad-filesystem`), a shell-wrapped launch (`mcp-shell-command`),
  plaintext remote transport and auto-approved tools. The checks read the
  sanitized server record only; nothing is started or fetched.
- Coding-agent configuration findings report posture from the agent's own
  settings: Claude Code `bypassPermissions` and unrestricted `Bash` allow
  rules, Codex `approval_policy = "never"` and `danger-full-access`, Goose
  `GOOSE_MODE: auto`, and an OpenClaw gateway exposed beyond loopback or
  without an auth token. Only enumerated setting values are reported.
- A `coding-agent.openclaw` signature recognizes OpenClaw state directories.
- New default risk weights for these tags; see `docs/concepts/risk.md` and the
  October 6 migration note in `docs/production.md`.
- New `endpoint.inventory` connector on the `endpoint` surface. It reads a
  fixed list of documented user-scope locations below home directories: AI client
  and coding-agent configurations with their MCP servers, server risks and
  posture; AI editor and browser extensions; local model stores; and, with
  `shell_history: true`, AI command-line tool names and counts. Offline it
  replays exported records or osquery `vscode_extensions`,
  `chrome_extensions` and `firefox_addons` results. Symbolic links are never
  followed, and links, unreadable locations, oversized files or an exhausted
  `max_entries` budget make the scan incomplete.
- New finding kinds `ai-app`, `local-model`, `network-contact` and
  `runtime-process`, and surfaces `network` and `runtime`.
  `KIND_BASE` gives the first three 5 and `runtime-process` 10.
- MCP risk and posture recording moved to shared helpers
  (`record_server_risks`, `record_posture`) used by the code and endpoint
  connectors.
- The offline demo runs `endpoint.inventory`.
- `gateway.logs` classifies agentic callers from request metadata when logs
  carry no request bodies: hosted agent runtime operations
  (`agent-runtime-api`), MCP endpoints (`mcp-client`) and agent-loop cadence
  from programmatic callers (`agent-loop`). The indicators live in
  `shadowscan/connectors/agent_behavior.py` for reuse by other log sources.
- Fixed: every gateway caller to `*.openai.com` or `*.anthropic.com`, and any
  caller named after those vendors, was titled "Agentic caller" because the
  ChatGPT and Claude SaaS app signatures carry an agent indicator for OAuth
  grants. Gateway callers no longer take agent indicators from
  `identity-app` signatures; the golden replays record the corrected titles.
- Fixed: a user or key alias that matched a product name (a person called
  Jules) and browsing `chatgpt.com` (also listed by the ChatGPT plugin
  protocol signature) made gateway callers agentic. Name matches are hints,
  and a host counts only through the service it belongs to. Found by the
  post-change benchmark run; regression tests added.
- `framework.autogen` gains a user-agent signal (`autogen/…`, `ag2/…`).
- New `network.logs` connector and `network` surface. It reads Zeek
  `dns.log`, `ssl.log` and `conn.log` (TSV or JSON), Route 53 Resolver query
  logs, VPC Flow Logs and generic DNS/SNI exports, and reports one
  `network-contact` finding per client address and AI service. Host names
  match exactly or by a declared wildcard, and only AI host names are kept.
  Flows are attributed by Zeek `uid` to a TLS server name or through DNS
  answers in the same input; addresses shared with another service's host
  attribute nothing. The offline demo runs it.
- New `runtime.processes` connector and `runtime` surface: coding-agent CLIs,
  AI desktop apps, MCP servers, local model servers and agent dev servers seen
  running, from osquery `processes`, Defender `DeviceProcessEvents`,
  CrowdStrike process events, generic exports or `/proc` on Linux. Command
  lines never enter a finding, and the connector's records are excluded from
  `--dump-records` because command lines can carry credentials. The offline
  demo runs it.
- Lifecycle corroboration: the engine links endpoint findings (configured,
  installed) to running-process findings for the same tool on the same
  device, recording `metadata.lifecycle` and the tag `observed-running` with
  zero-weight evidence. MCP configurations link only through the same server
  package. Scores do not change.
- The CycloneDX 1.6 AI-BOM output (`--format cyclonedx`) models agents and
  other findings as application components, model artifacts and stores as
  machine-learning-model components, MCP and model-server inventories as
  services, and frameworks, models, providers and MCP servers as shared
  entries with dependencies.
  Credential findings are excluded, and `compositions` declares the inventory
  `incomplete` whenever the scan was. See `docs/operations/ai-bom.md`.
- Opt-in LLM triage (`options.llm_triage`, off by default): a redacted summary
  of the highest-risk findings goes to a model the operator names, through the
  scanner's HTTPS client, and the reply is stored as advisory
  `metadata.llm_triage`. Resource ids, owners, accounts, locations and
  snippets are not sent as fields, and their values are withheld from titles
  and evidence text; keys come only from an environment variable; replies
  never change scores or completeness. See `docs/operations/llm-triage.md`.
- `endpoint.inventory` coexists with the `endpoint.*` offline inventories:
  it reads local locations or osquery exports, they read collector exports.
  Their findings carry no device name, so lifecycle links do not apply to
  them.
- The CycloneDX output replaces the earlier candidate's exporter: findings
  other than models, MCP and Ollama inventories are `application` components
  instead of `machine-learning-model` components, risk is published as
  `shadowscan:heuristic-risk` (the earlier `shadowscan:risk_level` lookup never
  matched), per-tag `shadowscan:tag:<tag>` properties are one
  `shadowscan:tags` list, and credential findings are excluded. Regenerate
  BOMs and update their consumers.

#### Fixes from a review of the merged branch

- CycloneDX: MCP server risks were never emitted (the reporter expected
  objects, the records hold ids); `endpoint.ollama` model findings are
  `machine-learning-model` components again; each entry is sanitized on its
  own, so scans of about a thousand findings or more render; entries capped
  at 50 MCP servers or 20 models are recorded as `incomplete`; same-named
  servers and empty or repeated finding ids get distinct refs; providers carry
  no `trustZone`; names and vendors come from the scan's signature index,
  custom packs included.
- `endpoint.inventory`: a symbolically linked directory on the way to a
  location (Linux reports it as "not a directory") was treated as absent; it
  is now a gap. Unparseable agent settings, whose posture is therefore
  unknown, and a shell history longer than the read limit are gaps too.
  Malformed server, posture or model entries in replayed records are dropped
  with a warning (incomplete) instead of failing the connector or, through
  the lifecycle pass, the whole scan. Project servers in `~/.claude.json` that
  reuse a user-scope name are kept (`name#2`), MCP risk evidence cites the
  file that holds the servers, and the lock links a running Chromium browser
  keeps in its user-data directory no longer make every scan incomplete.
- `runtime.processes`: an export row whose pid is a non-ASCII digit no longer
  fails the export (64-bit ids such as CrowdStrike's `TargetProcessId` are
  kept). A live scan of a container's own `/proc`, identified by the PID
  namespace's inode, is marked incomplete because it cannot see the host's
  processes; so is one under a `hidepid` setting that hides processes from
  the scanning account. `subset=pid`, and root under the default `hidepid`
  group, hide nothing and stay complete.
- Lifecycle links also match by tool id, so Claude Desktop, Kiro and
  LM Studio configurations, which have no signature, link to their running
  processes.
- LLM triage withholds owner, account, resource, device, home, file and
  network client values from the title and evidence text it sends (one- and
  two-character values as whole words), while product names stay readable. A
  malformed reply is `unparseable`; an API key that is not a valid header
  value, or any other triage failure, is a warning on the triage entry that
  never echoes the key, and the scan keeps its report.
- MCP servers reached through `ws://`, an upper-case `HTTP://` scheme, or a
  URL that MCP clients' parsers read as plaintext despite embedded tabs,
  newlines or leading control characters gain the `mcp-plain-http` factor
  (+10): the factor parses the scheme as the `mcp-insecure-transport` tag
  does, so every tagged server is scored.
- A coding agent's own configuration file belongs to that agent's signature
  alone: `main`'s `platform.openclaw` no longer adds a second framework-usage
  finding for files in an OpenClaw state directory.

### Offline runtime inventory connectors

- Added the `endpoint` surface, offline analyzers for MCP tool inventories,
  OTLP GenAI spans, host/runtime records, local model metadata, and eBPF events,
  plus offline Kubernetes/OpenShift workload analysis.
- Added risk tags and OWASP/MITRE control references for selected runtime
  indicators, and a CycloneDX 1.6 AI-BOM output format. New runtime tag
  weights can change risk scores for findings that carry those tags.
- These offline inventories (`endpoint.host`, `endpoint.mcp`, `endpoint.ollama`,
  `endpoint.models`, `endpoint.ebpf`, `gateway.otel`, Kubernetes/OpenShift)
  remain offline-only; live MCP, Ollama and Kubernetes collection is
  unsupported. (`endpoint.inventory` and `runtime.processes`, above, read local
  state when no `input` is set.)
- Model metadata is supplied by an offline exporter; ShadowScan does not parse
  GGUF or safetensors files. MCP tool fingerprints have no rug-pull baseline, and
  findings from these inventories carry no device name, so lifecycle links do
  not apply to them.

### Security-review follow-ups

- `SHADOWSCAN_IDENTITY_KEY` accepts explicit `hex:<value>` and
  `base64:<value>` encodings. Bare values that are valid under both encodings
  now fail with a credential-free `SetupError` asking for a prefix. This
  intentionally breaks ambiguous bare keys, including ordinary 64-character
  hex strings; prefix them with `hex:`. The README now leads with the reviewed
  revision and hash-locked deployment install, and labels floating VCS installs
  as development-only and non-reproducible.
- Inventory approval warnings now include additional resource-shape probes and
  flag near-universal patterns as advisory sampled evidence. Only star-only
  globs are described as universal. The classifier retains the parsed pattern
  semantics, including literal whitespace and question-mark minimum lengths.
  Scope constraints, including observation discriminators, still limit approval.
  The Dockerfile documents the
  live-apk reproducibility trade-off and requires matching base-image and Python
  package pins across stages; a repository consistency test enforces the digest
  and pin synchronization.

### October 3 live merge-policy drift audit

- The weekly dependency-audit workflow now independently checks both live main
  rulesets against the reviewed update payloads using read-only GitHub API
  requests. Disabled, weakened, malformed or unavailable policy evidence fails
  the job. The audit does not apply settings or establish independent human
  review; an administrator must apply and read back the documented updates.
  Regression tests run the workflow's exact script against valid and invalid
  synthetic API snapshots.

### October 3 keyed credential evidence and invisible-character publication

- Code and cloud credential evidence now uses domain-separated HMAC-SHA-256
  pseudonyms rather than public SHA-256 digests of credentials. Engine workers
  share one random private key per scan. The existing `SHADOWSCAN_IDENTITY_KEY`
  opt-in supplies a stable key; it never enters configuration, reports or caches.
  Credential-bearing static results are rescanned without that stable key;
  stable-key rotation invalidates cached pseudonyms and collection comparability.
  Cache format 4 requires a fresh scan of previous entries. Resource-based
  finding IDs and existing private gateway exact-binding mappings are preserved.
  Regenerate older reports and comparison baselines; their public credential
  digests remain susceptible to candidate guessing. See the deployment guide.
- Saved HTML, CSV and Markdown now expose zero-width characters, byte-order
  marks, Unicode tag characters and lone surrogates consistently with terminal
  tables. Printable source characters and intentional format whitespace remain.

### October 3 source capability attribution

- Follow-up attribution checks reject discarded callbacks passed to unknown
  JavaScript factories, shadowed helpers and unrelated MCP member receivers.
  Supported import-bound tool factories retain async execute callbacks. Python
  tool regions omit statements after guaranteed exits and deferred lambdas in
  compound callees while retaining directly invoked lambdas. Regression cases
  cover positive registrations and contextual-only counterexamples.
- Unregistered tools and unrelated execution helpers no longer grant a
  project's agent `tool-use` or `code-exec`, or raise its confidence. Their
  evidence remains visible with zero weight and a contextual attribution;
  unproven features remain in `potential_capabilities`. Narrow local Python
  registrations, supported tool collections, direct unshadowed helper calls,
  and verified provider dispatch retain connected execution evidence. Tool
  registration does not establish runtime execution.
- JavaScript/TypeScript binding excludes provably constant-dead literal
  `if`/`else` and `while` branches while retaining executed alternatives and
  conservative hoisted-name shadow checks. Dynamic conditions and unsupported
  expression shapes remain possible source evidence. This is bounded static
  recognition, not whole-program reachability analysis.

### October 3 review remediation

- HTTP transport and streamed-body failures now preserve only controlled
  exception categories and the HTTPS origin, discarding opaque URL values
  and credential-bearing request/response objects and exception chains.
  Prior findings remain available and coverage remains incomplete.
- Strands constructor tool collections recognize non-empty literal tool
  names and paths. Other SDK collections and agent participants still require
  supported object evidence; strings do not establish an agent handoff.
- Shared HTTP diagnostics now retain only an HTTPS origin and status. URL
  paths, userinfo, queries and fragments are omitted, and malformed URL
  parsing produces fixed messages. Regression tests exercise the CLI logger,
  request errors, redirects and pagination; transport policy remains enforced.
- Configured capability analysis now covers supported ADK, Strands, AutoGen,
  LlamaIndex and Semantic Kernel constructors. Empty or unresolved options
  retain SDK features as potential capabilities instead of adding them to risk.
  Explicit participant collections and enabled execution options are interpreted
  using the SDK contract; weak planning vocabulary alone no longer establishes
  autonomous operation. Positive and negative cases cover the new behavior.
- Git submodule inventory can report controlled failure categories and numeric
  OS errors without publishing subprocess diagnostics or paths. Unknown
  coverage remains incomplete. Fast-exit metadata subprocess regressions and
  diagnostic assertions support investigation of the observed macOS failure;
  they do not establish its root cause or claim that it is fixed.
- Ruleset preparation refuses conflicting check-provider bindings. The merge
  runbook prepares both rulesets from fresh administrator snapshots, preserves
  stronger settings and verifies exact readback. Prepared policy files do not
  activate GitHub enforcement. Independent review and live tenant acceptance
  remain external prerequisites.

### October 3 incremental enumeration-budget review

- Incremental fingerprints now include the number of entries inspected by
  coverage probes in default-excluded directories. Moving a vendored file
  deeper can exceed `max_entries` without changing the probe's non-empty
  result; previously that change could reuse a cached complete scan. The
  changed fingerprint forces a full scan, which reports incomplete coverage
  when the entry limit is exhausted. Probes also share the fingerprint's
  cancellation, deadline and entry budgets. Regression tests cover cache
  invalidation and fingerprint-budget accounting.
- The testing guide now documents exact synthetic-secret approvals rather
  than the removed directory exclusions and placeholder-word exemptions.

### October 3 merge integration hygiene

- DCO checks every commit in the pull-request range, including merge commits.
  A merge can introduce conflict resolutions or other content beyond its
  signed-off parents; skipping it let that content pass without the merge
  author's certification. Regression tests exercise signed and unsigned
  two-parent commits with a file authored only in the merge.

### Bounded source-directory enumeration

- `code.filesystem` now limits directory enumeration before retaining entry
  names, including directories, excluded files and coverage probes. The new
  `max_entries` option defaults to 1,000,000 and is independent of `max_files`.
  GitHub and GitLab forward it to each checkout. Enumeration also checks
  cancellation and connector deadlines when there are no analyzable files.
  Entry and file limits retain findings already assessed and mark the scan incomplete
  (exit 3). Regression tests cover the limit, ignored and directory-only
  inputs, cancellation, deadlines and findings retained after a partial walk.

### October 3 incremental metadata confinement

- Incremental scans with `use_git: true` apply the bounded Git metadata
  preflight before fingerprinting, including when considering a cache hit.
  Unsafe metadata disables reuse and the full scan reports incomplete coverage
  while retaining source findings. This matches the existing history-enrichment
  policy; the preflight shares the connector deadline.

### October 3 secret-gate hygiene review

- Scan tests, signature packs and evaluation corpora for hardcoded credentials
  instead of exempting their directories. Synthetic fixtures and documentation
  placeholders require exact path, credential-family and SHA-256 approvals in
  `tools/secret_allowlist.json`; placeholder words no longer suppress findings.
  Private-key marker approvals also bind the whole fixture's bytes. Malformed,
  duplicate, stale or missing approvals fail the gate, including partial hooks.

### October 2 follow-ups to #135

- `test-macos (3.11)` failed `main` after #135 merged. The confinement test for
  a symlinked `.git/objects` deletes that directory right after its fixture
  commits. Since Git 2.47 a commit starts `git maintenance run --auto` in the
  background, and the detached process removed its `maintenance.lock` while
  `shutil.rmtree` was deleting the directory; Python 3.11 reports the vanished
  file as an error. With Git 2.55 and Python 3.11 the test failed in 4 of 150
  repeated runs. Every test helper that commits now passes
  `-c maintenance.auto=false`, and the repeated runs pass 150 of 150. The
  scanner's own Git commands (a clone and read-only metadata reads) never start
  maintenance.
- Five tests that read a repository snapshot need Git 2.45 or newer, like the
  other history tests, but were not marked `requires_git_2_45`. On an older
  Git, such as the 2.43 in Ubuntu 24.04, they failed instead of being skipped.
  They now carry the marker.
- The CI lock takes Dependabot's development-tool updates from #136
  (platformdirs 4.12.2, virtualenv 21.14.0), regenerated with the documented
  command and uv 0.12.18. The docs lock moves platformdirs with it, regenerated
  with its documented pip-compile command, because the combined install needs
  one version of each shared package. Dependabot changes only the constraints
  file, so its pull request failed the lock consistency tests.

### October 2 integration of #134 and repository hygiene review

Pull request #134 landed through an integration pull request as one signed-off
commit, rebuilt on the current `main`: its branch predated #123, #132 and #133
and conflicted with the SARIF message escaping from #123. The
other changes come from an AI-assisted review of CI, documentation, code and
repository layout. Each defect was reproduced before it was fixed and has a
regression test or check; none had a second-person review. Migration notes are
in `docs/production.md` under "Candidate change history".

#### Heuristic severity in SARIF (#134)

- SARIF output no longer presents the heuristic risk level as a CVSS-like
  security severity. Rules carry neither `security-severity` nor the `security`
  tag. The level is recorded as the rule property `shadowscan/heuristic-risk`,
  next to `shadowscan/score-basis: heuristic-not-cvss`, and as the result
  property `risk_level`. Discovery hits are SARIF `warning` (critical, high,
  medium) or `note` (low, info), never `error`, which stays reserved for
  connector failures in the tool execution notifications. Each rule's help text
  and `helpUri` link to the new
  [severity guide](https://github.com/aisecnomad/Project-Nexus/blob/main/docs/severity.md),
  which states what the score is and what enforcement would require. Rule IDs
  and `partialFingerprints` are unchanged.

#### CI on `main`

- The SIGINT clone test failed `main` after #133 merged: its child scanner
  aborted (SIGABRT) instead of exiting after the interrupt. The child waited for
  its clone worker with `Thread.join()`. On CPython 3.11 and 3.12 a
  KeyboardInterrupt that interrupts `join()` marks the still-running thread as
  stopped, so interpreter shutdown did not wait for it, and the process aborts
  when that thread holds the stderr lock at exit. The child now waits with
  `concurrent.futures.wait` on a pool thread, as `Engine.run` does, and the test
  requires the clone worker to return before the process exits. The scanner's
  scan path already waited this way and is unaffected.

#### Scanner fixes

- JavaScript import, `require` and bound-call line numbers, and IaC model ids,
  are numbered incrementally (`shadowscan.utils.text.line_counter`). Each match
  counted the file's newlines from its start, which was charged against the
  match deadline: a scanned file with thousands of imports made its analysis
  incomplete on purpose. Line numbers are unchanged.
- `code.filesystem` rejects a boolean, fractional or non-numeric
  `max_file_size` or `max_files`, and a boolean, non-finite or out-of-range
  `scan_timeout`, as configuration errors with a fixed message. `max_file_size:
  true` was a 1-byte limit that skipped every file, and `max_files: 1.9` became
  1. Numbers and numeric text are accepted as before.
- The wheel ships `.yml` signature packs as well as `.yaml`; the loader reads
  both.

#### Container and CI tooling

- The worker image no longer carries the build backend: the wheel is built in
  a separate environment that is not copied, so `setuptools`, `wheel` and
  `packaging` stay out of `/opt/venv` (the Dockerfile already said so). The CI
  smoke test asserts it, and the Dockerfile policy test covers `pip wheel` as
  well as `pip install`.
- Both image stages pin Wolfi's `python-3.12` to `3.12.15-r0` for now.
  `3.12.15-r1`, published on 2026-10-02, has no SHA-224 or SHA3-224, and pip
  derives its cache keys from SHA-224, so every `pip install` in the build
  failed, on `main` as well. Drop the pin once a newer revision provides
  `hashlib.sha224`; the policy test requires both stages to stay on one
  interpreter revision.
- The consumer workflow example runs `python -m` from the runner's temporary
  directory, never from the scanned checkout, where a `pip/__main__.py` or
  `shadowscan/` package in a pull request would run in place of the installed
  tools. Its `security-events: write` permission moved to the job.
- Dependabot updates the example's action pins with the workflows' in one
  grouped pull request, and groups the remaining pip constraint updates; a
  bump that changed only the workflows failed the pin-equality test.
- The Docs workflow also builds for `RELEASE_NOTES.md` and the docstrings the
  API pages render, and a push no longer cancels a manual publishing run.
  Scorecard grants nothing at workflow level.
- Pre-commit: `pre-commit run --all-files` passes on a clean checkout again.
  The private-key hook skips the redaction rules and tests that name synthetic
  key markers, the format hook formats Python only (as CI does), the check hook
  uses its current id `ruff-check`, and Markdown line-break spaces are kept.
- `.gitignore` anchors root build, report and site outputs, so a source file
  such as `shadowscan/reporters/report.py` is no longer ignored, and the
  digest-bound license texts are never converted by Git (`-text`).

#### Documentation

- The README demo output and inventory example match the code; a consistency
  test reruns the demo and compares the shown totals and rows. Signature counts
  are checked in the root documents the site publishes (a stale "1,001
  signals" was in the release notes).
- Ruleset enforcement is described in one dated place, `docs/production.md`;
  the other documents no longer call the disabled rules active. The exit codes
  for usage errors (`docs/scanning.md`) and for expired or over-budget
  known-gap policies (`docs/evaluation.md`) match the code.
- Smaller corrections: the dark theme's toggle label, the inventory registry's
  place in the API reference, connector page heading levels, and a dropped
  fail-closed sentence in the connector overview.

### October 2 integrity and capability corrections

- Selected source and configuration files use strict supported text decoding,
  including Python's supported PEP 263 declarations and BOM-declared
  UTF-16/UTF-32. NUL bytes no longer silently exclude source from analysis;
  malformed configuration and unsupported encodings make coverage incomplete.
- MCP registration analysis distinguishes executable registrations from
  comments and examples, accepts supported decorator options, and preserves
  independent execution-sink evidence. Analysis limits must not imply complete
  capability coverage. Empty or explicitly disabled provider tool options no
  longer establish tool-use.
- GCP IAM collection requests policy version 3 and retains conditional-binding
  evidence. Ambiguous/degraded permissions and unresolved child records in
  Auth0/ServiceNow make coverage incomplete. SaaS exports missing a usable app
  name cannot produce a complete empty scan or resolve previous findings.
- Git metadata enrichment remains opt-in and now rejects metadata indirections,
  including local `include`/`includeIf` configuration sections, and bounds
  captured output. Bounded confined config reads reject unsupported section
  syntax, encodings, continuations and multiline values before Git runs.
  Credential source sanitization handles supported
  whitespace, wrapper and record forms without treating its output as public
  data. See the security policy for remaining limits.
- Proposed ruleset update payloads and offline verification tooling prepare
  mandatory aggregate CI and non-author review enforcement. Merging these
  files does not activate GitHub settings; live readback remains required.
- The documentation toolchain lock shares the reviewed `platformdirs` pin with
  CI, restoring the documented combined installation. Shared-pin consistency
  checks prevent independently refreshed locks from making that install fail.
- These changes are supported by authored regression tests. They do not
  establish independent human review, fresh field accuracy or live tenant
  acceptance. Review changed capabilities/risk scores and collect a new baseline
  before enforcement.

### October 2 integration of the open pull requests

The open pull requests #107 and #110 to #122 landed together through #123,
which was squash-merged into one commit on `main`. On #123's branch each of
them is one commit: each commit of the stack (#107, #110 to #120) has exactly
that pull request's tree, and #121 and #122 also carry their conflict
resolutions against the stack. The redaction review fixes and this grouping
followed in a separate pull request.

The review fixes below come from an AI-assisted review of the integrated code.
Each defect was reproduced before it was fixed and has a regression test.
Neither the review nor the fixes had a second-person review, and the offline
evaluation corpora are author-written: their unchanged results say nothing
about field precision. Migration notes are in `docs/production.md` under
"Candidate change history".

#### Integration changes

- Worker image: built on Chainguard's Wolfi base (`chainguard/wolfi-base`,
  pinned by index digest in both stages) instead of `python:3.12-slim-trixie`.
  The Debian image could not pass the strict container gate: 55 unfixed HIGH
  entries in util-linux, ncurses, Perl, systemd libraries and Git's
  `libcurl3t64-gnutls`. Python 3.12, its expat and Git are now Wolfi packages
  that the image scan inventories; the official image's interpreter and its
  bundled expat 2.8.3, affected by denial-of-service and memory-safety
  advisories and used for every XML file the scanner reads, were invisible to
  the scan. pip and the build tools stay in the build stage, the scanner runs
  from `/opt/venv`, and the build removes every setuid and setgid bit and fails
  if one remains. The gate policy is unchanged.
- `tools/container/verify.py` lists each blocking finding (identifier,
  package, installed and fixed version, status) in the job log and in
  `container-evidence.json`, so a failed gate explains itself without its
  artifact. The CI smoke run requires the image's expat to be 2.8.5 or newer,
  and `--os-type` states the distribution whose packages the inventory must
  contain.
- The lock audits drop pip-audit's redundant `--no-deps`; `--require-hashes`
  already pins every requirement.
- `bounded_safe_load_all` is removed, as both #112 and #121 intended; the
  stack still defined it.
- Ruff `BLE` and `RUF100`, enabled by #121, now cover the stack's code: two
  broad redaction handlers state why they are broad, a `noqa` on a handler that
  always re-raises is removed, and two tests catch the exact exception they
  expect.
- `docs/connectors/reference.md` is regenerated from the stack's connectors,
  and `docs/production.md` puts operator guidance first with every dated note,
  including the stack's, under "Candidate change history" (#122).

#### Review fixes: code connectors and signatures

- `framework.vercel-ai-sdk`: the `stopWhen:` and `tools: { … tool(` code
  patterns were quadratic on planted input. A 30 KB file with `stopWhen:`
  followed by blanks timed out signature matching, so the file's evidence was
  dropped and every scan of that repository exited 3. Both are linear now with
  the same matches, and `tests/unit/test_regex_linearity.py` times the
  signature's code patterns on such shapes.
- `code.filesystem`: the catalog rule no longer discounts deployment and CI
  configuration. A Kubernetes-style resource (`apiVersion` and `kind`, also in
  a multi-document stream), an ECS task definition, a CI pipeline
  (`.gitlab-ci.yml`, `azure-pipelines.yml`, `bitbucket-pipelines.yml`,
  `.circleci/`, `.buildkite/`, `buildspec.yml` and others), Spring
  `application*`/`bootstrap*` configuration, and any data file that assigns a
  variable it names under an `env`, `environment`, `variables` or `secrets` key
  are configuration however many products they name. A Deployment injecting
  four provider keys, or a pipeline handing them to a job, used to give no
  finding and a complete scan. When a project's only evidence is in
  catalog-like files, a scan note (a warning that does not make the scan
  incomplete) names them instead of dropping it silently.
- Submodule declarations (`.gitmodules`) are read in linear time. The
  configuration parser rescans a run of blanks before `=` from each of its
  positions, in C while holding the GIL, so one planted 1 MiB line froze the
  whole process for over an hour and neither the connector deadline nor
  `--job-deadline-seconds` could fire. A file with a run of more than 32 blanks
  is refused before parsing and reported like other unreadable declarations
  (submodule coverage unknown, scan incomplete).
- The Python import binder joins a loop's bindings over the names the loop
  assigns, as it already did for `if` branches, instead of copying and joining
  the whole enclosing scope for every `for`/`while` loop and loop `else`. A
  143 KB file of 6000 module-level names and 4000 loops (under the AST cap)
  took 15 s, seven times its matching budget; it now takes 0.5 s. The binder
  also checks the file's matching budget every 256 visited nodes, so any
  remaining expensive walk ends at that budget as partial import-bound
  analysis (scan incomplete) instead of overrunning it.
- A JavaScript or TypeScript call into a signature's library that is longer
  than 8192 characters (a Genkit flow body, an agent with long instructions)
  is analyzed from its first 8192 characters, as the Python binder does, and
  the file's other import-bound evidence is kept. It used to discard every
  import-bound call of the file, so a long Genkit flow also lost the file's
  `genkit()` constructor evidence. Options past the limit are unread, so the
  scan is still incomplete (exit 3) as before; the error names the call's
  line.
- Dockerfile comment masking reads the `escape` parser directive as BuildKit
  does: only from the leading directive lines. A `# escape=` after an ordinary
  comment, a blank line, an unknown directive or an instruction is a comment.
  It used to switch the escape character, so a trailing backtick joined the
  next `RUN pip install ...` into a shell comment and hid its dependencies
  while Docker ran it.
- Java sources are lexed after Unicode escapes are translated, as javac does
  (JLS 3.3), and the masked spans are mapped back onto the source. Only escaped
  line breaks in `//` comments were handled: `/* ... \u002a/` (or `*\u002f`)
  closes a block comment and `\u0022` closes a string, so code after them, such
  as an import, used to stay masked. An escape that spells a printable ASCII
  character in code (`\u0069mport`) hides that code from the matchers, which
  read the source as written: such a file's lexical analysis is reported as
  incomplete.
- When the Python or JavaScript import binder does not run (the source does
  not parse, or a binder budget is exhausted), the file's bundled framework
  patterns are kept as lexical evidence that counts only with an import or
  dependency of the same library, as for a language without a binder. They
  used to be dropped although the warning said "lexical evidence retained", so
  one PEP 695 line on Python 3.11 turned an agent into "LLM usage". A
  notebook's IPython magic (`%pip`, `%%time`) and shell (`!pip`) lines are
  read as inert expressions before parsing, as IPython rewrites them, so a
  notebook that installs its packages keeps the import binder.
- Notebook code cells are lexed and parsed one at a time, as Jupyter runs
  them. A cell that left a triple-quoted string open used to mask every later
  cell, so a notebook with one unfinished scratch cell gave no finding and a
  complete scan. A cell that does not parse (a `%%bash` cell, an unclosed
  bracket) is now left out of import binding alone, with a warning naming it,
  and its framework patterns count as lexical evidence; the other cells are
  bound as usual.
- `code.filesystem` reports a file it reads that is a Git LFS pointer as a
  coverage gap (scan incomplete; an error under `strict_coverage`) instead of
  analyzing the pointer text as the file. Only live clones and API snapshots
  checked for pointers, so a local checkout or a directory of offline clones
  made without git-lfs, with `agent.py` stored in LFS, gave no finding and a
  complete scan. A pointer in place of a file the scanner never reads (an
  image, a model) is not a gap; the live-clone check is unchanged.
- Python code after an unclosed bracket is no longer masked on Python 3.12
  and later. Those versions report the tokenizer error at the start of the
  last line rather than past it, so that line was masked as if it were a
  literal: a construction on it was lost while the scan said its lexical
  evidence was retained. Python 3.11 was unaffected.

#### Review fixes: gateway, low-code and cloud connectors

- `gateway.logs` access-log attribution: trailer and logfmt tokens are read
  as logfmt, so a key must start a token. An unquoted client value after the
  final quote (`args=a&host=api.openai.com host=intranet`) no longer becomes
  the host, a request line or query logged as one token can no longer set
  `model` (`GET /v1/x?model=forged`), and a line
  truncated inside the user agent is malformed instead of taking its host from
  the user agent. Combined-format fields keep `\"` escapes inside the field.
  A host token in or before a quoted trailer field, which a client can write
  when the gateway does not escape quotes, is still not trusted; when it alone
  would have made a request LLM traffic the scan is now incomplete with a
  warning, where such requests used to be skipped with exit 0. An inference
  operation with a static suffix (`/v1/chat/completions.css`, which a
  suffix-matching router serves as the endpoint) is no longer excluded as a
  static asset, while static files under inference-like prefixes
  (`/agents/app.js`, `/v1/images/logo.png`) still are, and `;name=value` path
  parameters are removed before the static-asset test.
- `lowcode.servicenow`: an empty page no longer ends a table. ACLs remove rows
  after `sysparm_limit`, so a whole 500-row window can come back empty while
  later windows hold readable records; collection used to stop there with exit
  0. It now pages until the windows cover `X-Total-Count`, which also saves the
  extra empty request per table. A response without a valid `X-Total-Count`
  ends the table at an empty page with a warning that makes the scan
  incomplete. `HttpClient.get_json` takes an `on_response` callback that sees
  the response headers once the body is decoded, as `paginate_link(on_page=)`
  does. The ServiceNow guide no longer claims that collection advances by the
  rows returned, which it never did.
- Integer options are validated like `max_pages`: `max_lambda`,
  `max_ecs_api_calls`, `max_projects`, `min_events` and `max_teams` must be
  positive integers, `cloudtrail_days` and `audit_days` non-negative integers.
  `int()` used to accept booleans and truncate fractions, so
  `cloudtrail_days: 0.5` silently switched CloudTrail lookups off, and text
  such as `"abc"` raised a bare `ValueError`; each is now a configuration
  error. The option descriptions and `docs/connectors/reference.md` name the
  requirement.
- `cloud.azure`: subscription ids from the subscription listing and resource
  ids from Resource Graph were used in ARM request paths unchecked. Requests
  removes `.`/`..` segments and `?` or `#` cuts off the appended suffix, so a
  crafted id could turn the app-settings POST into a POST to another ARM
  action (such as an account's `listKeys`) with the scanner's token, on the same
  host. A listed subscription id must now be a GUID and a resource id a plain
  ARM path (no `.`/`..` segments, `?`, `#`, `%`, `\`, whitespace or control
  characters); anything else is skipped with a warning and the scan is
  incomplete. Listed subscriptions without a string id used to be dropped
  silently and are now counted in that warning.

#### Review fixes: redaction and source decoding

- Redaction: a quoted value closes at its first quote that no backslash
  escapes. A JSON string that started with a credential and an escaped value
  (`{"log": "password: \"S\""}`, a ConfigMap's embedded YAML, Python's
  `'password: \'S\''`) closed at the escaped quote, only its backslash was
  withheld, and the credential was shown. Double-quoted option values
  (`--password "a\"S"`, `-u "user:a\"S"`, `echo "a\"S" | … --password-stdin`,
  `dotnet user-secrets set`) and `auth=(user, password)` pairs read `\"` the
  same way. A quote right after an assignment operator, or a line with no
  unescaped closing quote, keeps the former reading, and assignments are read
  the former way once more afterwards, so a Windows path ending in `\"` hides
  no credential after it.
- Redaction is linear again on comment blocks. Every word that ends a comment
  line (or precedes a comment) is read as a possible callee, and each skipped
  the rest of the block again to look for its `(`: about 250 KB of `#` or `//`
  comment lines took six seconds, and 1 MB took two minutes before it failed
  the redaction work limit and left the file incomplete. A call after a long
  block had its arguments lexed again for each word. A skipped comment is now
  remembered with where its trivia ends, and a `(` that several words reach is
  lexed and judged once.
- A Python source whose PEP 263 cookie names a codec that does not read ASCII
  as ASCII (`utf_16_le`, `utf-16-be` or `utf_32_le` without a byte-order mark,
  `utf-7`, HZ, EBCDIC code pages such as `cp037`) is a coverage gap
  (`binary or undecodable content in analyzable file`). The ASCII file was
  decoded into other characters, CJK text for UTF-16, and its imports and keys
  went unanalyzed with no gap reported; CPython refuses most such cookies. A
  codec error raised as a plain `UnicodeError` is reported as the same gap.
- Redaction: a `;` before an escaped line break or tab (`\n`, `\r`, `\t` in
  JSON-escaped text) ends an unquoted value. Read as a `;` inside the value,
  it ran `HOST=db;\n` into the next line and took that line's credential name
  with it, so `"HOST=db;\n:password => \"S\""` showed `S`.
- Redaction: the credential after an authorization scheme is never `=` signs
  alone. In `bearer => S`, `Bearer =~ S` and `bearer == S` the scheme rule took
  the operator's `=` as the credential, the assignment rules then found no
  operator, and `S` was shown. A credential glued to an `=` (`Basic =S`) is
  still withheld.
- Redaction: a braced ODBC connection string password is withheld whole, with
  anything a malformed value has after its closing brace up to the `;`. ODBC
  puts a value that holds `;` in braces and doubles a `}` inside them; the
  `Pwd=` rule read the value to its first `;` and showed the rest
  (`Pwd={a;S}`, `Pwd={a}};S}`). A brace that does not close within 256
  characters on its line, or opens a `{{` template, is read as before.
- `sanitize` costs each member of a set or frozenset as it costs a list item.
  The members were counted as leaves, so a set around a tuple nested more
  than 64 deep passed the structure check and its copy was cut short with a
  marker, and a set around a tuple of large texts was copied past the
  expanded-output limit. Both now fail the sanitization limit (exit 3), as
  the same tuple in a list does.
- Redaction: a URL inside another URL's text is read as a URL, so its
  userinfo, credential query fields and webhook path secret are withheld. A
  URL runs to the first blank or quote, so the second URL of a list
  (`redis://:a@h1,redis://:S@h2`, `amqp://u:secret@h1;amqp://u:secret@h2`)
  or one in a query value, path or fragment (`?next=https://u:secret@b`) was
  part of the first, whose authority alone was read, and its password was
  shown. Each inner URL is read up to the next one, after every other rule,
  and a text this changes is read once more, as the next sanitization would
  read it. A percent-encoded inner URL (`?u=https%3A%2F%2Fu%3AS%40h`) is
  still not decoded.

#### Review fixes: engine, incremental scans, plugins and CI

- Incremental scans: the fingerprint of an offline `code.github` or
  `code.gitlab` checkout follows `default_excludes`. With
  `default_excludes: false`, a change inside `vendor/`, `dist/` or `bin/`
  reused the cached result, so the scan exited 0 without the new evidence
  and `shadowscan diff` counted those findings as resolved.
- Incremental scans: the fingerprint records whether each skipped built-in
  directory that can hold first-party code (`bin/`, `build/`, `dist/`,
  `vendor/` and the like) holds a file. Adding `vendor/agent.py` to an empty
  `vendor/` used to reuse the cached result without the default-exclude
  warning.
- `identity.jwt` `tokens` are withheld from `repr()` and `str()` of a
  `ConnectorSpec` and its `ScanConfig`, like the credential-file locations.
  Opaque or malformed tokens match no value pattern, so a debug log or
  traceback that printed the configuration showed them verbatim.
- Process-mode plugins: a program the plugin starts no longer inherits the
  worker's result socket or multiprocessing's liveness pipe, and results
  carry a length prefix. A finished result used to be discarded as a
  timeout when a plugin ran `os.system` or a `Popen(close_fds=False)` helper.
  Connector timeouts above about 24.8 days no longer overflow the waits, and
  a deadline kill that races `Process.close()` no longer ends the scan
  without a report.
- Approval inventories: the approve-everything warning covers every pattern
  that matches all finding resources (`?*`, `*?`, ...), not only patterns
  made of `*`, and an inventory inside the offline clone directory
  (`input`) of a `code.github` or `code.gitlab` entry is reported like one
  inside a `code.filesystem` path.
- CI: every run outside a pull request has its own concurrency group, so a
  quick series of merges no longer replaces the pending push run of the
  middle commit. `make secrets` sets `pipefail`, and
  `tools/check_secrets.py` exits 2 when it is given no file instead of
  passing after checking nothing. A weekly run on `main` rebuilds the
  worker image from current Wolfi packages and rescans it with a fresh
  database.
- CI: the DCO check reads a sign-off after a `---` line in the commit
  message. Dependabot opens its YAML metadata with such a line, so its
  sign-off was never read and every Dependabot pull request failed the check.
- The CI lock takes Dependabot's eight pending development-tool updates
  (coverage 7.16.2, filelock 4.0.6, identify 2.6.20, librt 0.16.0, msgpack
  1.2.3, nodeenv 1.11.0, platformdirs 4.12.1, virtualenv 21.13.0), regenerated
  with the documented command and uv 0.12.18.

### October 2 review fixes (AI-assisted, not independently reviewed)

Fixes for defects found by an AI-assisted review of commit `d65b27f`. The
reviewers reproduced each one against that commit before it was fixed, and each
has a regression test. Neither the review nor the fixes had a second-person
review; the offline evaluation corpora are author-written and say nothing about
field precision. Behavior changes that affect an existing baseline are listed in
`docs/production.md` under "October 2 review changes".

#### Connectors: gateway, identity, low-code, SaaS and cloud

- `cloud.oci`: IAM policy statements are matched in linear time. The previous
  pattern retried a lazy scan from every `allow` word, so a 48 KB hostile
  statement took seconds (1 MiB about an hour) while holding the GIL and
  defeating `--connector-timeout-seconds`. A statement longer than 8192
  characters is a malformed record: that policy is skipped with a warning, the
  scan is incomplete, and valid neighbouring records are kept.
- `gateway.logs`: a client-chosen query string or fragment can no longer hide an
  inference call as a static asset or health probe (`POST
  /v1/chat/completions?_=.js` used to give 0 findings and a complete scan). Only
  the request path is tested and a probe name must be the last path segment, so
  `/healthz/../v1/chat/completions` is no longer excluded either. The number of
  excluded requests is reported as a scan note (a warning that does not make
  the scan incomplete).
- `gateway.logs`: `key=value` (logfmt) lines honor `\"` and `\\` escapes in
  quoted values, so a quoted client value can no longer inject `api_key=`,
  `user=` or `model=` pairs and attribute events to another caller. A line that
  repeats a key or leaves a quote open is malformed (scan incomplete); other
  lines are kept.
- Gateway provider attribution follows the RFC 3986 authority: userinfo up to
  the last `@` is dropped (an authority of `api.openai.com:443@evil.example`
  names `evil.example`), bracketed IPv6 literals lose brackets and port, and an
  empty host is `None`.
- Timestamps in microsecond and nanosecond epochs, Go `time.Time.String()`
  output and RFC 2822 dates are now parsed; they used to become empty, so
  events silently lost their time. Gateway records whose timestamp field no
  supported format parses are counted in a warning and make the scan incomplete.
- `identity.entra`: app-role and scope labels are resolved per resource. Another
  service principal that reuses a privileged role id with a harmless label can
  no longer relabel a grant (a `Mail.ReadWrite` grant used to print as a raw
  GUID, dropping risk from high to medium and losing `policy.privileged-scopes`).
  Conflicting labels for one resource and role keep the id and make the scan
  incomplete; a non-string `resourceId`/`resourceAppId` makes the record
  malformed.
- `lowcode.servicenow`: a page with fewer rows than `sysparm_limit` no longer
  ends collection of a table (ACLs filter rows after the limit is applied, so
  100 of 500 rows could come back with exit 0). Collection continues until an
  empty page; reaching `max_pages` first makes the scan incomplete. Each table
  costs one extra request.
- `lowcode.power-platform`: one flow, app or bot record that cannot be analyzed
  (signature-matching timeout or malformed fields) is skipped with a warning and
  the scan is incomplete; the records around it are still reported. A 3 MiB flow
  definition used to abort the connector with 0 findings. Signature matching
  examines at most the first 300000 characters of a definition, as the other
  low-code connectors do.
- `saas.generic` and `lowcode.zapier`: an export whose columns map to no app or
  zap name no longer gives 0 findings, a complete scan and exit 0. When no
  record has a name, a warning lists the accepted column names (never record
  values); when only some lack one they are skipped with a counted warning.
  Either way the scan is incomplete.
- `saas.slack`: a record naming another workspace (for example a Slack Connect
  bot with a foreign `team_id`) or an invalid workspace ID is skipped and
  counted in a warning, and the scan is incomplete; the workspace's other apps
  are still reported. One such record used to withhold every Slack finding.
- `identity.jwt`: without `jwks_url`, every token finding carries
  `metadata.verified: false` (with `verification_scope: "none"`,
  `issuer_verified: false`, `authorization_validated: false`) and a
  `jwt:signature` evidence line saying that claims are unverified. Previously
  there was no `verified` key, so an unsigned or tampered token read like a
  checked one. Confidence and risk are unchanged.

#### Engine, configuration, inventory, YAML and signature packs

- YAML with a malformed explicitly tagged scalar (`!!bool x`, `!!int >`,
  `!!timestamp ---`, an impossible date) is reported as malformed input
  everywhere ShadowScan reads YAML. PyYAML let `KeyError`, `IndexError`,
  `AttributeError` and `ValueError` escape, so one such file discarded the valid
  records of its neighbours, the connector error quoted the scalar, and a scan
  configuration with such a value printed a traceback. The bounded loaders raise
  `YAMLConstructionError` whose message gives only the line and column. A
  `RecursionError` during construction is a `YAMLResourceLimitError`.
- An integer or float scalar longer than 10,000 characters is a YAML resource
  limit (`YAMLResourceLimitError`; the scan is incomplete) instead of being
  converted. YAML 1.1 builds a sexagesimal integer (`1:1:1:...`) by repeated
  big-integer multiplication, which is quadratic: 80 KB took 0.5 s, 1 MB about a
  minute, and the 64 MiB input limit alone allowed hours.
- A connector or plugin that calls `sys.exit()` or raises another
  non-`Exception` `BaseException` during import, construction or collection is a
  failed connector: its error is recorded, the scan is incomplete (exit 3) and
  the report is still written. Previously the `SystemExit` ended the process
  with the plugin's exit status and no report, so `sys.exit(0)` read as a clean
  pass. `KeyboardInterrupt` still stops the scan.
- A scan warns when an inventory file or directory, or a file it loads, is
  inside a local path scanned by `code.filesystem` in the same run (scanned
  content, for example a pull request, could approve its own findings), and once
  per entry with a `*`-only resource pattern, which approves every finding. The
  warnings appear in a new `engine.inventory` entry of the report's `stats` and
  in table output; they do not make the scan incomplete or change the exit code.
  `shadowscan diff` ignores `engine.*` stats entries when it compares completion
  coverage.
- A configured custom signature pack directory that contributes no
  `.yaml`/`.yml` pack (empty, other file types only, or only symbolic links) is
  an error naming the directory and the skipped entries, in scans,
  `signatures list/show/test` and `python -m shadowscan.signatures.validate`.
  Symbolic links skipped inside pack directories, inventory directories or
  inventory globs are reported by name; links are still never followed. An
  inventory glob that matches no file is an error like a missing literal path
  instead of an empty inventory that marks every finding shadow.
- `shadowscan diff` requires each report's `summary.total` (and `by_surface` /
  `by_kind` counts when present) to match its `findings` array before missing
  findings can count as resolved. Emptying the `findings` array of a complete
  report used to print "1 resolved" with exit 0; such a report is now
  incomparable, its missing findings are listed as unknown and the exit is 3.
- `repr()`/`str()` of `ConnectorSpec` and of a `ScanConfig` holding it no longer
  print connector credentials. Values pass the report redaction rules and
  credential-file locations (`service_account_file`, `credentials_file`,
  `token_file`) are withheld.
- Inventories, configuration files, signature packs and reports accept a
  leading UTF-8 byte-order mark (spreadsheet "CSV UTF-8" inventories were
  rejected). A scan configuration that is a symbolic link, or reached through
  one (a Kubernetes ConfigMap mount), still fails, but the message now says that
  links are not followed and to pass the real path.
- Signature validation checks for empty-matching patterns with the same `regex`
  engine, flags and 0.1 s timeout as the matcher. A pattern only the `regex`
  module understands, such as `\p{L}*`, previously passed validation yet matched
  everywhere; it is now rejected.
- The default incremental state directory ignores an empty or relative
  `XDG_STATE_HOME`, as the XDG specification requires. An empty value used to
  put private state under `./shadowscan` in the repository being scanned.
- `shadowscan diff` text output no longer runs Rich's syntax highlighter over
  imported titles and resources, which was quadratic (a 50,000-character title
  took about 19 s).
- Inventory approval patterns are checked for citation markers (`[cite: 1]`,
  `[cite_start]`) in a single pass. The regular expression rescanned to the end
  of the item from every `[cite:` that had no closing `]`: 120 KB of `[cite:`
  took 13.6 s, and a megabyte about twenty minutes.
- `--incremental` with `--dump-records` logs that the cache is not used instead
  of disabling it silently. `docs/operations/ci.md` no longer recommends
  restoring incremental state with `actions/cache`: the fingerprint includes
  file identity, so a fresh checkout never reuses restored state.

#### code.filesystem: silent coverage gaps and denial of service

- Files that start with a UTF-8, UTF-16 or UTF-32 byte-order mark are decoded
  and the mark is removed. A UTF-16 `requirements.txt` (what Windows PowerShell
  5.1 `pip freeze >` writes), a UTF-16 `.env` and BOM-prefixed Python or JSON
  sources used to read as nothing and gave a complete, empty scan. A Python
  source is decoded with the codec its PEP 263 cookie declares; a codec that
  cannot decode it is a gap, and `punycode` is refused because its decoder is
  quadratic.
- A file the scanner analyzes by name that still holds a NUL byte in its first
  8 KiB (and is not a byte-order-marked text file) is a coverage gap, `binary or
  undecodable content in analyzable file`, so the scan is incomplete (exit 3).
  Compiled or packed artifacts without any file extension (ELF, Mach-O, wasm,
  archives, images, PDF) and names the scanner never analyzes stay quiet.
- The built-in directory exclusions are disclosed: a skipped non-empty `bin`,
  `build`, `dist`, `out`, `target`, `obj`, `coverage`, `vendor`, `third_party`,
  `thirdparty` or `external` directory is listed once per scan root in a warning
  (the scan stays complete). The new `default_excludes` option and `shadowscan
  code --no-default-excludes` scan them (also accepted by `code.github` and
  `code.gitlab`); version-control metadata stays excluded. The incremental
  fingerprint follows the option.
- Two quadratic patterns that hold the GIL, so neither
  `--connector-timeout-seconds` nor `--job-deadline-seconds` could interrupt
  them, are linear now and run under a matching budget: the agent-definition
  front matter (20 KB of blank lines took about 2.5 s) and the Terraform and
  CloudFormation IAM wildcard check (a 110 KB `.tf` made a scan take 137 s). A
  timeout is a file-level gap and the findings of other files are kept. Only
  horizontal whitespace may follow a front-matter marker now.
- `PackageReference` and `PackageVersion` items in `Directory.Build.props`,
  `Directory.Build.targets` and shared `*.props`/`*.targets` files are read as
  NuGet manifests (a `Microsoft.SemanticKernel` reference there gave no finding).
- `exclude` and `paths` must be lists of non-empty strings. A bare string was
  iterated per character, became the patterns `/` and `*`, excluded the whole
  tree and reported a complete, empty scan (`paths: "/srv/repo"` would have
  scanned `/`). The error names the option, never its value.
- A file or directory whose name is not valid UTF-8 no longer breaks the table,
  CSV, HTML, Markdown and SARIF reporters. Each undecodable byte is shown as a
  `\xNN` escape in reports while the file is still read under its real name.
- The directory walk uses an explicit stack. A chain about a thousand
  directories deep used to raise `RecursionError` on Python 3.11 and lose every
  finding.
- Python (or a notebook) that the running interpreter cannot parse, for example
  a PEP 695 `type A = int` on 3.11, adds a warning that import-bound analysis
  was skipped instead of dropping it silently; the lexical evidence is kept.
- An empty directory, or one holding only data files, named like an SDK
  (`openai`, `agents`, `langchain`) no longer makes every import of that SDK
  read as repository code. A `name.py` module, a package with `__init__.py` and
  a directory without it that holds Python source (a bounded look of 256
  entries and 8 levels) still count as local code.
- MCP servers that declare themselves disabled (`disabled: true`,
  `enabled: false`) are reported with the tag `declared-disabled` and
  `disabled: true` in `metadata.servers`, and `metadata.disabled` is set when
  none is enabled. The flag is client-specific (Cline honors it, Claude Code
  does not) and repository-controlled, so honoring it let a repository hide a
  server. `server_count` still counts the servers not declared disabled. The
  three `mcp-disabled-*` evaluation cases are now labelled present and the
  documented authored-corpus counts change from 29/48 to 32/45 positives and
  negatives; the evaluation harness scans cases with `default_excludes: false`.

#### Detection precision, labels and risk policy

- The top bucket of the `likelihood` field is renamed from `confirmed` to
  `strong` in every report format. It was only ever `confidence >= 0.85`, never a
  verification state; the thresholds are unchanged. Reports, `diff` baselines and
  incremental-cache entries that carry `confirmed` are still read, as `strong`
  (the label is derived from `confidence` and is not part of finding identity).
  Python callers: `Likelihood.CONFIRMED` is now `Likelihood.STRONG`. Anything that
  filters or counts on the string `confirmed` must accept `strong`; use
  `confidence` for thresholds.
- A data or prose file that only lists products no longer establishes a
  technology. A YAML, JSON, TOML, INI, XML, CSV, text or Markdown file that names
  four or more products through domains or environment-variable names, and holds
  no import, dependency, code, file-name, image, IaC, model or credential
  evidence, is a catalog (a proxy blocklist, an egress allowlist, a vendor policy,
  a copy of the signature packs). Its mentions count only for a signature with
  library evidence elsewhere in the project. A repository whose only content was
  such a list reported "LLM usage: CrewAI" at confidence 1.0 and high risk; it
  now yields no finding, and `metadata.catalog_mentions` lists the discounted
  files when a finding remains. Source code, manifest-named files (dotenv,
  Compose, Helm values, workflows, requirements, IaC) and data files naming one to
  three products are unchanged. Scanning `shadowscan/signatures/data` no longer
  reports LangGraph, CrewAI, Google ADK and Agno. Known cost: a bare data file
  that names four or more providers and is the only evidence (for example an
  Envoy routing table kept in YAML) is no longer reported; its deployment is still
  found through its dependency, import, image, IaC or file-name evidence.
- `Evidence` refuses a weight that is not a finite number between 0 and 1, at
  construction and on assignment. A NaN or infinite weight clamped to 1.0 inside
  the noisy-OR and produced confidence 1.0. A plugin that passes such a weight now
  fails its connector (the scan is incomplete) instead of reporting an inflated
  confidence.
- `options.risk_weights` keys under `capabilities` and `providers` are
  validated: a capability must be one of the ten capability names and a provider
  must be a provider signature id of the loaded packs, with a "did you mean" hint.
  `capabilities: {code-execution: 99}` used to exit 0 and change nothing; it now
  stops the scan setup. Tags stay open-ended, so an unfamiliar tag key is accepted
  and logged once per process.
- The risk score scales by confidence with exact arithmetic. Binary floats had
  drifted (`0.6 + 0.4 * 0.15` is `0.6599999999999999`), so a raw 75 at confidence
  0.15 scored 49 (medium) instead of 49.5, which rounds to 50 (high). Over raw
  totals 0 to 300 and confidences 0.000 to 1.000, five clamped scores move by one
  and one crosses a level (medium to high).

#### Remote collection: clones, listings and HTTP

- A scan that is terminated (SIGINT, SIGTERM, SIGHUP) or hits
  `--job-deadline-seconds` stops its in-flight `git clone` process groups and
  deletes the temporary checkout of the repository being scanned before it exits.
  Git used to keep running in its own session, without size or time limits and
  with the clone credential in its environment, and the checkout stayed on disk.
  No new clone starts afterwards, and an interrupted clone is not retried through
  the sampled API fallback. SIGKILL and OOM kills cannot be handled in process.
- `code.github` and `code.gitlab` read the organization, user or group listing to
  the end before the first repository is cloned or scanned, in an order a push
  cannot change (GitHub `sort=full_name`, GitLab `order_by=id`). The listing was
  ordered by recent activity and paged lazily, so a push to a not-yet-listed
  repository during the scan moved it behind the cursor: it was never examined
  and the scan stayed complete (exit 0). When more repositories exist than
  `max_repos` or `max_projects`, the covered subset is the first N in stable
  order. GitLab listings are compared with `X-Total` and `X-Total-Pages`; entries
  that do not add up make the scan incomplete. GitHub reports no total, so a
  repository deleted (not pushed) mid-listing can still hide another.
- A clone, and API mode, report Git LFS pointer files (small files opening with
  `version https://git-lfs.github.com/spec/v1`): `Git LFS pointer files in <repo>
  are not resolved; source coverage partial` makes the scan incomplete (an error
  under `strict_coverage`). Submodules are reported by the gitlink check merged
  from main.
- `topics`, `repos` and `projects` of `code.github` and `code.gitlab` must be
  lists of non-empty strings, and `max_repos`, `max_projects` and `clone_depth`
  whole numbers. `--set topics=llm` was iterated as the characters `l`, `l`, `m`,
  examined no repository and finished complete with exit 0; it now stops the
  connector with an error that names the option.
- Cloning requires Git 2.32 or newer: the clone protections travel in
  `GIT_CONFIG_COUNT` and `GIT_CONFIG_GLOBAL`, which an older Git ignores
  silently (a 302 to another host was followed and the scan finished). With an
  older or unidentifiable Git the connectors use sampled API mode and the scan is
  incomplete. Clones also verify received objects (`transfer.fsckObjects`).
- The HTTP destination policy refuses `168.63.129.16` (Azure wire server) and
  site-local IPv6 `fec0::/10`. A URL containing whitespace or control characters
  is refused instead of being cleaned by the parser while git rejects it, and an
  API tree that names a `.git` path component aborts that repository's snapshot.
- Documentation: the GitHub token needs Contents and Metadata plus Secrets,
  Variables, Codespaces secrets and Dependabot secrets (read). Without them every
  repository adds four identical `repository metadata HTTP 403` warnings and the
  scan exits 3. Use separate token variables for `code.github` (which reads
  untrusted content) and `saas.github-apps` (which needs organization admin).

#### Redaction and report output

- Credential redaction reads an operator whole. `'api_key' => '<value>'` used to
  become `'api_key' =[REDACTED] '<value>'` and `if token == '<value>':` became
  `if token =[REDACTED] '<value>':` (the marker replaced the operator's second
  character and the literal stayed in the report); `!=`, `||=`, `+=` and `.=`
  were not read at all. `=>`, `==`, `===`, `!=`, `!==`, `=~`, `:=`, `||=`, `&&=`,
  `??=`, `+=`, `-=`, `.=`, `?=` and `<-` now join a name to a value like `=` and
  `:` do: the literal is withheld and the operator is kept. A comparison with a
  sensitive name withholds only a quoted word or an opaque value, so `x == 1`
  and `key => users` stay.
- Provider tokens and JWTs are withheld when a word character precedes them:
  after a JSON-escaped line break or tab (`\n`, `\t`, `\x22`), a percent escape
  (`%3D`) or `_`, and, for the unmistakable prefixes (`sk-proj-` and the other
  `sk-<qualifier>-` forms, `ghp_`, `github_pat_`, `xox*-`, `AIza`, `AKIA`, `eyJ`),
  after a digit. Words that merely end in a prefix's text (`risk-`, `disk-`) stay.
  The JWT rule reads each run of base64url characters once (a 400 KB run of
  `eyJ-eyJ-...` took about a minute).
- URL userinfo is withheld whole when the password holds a raw `/`, `?` or `#`
  (`postgres://u:example#pw@h`, `https://svc:example7?x@llm-gw.example/v1`); URLs
  such as `https://host/path?x=a@b` are unchanged.
- `--dump-records` and report metadata withhold structured fields by the words of
  their name. `webhook_secret`, `signing_secret`, `bot_token`, `client_key`,
  `openai_key`, `pwd`, `passphrase`, `db_pass` and `jwtSecret` kept their raw
  values in the `NNNN-*.jsonl` dump of a `saas.generic` export. Cursors
  (`next_token`, `skipToken`), tokenizer tokens, switches (`requires_auth`) and
  the bare `key` of tags and objects are unchanged.
- A value of an unknown type in finding metadata or a record dump (bytes, a set,
  an exception, a plugin's object) is converted to text and redacted like any
  other value instead of reaching a report raw through `json.dumps(default=str)`
  or `repr`.
- Private-key blocks in PGP, RFC 4716 (SSH2) and PuTTY forms are withheld with
  their line count; `passphrase`, `SECRET_KEY_BASE`, `creds`, `db_pass`,
  `smtp_pwd`-style names, npm's `_auth` and an ODBC `Pwd=` member are withheld
  whatever the value, as are authentication headers named for a credential word
  (`curl -H "X-Token: v"`).
- `-f csv` neutralizes formula cells in one linear pass. A run of 20,000 CRLF
  pairs in a title, owner or evidence text took about five seconds and every
  doubling cost four times as much. The inserted markers are unchanged.
- The terminal shows zero-width characters, the byte-order mark and Unicode tag
  characters as escapes. A lone surrogate in a name read from an export no longer
  fails `-o x.csv|md|html` or prints a traceback; it is written as `\ud800`.
- Markdown reports defang `http://`, `https://` and `ftp://` after any non-letter
  and `www.` after any non-alphanumeric (`_https://host` was still an autolink),
  and SARIF message text escapes `\`, `[` and `]` so scanned text cannot write a
  `[text](destination)` link. These two follow the GFM and SARIF 3.11.6 rules and
  were not checked in a viewer. `SECURITY.md` lists what can still remain.

#### Source lexer

- The JavaScript lexer no longer treats a keyword-named property or method as a
  keyword. After `o.of`, `o?.in`, `this.#typeof` or `o.for(x)` a `/` is a
  division, so `o.of / 1; <code>; 2 / 1;` can no longer turn the code between
  the two slashes into a "regular expression" that hides it (the scan reported
  0 findings and was complete). `of` is a keyword only after an operand, and a
  regular expression after a spread is lexed as one. A `/` after `await` or
  `yield` cannot be classified without a parse and makes the file's lexical
  analysis incomplete. So does a regular expression after a closing brace that
  holds a quote, backtick or slash, which a block-then-regex statement could use
  to hide the rest of a line.
- Line comments end at the language's real line terminators: LF, CR, U+2028 and
  U+2029 in JavaScript and TypeScript (also inside a JSX tag), `?>` in PHP,
  escaped line breaks in Java. Replacing every LF of 1,221 real JavaScript files
  with CR, U+2028 or U+2029 changed what 838 of them hid before and none after.
  A backslash no longer escapes the quote of a JSX attribute string.
- The JSX look-ahead has a per-file allowance. A 250 KB run of `<A>(` took over
  a minute and discarded the results of the whole scan; it now ends in under a
  second as an incomplete file while the other files are scanned. A megabyte of
  `#` in Swift (13 s) and the Java escape search are no longer quadratic.
- A regular-expression literal up to 262,144 characters lexes completely. The
  `emoji-regex` tables found in most npm trees (10 to 17 KB on one line) used to
  make the whole scan incomplete.

#### CI, repository policy and developer tooling

- CI no longer cancels a `main` push run when the next push arrives:
  `cancel-in-progress` is `${{ github.event_name == 'pull_request' }}`. Before,
  29 of 83 `main` push runs ended `cancelled`, leaving merged commits without a
  complete CI record.
- The repository policy tests check workflows with either YAML extension (a
  `.yaml` workflow used to skip every check) and add invariants for: no
  `workflow_run` trigger; no job- or step-level `continue-on-error`; no
  `|| true`, `--exit-zero` or `--ignore-vuln`; no coverage floor below 80; no
  event text, `head_ref`, `ref_name`, `inputs.*` or `toJSON` dumps interpolated
  into `run:`; no publication command anywhere (`gh release`, `twine upload`,
  `uv|poetry|hatch publish`, `pypi-publish`, `docker push`, `git push`); a
  release workflow that stays `workflow_dispatch`-only with `id-token: write`
  only in its checkout-free `attest` job; Dockerfiles with digest-pinned `FROM`,
  a final non-root `USER`, no `ADD <url>` and hash-checked `pip install`; and an
  allow-list-style `.dockerignore`. Each rule runs on the real file and on a
  mutated copy (32 mutations) to show that it still catches the violation.
- The `no-hardcoded-secrets` hook recognises many more credential shapes: of 28
  planted synthetic examples the previous patterns found 7 and the new ones find
  all 28. They include GitHub `github_pat_`/`gho_`/`ghu_`/`ghs_`/
  `ghr_`, AWS `ASIA` keys and `aws_secret_access_key = ...`, Google `AIza`, Slack
  `xoxp-`/`xoxa-`/`xoxr-`, Hugging Face `hf_`, Stripe live keys, signed JWTs,
  PEM private-key headers, Azure `AccountKey=`/`SharedAccessKey=` and passwords
  in URLs. It prints at most four characters plus the match length (it used to
  print twelve), fails on an unreadable file, runs on every text file, and CI
  runs the same script over `git ls-files`.
- `tools/coverage_gate.py` fails closed: a module with statements in an unlisted
  connector family, in a nested package, or directly under
  `shadowscan/connectors/` (other than `base.py`, `common.py` and `offline.py`)
  fails the gate with a message naming the reason, where it used to be skipped
  while the gate printed "Checked N modules". A malformed coverage report exits
  2. `tests/test_coverage_gate.py` pins the 75% floor and the exit codes.
- `make audit` (and so `make check`) audits the four hash locks as CI does.
- `make secrets` (part of `make check`) runs the credential check that CI runs
  over every tracked file; a consistency test pins both commands.
- `tests/unit/test_regex_linearity.py` fails when a module-level regular
  expression is superlinear on hostile input (CPython's `re` cannot be
  interrupted, so such a pattern defeats the connector and job deadlines), and
  times the redaction passes end to end. Mutation tests were added for the
  credential-mixing guard, symlink reporting in inventory globs, the incremental
  cache's refusal to store incomplete results, the shipped YAML alias budget
  and the Makefile coverage floor.
- Documentation: `docs/testing.md` lists the expected skips (core-only installs
  skip about 60 cloud-SDK tests, Git < 2.45 and root-only permission tests);
  `docs/evaluation.md` states the real 5 to 7 files per realistic-corpus case; and
  `docs/connectors.md` documents the 44 connector configuration keys that no
  connector page named. A consistency test now fails when a key reported by
  `shadowscan connectors --json` is undocumented.

### October 2 production review corrections

- npm dependency aliases are attributed to their declared registry target,
  preserving development-dependency status. Invalid alias targets mark source
  coverage incomplete while valid neighboring dependencies remain visible.
- CSV inventory parsing preserves embedded line separators in quoted fields,
  so resource and account approvals retain their declared identity.
- Imported evidence validates nullable text fields and object attributes before
  postprocessing. Malformed incremental entries trigger a fresh scan instead
  of reaching correlation or confidence calculations.
- Notion and Atlassian collection reject provider error envelopes even when
  empty collection fields are present. Google Workspace rejects malformed user
  suspension flags with incomplete coverage and retains valid neighboring users.
- Wheel validation uses a unique private temporary environment and working
  directory, with cleanup on successful and failed validation.
- The connector coverage gate requires the report to name every module under
  `shadowscan/connectors/` in the checkout and rejects malformed counts. Its
  scope (every connector module, statements and branches) and 75% minimum are
  unchanged.

### Code structure and developer experience

- **Module boundaries:** finding merge logic lives in `shadowscan/merge.py`
  and cross-surface correlation in `shadowscan/correlation.py`; the engine
  imports both. The public API is unchanged.
- **Property-based tests:** Hypothesis tests for the redaction module check
  idempotency, crash-freedom on arbitrary Unicode and removal of known token
  formats. Hypothesis is part of the `dev` extra and the CI lock.
- **Parallel test runs:** `pytest-xdist` joins the `dev` extra, with a
  `make test-parallel` target.
- **API reference:** mkdocstrings pages for the core modules are part of the
  documentation site.

### October 2 production hygiene review

- Connector diagnostic sanitization retains credential context across errors,
  warnings and skip reasons. JSON statistics are sanitized together, matching
  the other report formats. A sanitization limit clears omitted skip reasons.
- GCP, Azure, OCI and Slack live collectors preserve their locally assigned
  record classification and collection scope over provider fields. Invalid
  discovered GCP project identifiers produce incomplete coverage rather than
  entering authenticated request paths.
- MCP tool attribution ignores commented and string examples, and counts only
  referenced enum members. Recheck capability labels and enforcement baselines
  when comparing reports made before this correction.
- The secret-pattern checker escapes control characters in the file names it
  reports, so a crafted name cannot forge a report line or a workflow log
  command. It runs over every tracked text file in CI, `make check` and the
  pre-commit hook; the test, signature-pack and evaluation-corpus exemptions
  remain explicit, and this pattern check is not a complete secret detector.
- Local coverage and wheel validation use private temporary paths with cleanup
  on success or failure. Wheel validation refuses multiple stale scanner wheels.
- Evaluation rejects ambiguous case/Unicode path layouts, file/directory
  collisions and overlong UTF-8 filename components before materialization.
  Existing labeled files are never overwritten.
- Gateway UTC timestamp validation runs before caller state changes. An invalid
  timestamp or interval end marks coverage incomplete without suppressing valid
  neighboring observations for the same caller.
- Tenant-canary verification indexes exact resource identities instead of
  comparing every control with every collected record. Dump verification reads
  lines incrementally under the existing file-size cap; acceptance selectors
  and scope requirements are unchanged.
- Live ruleset readback found both rulesets active, with independent approval
  required, but the required-check list still omitted `CI gate`. This review
  does not alter repository settings, publish a release or establish live
  tenant acceptance or independent human review.

### October 2 review remediation

- Gradle and Dockerfile dependency extraction, and the content matching of
  those manifests, ignore comments while keeping quoted strings and active
  declarations; a credential inside a comment is still reported. Named Python
  URL requirements keep their declared package identity. The paired regression
  cases are authored test evidence, not a fresh field-accuracy measurement.

### October 2 review corrections

- Name/value credential redaction caches line bounds and the first content
  position instead of repeatedly scanning or copying growing record prefixes.
  This removes quadratic work on long lines of repeated record names while
  preserving credential withholding and list boundaries. Deterministic
  character-work regressions complement the existing timing checks.

- JavaScript and TypeScript source calls that exceed the bounded semantic
  analysis budget now make coverage incomplete instead of silently losing
  agent-construction evidence. Valid neighboring findings are retained.
- Binary-looking `.ts` source is no longer silently classified as MPEG video
  from packet bytes. Source comments can mimic that prefix while hiding agent
  construction. Such files make coverage incomplete; trusted operators may
  explicitly exclude known media paths from the intended scan scope.
- Failed incremental cache-decision hooks now make connector coverage incomplete,
  retaining built-in validation diagnostics and exposing only exception types
  for plugin hook failures.
- Zapier blank-row tolerance requires a recognized identity column; all-blank
  records with unknown JSON keys or CSV headers make coverage incomplete.
- Generic Genkit initialization and flow/tool declarations no longer establish
  an agent or configured tool-use capability. Supported concrete agent
  definitions and model calls with registered tools retain detection.
- The shared HTTPS transport bounds response acquisition as well as body
  delivery, interrupting slow status/header delivery without releasing an
  actively cancelled connection back into the pool. System DNS and external
  SDK calls still require a process/job supervisor for a hard execution limit.
- CI checks the exact built worker image for HIGH/CRITICAL OS and Python
  vulnerabilities and retains a container SBOM, scan result and image identity.
  Vulnerability database acquisition and scanner errors fail the gate.
- The worker build upgrades base Debian packages from the enabled archives
  before installing Git and certificates, applying available security fixes.
  Unfixed HIGH/CRITICAL advisories continue to block the container gate.
- Release candidate evidence now checks active merge rules, independent-review
  requirements, strict `CI gate`/CodeQL checks and bypass visibility. An offline
  settings-patch command preserves additional protections while adding the
  aggregate check, binding required checks to GitHub Actions and requiring
  final-push approval, resolved review threads and deletion protection.
  Repository administration remains a separate action.
- These changes add authored regression evidence. They do not establish live
  tenant acceptance, fresh field accuracy or independent human approval.

### October 1 scan integrity remediation

An AI-assisted audit of the unreleased candidate (not independent human review)
found places where a scan could finish `complete` while skipping content or
persisting credential-shaped text. These changes close the confirmed gaps; each
has a regression test.

- **Silent coverage gaps now mark the scan incomplete.** A source or config file
  with a NUL byte in its first 8 KiB and no byte-order mark (UTF-8/16/32 files
  with a byte-order mark are now decoded instead; other invalid UTF-8 is still
  decoded with replacement characters), a FIFO, socket or device named like a
  config file, a directory named like an MCP configuration file (`.mcp.json/`),
  a directory tree nested too deeply for the Python 3.11 walker, any file
  without a supported export suffix in a connector's offline input directory (a
  rotated `access.log.1`, a `.bak` or `.zst` copy, a `README.md`),
  `saas.generic` rows without a resolvable name, wrong-schema `saas.generic` and
  `lowcode.zapier` objects, and negative or absurd gateway token and cost values
  each produce a specific incomplete diagnostic. A symlinked card inside an
  inventory directory stops setup instead of being skipped. A recognized binary
  artifact (executable, archive, image, PDF or SQLite database, by its header)
  stays a quiet skip when it has no file extension, when only a directory-wide
  signature glob such as `.cursor/rules/**` selected it. An analyzable source
  extension, including `.ts`, and unrecognised binary content remain a gap.
- **Disclosure without failure.** Code scans list default-excluded directory
  names (`build`, `vendor`, `external`, ...) once per root, and default-scope AWS
  and GCP scans name the regions or locations that were not scanned. Both are
  notices that do not mark the scan incomplete. Reports list disabled or
  `--only`-excluded connectors in `collection_scope.not_run`. The AWS CloudTrail
  management-events notice no longer forces exit 3.
- **Credential redaction.** Newly withheld: values of the `--passphrase`,
  `--pat` and `--auth` options (withheld as a `--password` value is, so a
  lowercase word after a space stays; in an argv list the value after these
  options and `--pass`, `--pwd` or `--password` is always withheld); whole
  armored PGP private key blocks, including one after a credential name; every
  cookie in a `Cookie` header; compact headers and passwords without a space
  (`x-api-key:S`, `password:S`); unquoted values containing `;`; values in
  escaped-quote JSON; the URL query keys `auth`, `pwd` and `pat`; Fireworks
  `fw_` keys; and provider tokens next to non-Latin text. Sets and bytes are
  traversed. Some text is over-redacted: `ffmpeg -pass 1` loses its pass
  number, `NAME=S;rest` loses the text after `;`, and `Authorization:` loses
  its scheme name. A quadratic JWT pattern that could stall a scan for minutes
  was replaced by a linear one. The unkeyed SHA-256 `credential:sha256:` digest
  is unchanged; see `docs/production.md`.
- **Gateway attribution.** Access-log hosts are read only from the trailing
  unquoted `host=` token, so a user agent or path cannot hide or forge LLM
  traffic. Generic vendor hosts (`api.cloudflare.com`, `huggingface.co`) are
  hints rather than LLM-usage evidence, except Cloudflare Workers AI inference
  paths (`/accounts/<id>/ai/run/`, `/accounts/<id>/ai/v1/`), which stay LLM
  traffic. PyPI `swarm` no longer maps to OpenAI Swarm. Scope names are matched by bare name across providers, so names that
  are routine on another provider no longer match `policy.privileged-scopes`:
  OIDC `offline_access`, Salesforce `full`, `web` and `refresh_token`, GitLab
  `api`, GitHub `workflow` and Slack `admin`. Findings that held only these
  scopes lose that risk factor and can drop a risk level.
  `identity.jwt` ignores empty or false agent claims, labels GitHub Actions,
  GitLab CI and Kubernetes service-account tokens `workload` (a Kubernetes
  service-account subject or claims make a `workload` for any issuer, including
  GKE), counts a GitHub Actions `actor` or `triggering_actor` as an agent hint
  only when it names an AI agent or product, and marks tokens scanned without a
  JWKS (`signature_verified: false`). Gateway registry matches on
  operator-asserted or unverified caller names carry
  `metadata.registry_match_assurance` and the `registry-identity-unverified` tag.
- **Engine and reports.** A connector or third-party plugin raising
  `SystemExit` or another `BaseException` other than `KeyboardInterrupt`, while
  it is imported, its class is verified, an engine hook runs or it collects, is
  an incomplete connector (exit 3 with a report), not a process exit. Only the
  exception type is reported. `KeyboardInterrupt` still ends the scan. Incomplete CSV
  reports start with a `SCAN-INCOMPLETE` status row. Saved CSV and HTML render
  terminal control characters visibly. `shadowscan diff --fail-on-new` exits 2 on
  new or higher-risk findings. Exit codes 1 and the usage-error 2 are documented.
- **HTTP client.** Okta `X-Rate-Limit-Reset` is honored, retries stop at the
  connector deadline, a response body must also finish before that deadline
  (in addition to the read deadline below), and `identity.jwt` accepts an
  explicit `ca_bundle` for private PKI (verification stays on; a relative path
  resolves beside the configuration file).
- Dialogflow CX and Discovery Engine use their regional endpoints. ServiceNow
  collection pages until an empty page. A weekly scheduled `pip-audit` workflow
  was added. The Anthropic signature recognises `sk-ant-oat01-` OAuth tokens.
  Unquoted Cursor `globs: **/*.ts` no longer causes a false exit 3,
  and `host_of` strips URL userinfo and handles IPv6 literals.
### October 1 review corrections

- Named Python direct-reference requirements retain their declared package
  identity before URL or VCS inference. Extras, fragments, environment markers
  and source lines remain available as evidence.
- Python semantic analysis ignores constant-false loop bodies, preserves the
  applicable loop `else` path, joins uncertain loop bindings conservatively,
  and stops unreachable statements after explicit local control transfers.
  This is bounded source analysis, not interprocedural execution proof.
- Optional Git enrichment streams stdout and stderr under a combined 16 KiB
  limit, caps accepted identity fields, and terminates children on overflow,
  cancellation or deadline. Limit hits retain code findings and mark coverage
  incomplete rather than publishing unbounded metadata.
- Credential redaction covers additional constructor syntax, environment
  fallback literals, credential records and explicitly named command/query
  values. Regenerate stored reports and incremental baselines under the revised
  policy before sharing them; ambiguous comments and arbitrary computed values
  still require confidential handling.
- Production evidence policies can add aggregate and per-kind 95% Wilson
  lower-endpoint thresholds. Legacy point-estimate policies remain compatible;
  successful decisions expose the lower endpoints. The example uses confidence
  gates and per-kind sample floors; these are operator-selected targets, not
  evidence of measured production accuracy.
- Added a versioned active merge policy and bounded snapshot checker requiring
  the aggregate CI gate, bound check origins, final-push review and no bypass
  actors. They do not change live repository settings. Administrator activation,
  independent human review, fresh holdout labels and tenant acceptance remain
  external requirements.
### October 1 review remediation

Fixes and recommendations from the 2026-10-01 repository review. Upgrade
steps are in docs/production.md ("October 1 review changes").

- **Exit codes:** usage errors exit 1 instead of 2, so exit 2 only means a
  complete scan reached `--fail-on`.
- **Gateway identity:** `diff` lists scan-local gateway findings under
  `not_comparable` instead of as new. The opt-in `SHADOWSCAN_IDENTITY_KEY`
  (environment only, at least 32 bytes) keeps gateway IDs and collection scope
  stable across scans; git child processes never receive it.
- **Confidence:** outside the code surface, repeated evidence of one signal
  counts once. n8n, Make and Zapier findings score all their evidence before
  they are finalized.
- **Inventory:** cards accept `discovery.discriminators`; `inventory stubs`
  binds each card to its own finding and writes plain-string names.
- **Cloud:** `cloud.aws` parses role trust policies (`Deny`, `NotAction` and
  `NotPrincipal` never establish trust; a malformed policy makes the scan
  incomplete). `cloud.oci` converts SDK models without silently dropping
  fields. Every connector validates `max_pages` and caps it at 1000.
- **Detection:** Vercel AI SDK multi-step tool loops, including AI SDK 7
  `isStepCount`, are agents. Custom-pack framework code patterns apply in
  Python and JavaScript. ShadowScan, Semgrep, Sigma and gitleaks rule files are
  treated as data and listed in `metadata.detection_rule_files`.
- **Threshold filtering:** `--min-confidence` removes `related` links and
  `runtime_activity` references to omitted findings.
- **Timestamps:** microsecond and nanosecond epoch values are parsed.
- **Redaction:** keys passed positionally to well-known LLM SDK calls are
  withheld, including the endpoint-`Uri` overloads. Long blank runs no longer
  make the Python 3.11 tokenizer quadratic, and Python 3.12+ codec errors no
  longer make a file's analysis incomplete.
- **Removed:** the unused `safe_yaml.bounded_safe_load_all` and
  `HttpClient.requests_made`; use `strict_bounded_safe_load_all`.
- **Evaluation:** `tools/evaluation/current_idioms_corpus.json` (24 cases)
  runs in `make evaluate` and CI.
- **Tests and CI:** tests resolve hostnames hermetically and fail on outbound
  connections. Both coverage floors count branches, and the connector floor
  covers every module under `shadowscan/connectors/`. Coverage is traced on
  Linux 3.11 only, and a traced run takes about half as long. Matcher budgets
  are generous in tests unless a test opts into the shipped values. CI never
  cancels a running `main` build and runs the secret hook over tracked files.
- **Governance and docs:** `.github/rulesets/require-ci-and-review.json` versions the intended
  `main` ruleset; the README regains its project-status section and an OpenSSF
  Scorecard badge; RELEASE_NOTES.md summarizes releases for users; ADR-004
  and ADR-005 propose a parsing strategy and code-scanner module boundaries.
### October 1 review fixes: bounded matching, link walks and record tolerance

Fixes for the findings of an AI-assisted repository review (not an
independent human review); each behavior change has a regression test.

- `code.filesystem`: the IaC wildcard-action and agent front-matter patterns
  now run on the bounded regex engine with possessive whitespace, under the
  per-input matching budget. Before, a planted file (`Action:` followed by a
  long run of spaces, or `---` followed by many blank lines) backtracked
  quadratically in stdlib patterns that nothing could interrupt, which could
  hold the connector past its deadline and discard every code finding.
- `code.filesystem`: symbolic links now count toward `max_files`, link checks
  stop at the connector deadline with an explicit error (`connector deadline
  reached while checking symbolic links`), and the project lookup behind each
  link is cached per directory. A tree planted with thousands of links was
  quadratic and uncounted. Scans of repositories holding more links than the
  remaining `max_files` budget become incomplete; raise `max_files` or exclude
  the link directories.
- `code.filesystem`: a JSON, YAML or TOML file that merely contains the words
  `"mcp"` and `"servers"` but configures no MCP server (an exported workflow
  tagged `mcp`, a template with such a comment) is ordinary configuration
  again. Before, it was treated as MCP configuration and the IaC,
  configuration and lexical passes skipped it without a diagnostic, hiding
  the workflow or the wildcard IAM grant. Dedicated MCP file names
  (`.mcp.json`, `claude_desktop_config.json`, ...) are unchanged.
- `code.filesystem`: a credential in a notebook code cell is counted once;
  the raw document's copy of the cell no longer doubles the count and the
  confidence. Outputs and markdown cells are still scanned.
- `cloud.aws`: a malformed provider record (a function without an ARN, an
  endpoint without a name, an alias version that is not a string) skips that
  record with a warning and incomplete coverage instead of aborting every
  remaining service and region. Failed SDK calls now report the operation
  and the provider error code (`cloud.aws: get_agent access denied
  (AccessDeniedException)`), never the message text, which can echo request
  arguments or encoded policy context. `cloud.gcp` treats a service record
  without a config name the same way.
- `identity.entra`, `saas.microsoft-teams`, `lowcode.make`: response-derived
  identifiers are percent-encoded before they enter a request path.
  `max_app_role_lookups`, `max_users` and the automation connectors'
  `max_pages` must be positive integers; a zero or non-numeric value now
  stops the connector with a configuration error instead of being coerced.
- Gateway timestamps: an eight-digit `yyyymmdd` value is a calendar day.
  It was read as epoch seconds and attributed callers to 1970.
- One `failure_summary` helper replaces eighteen copies of the HTTP-status or
  exception-type expression in connector diagnostics (no output change).
- Documentation: the README states the usage, setup and `diff` exit codes
  and carries the OpenSSF Scorecard badge the roadmap refers to;
  `docs/connectors.md` lists the GitHub credential-name permissions and adds
  least-privilege rows and option lists for Slack, ServiceNow and Notion. A
  repository test now checks the "25 of 27 connectors ship fixtures" claim.
### Confined file portability and plugin deadlines

- On platforms exposing `O_NOFOLLOW_ANY` without Linux `O_PATH` (including
  supported macOS versions), confined file reads use one kernel-checked path
  lookup, including reads relative to an already-open scan root. This avoids
  opening every ancestor for reading while still rejecting symbolic links in
  every component. FIFO protection and regular-file verification remain in
  force; paths are never resolved through symlinks as a fallback.
- Signature directory traversal now fails on unreadable subdirectories and
  enforces its entry budget for directory-only trees. A partial signature pack
  must not silently become an accepted policy or digest.
- `pytest` console invocations can import checkout-only evaluation and canary
  tooling without a caller-supplied `PYTHONPATH`; macOS CI exercises this entry
  point as part of the full suite.
- Optional `options.plugin_execution: process` / `--plugin-execution process`
  runs approved third-party connectors in dedicated spawned workers, including
  plugin import. Connector deadline expiry terminates the worker and marks its
  results incomplete. A worker also stops itself two seconds after that
  deadline, or as soon as the scanner process exits (including the job-deadline
  watchdog, SIGTERM and SIGKILL), and a `KeyboardInterrupt` during collection
  kills running workers. Processes a plugin starts itself are not terminated.
  Workers write record exports only into the private export directory the
  scanner prepared, and exit as soon as their result is sent, so lingering
  non-daemon plugin threads cannot turn a delivered result into a timeout.
  Result transport serializes like the JSON report (`str()` for values such as
  `datetime`, sets and bytes; NaN and infinity still fail closed).
  Crashes, malformed output and output above the 16 MiB transport
  limit also fail closed. The default remains `thread`; built-ins retain their
  existing execution path. Process mode provides lifecycle isolation, not a
  security sandbox or rollback of external effects.

### October 2 repository hygiene

- Agentforce metadata (`GenAiPlanner`, `GenAiPlugin`, `GenAiFunction`,
  `GenAiPromptTemplate`, `BotDefinition`, `BotVersion`) that declares XML
  entities or attribute defaults is no longer parsed and makes the scan
  incomplete (`structured configuration declares XML entities or attribute
  defaults; not parsed`), because Expat before 2.4 does not bound entity
  expansion. Other XML files with such declarations are skipped without a
  syntax warning; files without them are parsed as before.
- `docs/connectors/reference.md` is generated from the connector classes
  (`python -m tools.connector_reference`, checked by the docs consistency
  tests), so documented keys cannot drift from `config_keys`.
- Development: mypy checks every tool package and the pre-commit hook runs it
  with the project's settings; ruff reports broad exception handlers (`BLE`),
  and each suppression must state its reason; CodeQL cancels superseded
  pull-request analyses; `.gitignore` covers local credentials and tool state,
  and license texts are kept byte-exact.

### October 1 discovery review corrections

- Code collection identifies declared submodules whose source has not been
  materialized and reports incomplete coverage instead of a complete empty
  result. Remote clone collection also checks the Git tree for submodule
  entries. Submodule URLs are never fetched automatically.
- Ordinary Spring AI `ChatClient` and LangChain4j `AiServices` construction,
  and standalone Java tool declarations, no longer establish an agent or
  tool-use capability. Explicit agent construction and bounded, concrete tool
  registration remain evidence.
- Import-bound source calls distinguish configured workload capabilities from
  features merely offered by their framework. Empty tool/handoff collections
  and disabled delegation no longer add those capabilities or their risk
  factors. Review changed findings and rebuild enforcement baselines.
- Authored evaluation cases now check capability labels as well as kind and
  product attribution. The frozen independent corpus and its labels are
  unchanged; these regressions do not establish fresh field accuracy, live
  tenant acceptance or independent human review.

### October 1 code.filesystem coverage and precision

- A coding-agent instruction document that links to another one in the same
  project with the same test classification (`CLAUDE.md` to `AGENTS.md`) no
  longer marks the scan incomplete. The target is scanned at its real path and
  the alias-only file name is not reported as a second agent. Links across
  projects or into and out of test paths, and directory links, stay gaps.
- Credential policy: a real-format credential under a test, fixture or
  `cassettes/` path stays a `secret` finding and now follows the project
  test-code policy: half weight, lower confidence and risk, and the
  `test-code-only` tag unless `include_tests` is set. Recorded cassettes
  capture real traffic, so such keys are downweighted, never dropped.
- A coding-agent configuration finding now needs more than an environment-variable
  or display-name mention such as `GOOSE_PROVIDER`. Config files, instruction
  documents, dependencies and code patterns such as a workflow step still
  establish it. In test paths only config files and instruction documents count
  unless `include_tests` is set.
- MCP parsing skips `*.lock.yml` and `*.lock.yaml` files (compiled agentic
  workflows) and cookiecutter `{{...}}` template paths, which no longer raise an
  invalid-MCP error. Other GitHub Actions workflows are still parsed for MCP
  servers passed as JSON step inputs (see the field scan follow-up below).
- Not changed: signatures, risk scoring and inventory labeling. Oversize
  recorded fixtures (`cassettes/`, test data) stay coverage gaps, because they
  can hold real credentials; skipping them unread is an operator decision
  through `oversize_skip_globs` (for example `*/cassettes/*`). Examples,
  templates and benchmarks are not discounted like tests, because the bundled
  corpora label their agents as real. Evidence is offline regression tests and
  corpora only; it is not a measured field precision.

### October 1 field scan follow-up

Fixes for defects found by scanning five public agent repositories (see
`archive/reviews/field-scan-2026-10-01.md`); each has a regression test.

- The JSX lexer no longer marks valid TSX incomplete. It skips explicit type
  arguments on elements (`<Select<Option> ...>`, `<Form<{ email: string }>>`),
  comments between attributes (a comment just before `>` no longer makes the
  tag self-closing), and treats `<Text>(...)</Text>` as an element
  unless the parenthesized group is followed by `=>` or a return type. In the
  field scan this removed 139 false incomplete files; unbalanced tags still
  fail closed.
- Gemini CLI's `httpUrl` is an MCP endpoint alias. Such extension manifests no
  longer make the scan incomplete, and their remote servers are reported. A
  header or env value that is only a shell-style reference (`Bearer $TOKEN`) is
  not an inline credential.
- GitHub Actions workflows that pass MCP settings to an agent action no longer
  fail strict YAML parsing on the `on:` key. Servers embedded as JSON step inputs
  are reported as MCP findings; unparseable embedded settings stay incomplete.
- `GOOGLE_GENAI_USE_VERTEXAI` no longer attributes the Google Agent Development
  Kit. It remains Vertex AI provider evidence.
- Exported workflows under test or fixture paths follow the project test-code
  policy: half weight and the `test-code-only` tag unless `include_tests` is set.
- A `setup.py` marks a project root only when it references setuptools,
  distutils or scikit-build, or calls `setup(...)`. Ordinary modules named
  `setup.py` no longer split a package into a separate project; an unreadable
  file keeps the previous behavior.
- An MCP argument assigning a file path to a credential-file variable
  (`GOOGLE_APPLICATION_CREDENTIALS=/app/key.json`), or one whose only redacted
  part repeats a variable reference from `env` (`-v ${KEY_FILE}:/app/key.json`),
  is still redacted but no longer marks the server as carrying an inline secret.
  Literal values remain inline secrets.

### Completeness, report safety and credential policy (2026-09-28)

Behavior changes to review before upgrading (see
[production](https://github.com/aisecnomad/Project-Nexus/blob/main/docs/production.md#completeness-report-and-credential-changes)):

- **Credential policy:** the scan-wide `options.allow_instance_credentials`
  now replaces `allow_instance_credentials` in every connector entry. Only
  `cloud.*` entries were replaced before, so a third-party connector's own
  entry could grant it instance-credential approval. The scan-wide value
  still goes to every `cloud.*` connector, plugins included, and now also to
  any plugin that declares the cloud surface or documents the key in
  `config_keys`; with the default `false` this only denies. Built-in
  connectors behave as before.
- **New incomplete scans (exit 3):**
  - A shared HTTP response body must arrive within twice the client timeout
    (60 seconds by default), not only within the 30-second per-read timeout.
    A slower body, for example from a slow-drip server, is aborted (`HTTP
    response exceeds the read deadline`) and the connector's collection is
    incomplete, never truncated.
  - `code.filesystem` opens each scan root once and reads every file, and
    `CODEOWNERS`, relative to it without following a link in any path
    component; before, only the final component was protected. A directory
    replaced by a link during the scan fails the reads below it
    (`file could not be read`). A root that cannot be opened this way is
    reported, by its `label` when one is set, as
    `could not open the scan root safely (<reason>)`.
  - `code.gitlab` skips a group listing entry whose project `id` is not a
    positive integer (`group project listing entry has no valid numeric id;
    project skipped`) and scans the other projects. Such an id used to reach
    request paths, where it could send the token to another API endpoint,
    and a missing id aborted the whole listing.
  - `code.github` skips an org or user listing entry whose `full_name` is not
    a plain `owner/name` (`repository listing entry has no valid owner/name;
    repository skipped`). It used to reach request paths and the clone URL.
- **Changed diagnostics (these scans were already incomplete):**
  - A YAML value PyYAML cannot construct, such as an impossible date or an
    integer over 4,300 digits, is reported as malformed YAML: `invalid YAML`
    for conda environment files (was `manifest parsing failed (ValueError)`)
    and `invalid agent definition YAML` for agent front matter (was
    `file analysis incomplete (ValueError)`). The agent definition is now
    listed where it used to be dropped, which adds `agent_definitions`
    metadata and can raise the finding's risk score. Scan configuration and
    inventory files with such a value still fail at setup (exit 1), now with
    `ConfigValidationError` and `InventoryValidationError` instead of an
    unclassified `ValueError`.
  - A cancellation or connector deadline while `code.filesystem` builds a
    credential finding ends the connector, as it does everywhere else,
    instead of becoming that file's `credential analysis incomplete` error.
- **Scans that now complete:**
  - A Python module none of whose imports can resolve to a signature no
    longer makes a scan incomplete when it exceeds `max_ast_nodes` or the
    import binder's nesting limit: the binder, which could add no evidence
    there, is skipped. The check is linear in the module and matches at most
    4,096 distinct import statements; other modules keep the
    `import-bound analysis skipped (…); lexical evidence retained`
    diagnostic. A scan of installed libraries such as mypy, pip, requests and
    rich, which exited 3 because of `mypy/checker.py`, now completes.
  - Configuration, inventory, signature pack, `diff` report and offline
    export files below a traverse-only directory (mode `0711`) now open:
    directories are opened for traversal only (`O_PATH` on Linux), not for
    reading.
  - An unrendered Helm, Jinja or Go-template YAML file, whose placeholders
    read as mapping keys (`image: {{ .Values.image }}`) or whose conditional
    branches repeat a field, no longer reports `structured parsing incomplete
    (YAMLIntegrityError)`. Such a file is not YAML until rendered, so its
    excerpts use lexical redaction, as for any template the YAML parser
    rejects. Plain YAML with duplicate or non-finite data still fails closed.
- **Report redaction** withholds more credential forms, in excerpts and in
  structured connector metadata. Expect more `[REDACTED]` markers:
  - string literals passed to credential constructors, helpers and factories
    (`AzureKeyCredential("…")`, `HTTPBasicAuth("user", "…")`,
    `Credentials.basic`, `setBearerToken`, `WithAPIKey`, `cohere.Client`),
    including Rust `::new("…")`, C# target-typed `new("…")`, calls down a
    builder chain (`builder().apiKey("…")`, `.header("x-api-key", "…")`) and
    `auth=("user", "…")` tuples;
  - literal defaults of credentials read from the environment
    (`process.env.OPENAI_API_KEY || "…"`, `?? "…"`, `or "…"`, `?: "…"`,
    `${OPENAI_API_KEY:-…}`);
  - credential command-line options: `--api-key`, `--token`, `--password`,
    `--key` and `--pwd`, also in argv lists; `curl -u` and
    `-H "X-Api-Key:…"`; `-p` after `docker login`, other registry logins and
    `az`, `oc` or `cf` logins; `sshpass -p`; MySQL `-p…`; a literal echoed
    into `--password-stdin`; and `dotnet user-secrets set NAME VALUE`;
  - Dockerfile `ENV`, `setx`, `setenv`, C `#define`, PowerShell and TOML
    quoted keys assigned with `=`, and R `<-`;
  - XML key/name attributes, element names and name/value records, read as
    .NET settings by their last `:`, `__` or `.` segment as well as whole
    (`<add key="OpenAI:Secret" value="…"/>`, `- name: AzureOpenAI__Key`). In
    structured metadata the value is also removed from the record's other
    fields;
  - an opaque-looking value under a name whose last word, ignoring trailing
    digits, names a credential (`openaiKey`, `key`, `KEY1`), and a lone
    opaque value on the unindented line after a sensitive key;
  - more token prefixes: Google `ya29.`, `1//0` and `GOCSPX-`; Slack `xapp-`
    and `xoxe`; the GitLab `glrt-` family; `npm_`, `pypi-` and `dop_v1_`;
    and Stripe, SendGrid, Databricks, Shopify, Atlassian, Linear, Notion,
    Postman, Doppler, Supabase, Grafana, Sentry, Vault and Terraform Cloud
    tokens. `Ocp-Apim-Subscription-Key` and names ending in
    `subscriptionKey` are credentials.

  A C# `new AzureKeyCredential("<key>")`, a Java `builder().apiKey("<key>")`
  or a web.config `<appSettings>` key used to reach the reports of a complete
  scan; regenerate such reports and rotate the keys they show. Endpoint URLs,
  model names, variable names and references, placeholders and ordinary
  values (`<add key="CacheKey" value="users"/>`) stay visible. SECURITY.md
  lists the forms that are still not withheld, among them a space or comment
  before a call's parenthesis, redundant parentheses, C# interpolated and
  multi-line triple-quoted strings, one-letter options, a query parameter
  outside a URL and an unquoted value that reads as an identifier.
- **Redaction fixes:** a YAML parent key such as `openai:` no longer takes
  the next line as its value, which leaked a nested `api_key: <value>`. A
  `Bearer`/`Basic` scheme before a line break no longer drops a line from
  the excerpt, and a marker inside an unquoted value no longer gains a `]`
  each time a report sanitizes it again. Redaction is linear on hostile
  layouts that used to time out, exhaust the redaction budget or hang the
  scan without marking it incomplete: long runs of unfinished annotations,
  minified lines with thousands of sensitive keys, and long unquoted values
  after `key=`. Expressions nested more than 100 brackets deep are withheld
  through the end of the excerpt, and an unquoted word holding more than 16
  command-line options is withheld from its 17th option on.
- **Finding identity:** IDs are computed from sanitized resource fields, so
  an ID changes only where such a field held a value that is now withheld.
  These redaction rules leave the findings and IDs of the demo, the sample
  repository and every evaluation corpus unchanged; the classification
  corrections of September 27 below can still change findings. The redaction
  policy token changed, so findings verified clean under the old rules are
  sanitized again. Report sanitization takes about 28% longer (11 s to 14 s
  for 19 MB of library source).
- **Reports:**
  - CSV also inserts the `'` marker after a `,`, `;`, tab, `|` or line break
    inside a value when a formula could start there (OWASP CSV injection), so
    a report opened with another delimiter cannot create a formula cell.
    Leading no-break spaces and double quotes no longer hide a trigger.
    Consumers that strip only a leading `'` must strip these markers too, or
    read `json`.
  - Markdown writes `@` as `[@]` in untrusted text, like the existing
    `hxxp://` and `www[.]` defanging, so a pasted report no longer
    @-mentions users or teams or links e-mail addresses. Code spans stay
    verbatim.
- **Plugins and embedders:**
  - `shadowscan.utils.text.sanitize_record` is removed; call
    `shadowscan.utils.redaction.sanitize`.
  - `HttpClient.paginate_cursor` is removed; paginate explicitly. The Slack
    and Notion connectors keep their own cursor pagination.
  - The engine no longer names connectors. Per-root incremental caching, the
    instance-credential approval and the per-run gateway identity key are
    hooks a connector class declares (`cache_roots_separately`,
    `inherits_instance_credentials_approval`, `uses_run_identity_key`; see
    `docs/architecture.md`). Offline export parsing moved from
    `BaseConnector` to `shadowscan/connectors/offline.py` with
    `BaseConnector` names unchanged, and duplicate-finding metadata merging
    to `shadowscan.connectors.common.merge_duplicate_metadata`.
  - `shadowscan.utils.redaction` is split into `redaction_*` modules with the
    same public API and rule names. Patch rules through
    `shadowscan.utils.redaction`, never through a `redaction_*` module;
    `policy_token()` covers every module.
  - `SignatureIndex.signals_of_type(kind)` returns the (signature, signal)
    pairs of one signal type in pack order.

Development:

- ruff enforces line length (E501, 110 columns) outside `tests/` and
  loop-variable capture in closures (B023) everywhere. mypy requires
  annotated definitions (`disallow_untyped_defs`) and reports unused
  `type: ignore` comments (`warn_unused_ignores`). Only `regex`, `boto3`,
  `botocore` and `oci`, which ship neither stubs nor a `py.typed` marker, may
  be imported untyped.
- Unit tests live in files named after the module or feature they exercise,
  not the review round that added them; test bodies are unchanged.
- The evaluation, benchmark, canary and acceptance tools resolve the temporary
  directories they create before handing paths to the scanner, so they pass on
  macOS, where `/var` and `/tmp` are links into `/private`. The symbolic-link
  checks on untrusted input are unchanged.
- `docs/testing.md` describes the development environment, the offline suite
  and every `make` gate CI runs. `docs/maintainer-onboarding.md` is a reviewer
  and co-maintainer checklist, and `GOVERNANCE.md` has reviewer,
  co-maintainer and offboarding sections.
- `code.github` and `code.gitlab` share one implementation
  (`shadowscan/connectors/code/remote.py`), and the four cloud connectors
  share one offline-record dispatcher and audit-caller aggregator. New
  offline exports cover every GCP and OCI record kind, raising line coverage
  of `cloud/gcp.py` from 78% to 99% and of `cloud/oci.py` from 88% to 99%.
  The scanning commands share one option decorator; options, defaults and
  help are unchanged.
- Consistency tests check that documents describing CSV markers name every
  separator the reporter marks, and that the documented HTTP read deadline
  matches the client.
- Documentation: ADR-003 has a dated amendment recording the implemented
  confidence and risk formulas, and `docs/concepts/risk.md` matches the
  code. The cloud connector guide lists each connector's offline `_kind`
  values, and the architecture guide the engine hooks.

### September 28 repository hygiene

- The DCO check accepts Dependabot's app-authored commits with GitHub's fixed
  `support@github.com` sign-off, and only that pairing; every other commit
  still needs a sign-off matching its author or committer.
- CodeQL, Scorecard and the operator example workflow use `github/codeql-action`
  4.38.2 in every step, and Dependabot groups GitHub Actions updates so
  sub-actions of one repository move together instead of failing analysis with
  mixed versions.
- The development toolchain moves to ruff 0.16.9 with the regenerated hash
  lock and the matching pre-commit revision.

### September 27 review follow-up

- Opaque values nested under a sensitive credential container are now remembered
  before that container is redacted. Repeated values in sibling report fields
  and optional record exports are redacted too; descriptive provider and status
  fields remain available. Report and export regressions cover the boundary.
- GitHub and GitLab clones now check observed local checkout size during the
  clone and after Git exits, in addition to the provider size preflight. A
  measurement failure or exceeded cap stops the Git process group and leaves
  the scan incomplete with sampled API fallback. Sampling may overshoot and
  does not limit network bytes; use a worker disk quota for a hard ceiling.
- The evaluation runner supports explicit checks for expected and forbidden
  finding kinds, product signatures and model providers, with counts separated
  from the one-target binary accuracy result. Selected authored cases now
  guard against attribution noise; they do not establish field accuracy.
- Contributor and governance guidance now describes the configured pull-request
  approval and required-status rules, with dated observations of their changing
  enforcement state. The dated assurance report identifies its historical corpus
  count separately from the current corpus.

### September 27 review corrections

- Offline exports, approval inventories, imported reports, repository manifests,
  notebooks, agent/MCP configuration and other scanned JSON, JSONC and YAML
  reject duplicate or non-finite data. Rejected input makes collection
  incomplete instead of establishing absence; valid neighboring evidence is
  still retained.
- Structured projections reject conflicting schema aliases; CSV headers reject
  case-folded collisions; and conflicting provider records for the same logical
  Teams, Slack, Entra, Power Platform or Salesforce identity are quarantined
  without discarding valid neighbors. Azure pagination likewise refuses
  disagreeing continuation aliases.
- Generic graph and flow construction no longer establishes an agent by itself.
  Disabled, empty or schema-only tool options do not establish model-directed
  action execution. Source capabilities require corresponding evidence rather
  than inheriting every feature of an imported framework.
- CI exposes a single `CI gate` covering documentation, every supported Python
  version, the container checks, and DCO on pull requests. The repository ruleset
  must require that check; workflow code alone does not configure branch rules.
- Size-scaled source matching gives files near a 256 KiB budget boundary the
  next bounded time slice, avoiding scheduler-sensitive false incompleteness
  without weakening the fail-closed timeout behavior.
- The Python distribution is now `project-nexus-shadowscan` to distinguish it
  from the unrelated PyPI package. The `shadowscan` command, import namespace,
  entry-point group and report schemas retain their names. No package is
  published or namespace reserved by this change.
- Built-in connector options now use one fail-closed schema for YAML and
  programmatic configuration. Boolean aliases are normalized explicitly,
  ambiguous values and unknown/reserved built-in keys are rejected, later
  mutations and nested risk policy are revalidated before collection, and
  plugin-owned configuration stays schema-opaque while still rejecting cycles,
  excessive nesting and non-finite values.
  Configured inventory is reloaded on every run so the first execution cannot
  reuse an approval snapshot captured during engine construction.
- Shared JSON input rejects duplicate keys and non-finite values. JSON and
  SARIF publication refuses `NaN`/infinities. HTML/CSV sent to a terminal makes
  control and bidirectional-formatting characters visible, while explicit
  output files retain their serialized values. Reporter boundaries sanitize
  copied diagnostics, tolerate malformed related-finding metadata and preserve
  valid SARIF paths without treating provider resources as source locations.
- Incremental cache work now observes connector cancellation/deadlines, refuses
  `.git` indirection for Git-aware reuse, binds fingerprints to runtime/parser/
  Git versions, bounds tree traversal, and applies TTL, aggregate size/count,
  deterministic eviction and stale-pending/orphan-lock cleanup policies. Startup
  maintenance has a fixed two-second monotonic budget and disables reuse for the
  run when it expires. Lock acquisition verifies pathname identity after `flock`
  so cleanup cannot split one cache slot across stale and replacement lock inodes.
- Google Workspace domain-wide delegation strictly parses service-account JSON
  and pins both the signed assertion audience and token exchange to Google's
  HTTPS token endpoint; a key file cannot redirect the assertion.
- CI core/development tooling is now exact-versioned and SHA-256 hash-locked on
  Linux and macOS. All runtime, build, CI and documentation locks are audited.
  Pre-commit repositories use immutable commit SHAs and their additional type
  stubs are exact-pinned. Supported Python is explicitly 3.11 through 3.13.
- Release evidence now refuses a dirty checkout, builds from a clean archive,
  and assembles the exact attested wheel and bundles as a non-publishing
  `release-publication-input-<SHA>` artifact. The runtime SBOM remains a Python
  dependency SBOM, not a container/operating-system SBOM; no hermetic apt or
  package-index publication claim is made.
- Regenerate discovery baselines after adopting these classification and
  capability corrections. Fresh human-labeled holdouts, live tenant acceptance,
  independent release review and hosted artifact attestations remain separate
  release requirements; regression results do not supply that evidence.

### Self-graded audit follow-up

Fixes from an internal, AI-assisted grading pass over the repository; each
has a regression test.

- The registry's inventory scope-matching no longer hardcodes a single
  `google-workspace` string check to decide whether a card must list
  `accounts` before a resource pattern can approve a finding. The same
  requirement is now driven by
  `shadowscan.utils.identity.PROVIDERS_REQUIRING_CARD_ACCOUNT_SCOPE`, a single
  extensible set instead of a hand-patched exception repeated at three call
  sites (`Inventory.match`, `Inventory._scope_matches`, `card_stub_for`).
  Behavior for existing providers (AWS, Google Workspace, and every other
  built-in connector) is unchanged; adding the next provider that needs this
  protection is now a one-line addition to that set.
- `cloud.gcp` and `cloud.oci` test coverage now exercises the Cloud Function
  plaintext-secret handler, the Vertex endpoint and Discovery Engine
  handlers, the Cloud Audit Logs pagination edge cases (empty-token
  termination, repeated-token detection, invalid responses, transport
  failures), the instance-credential transport's redirect refusal and
  30-second timeout bound, and the three OCI GenAI resource handlers
  (dedicated endpoint, dedicated cluster, knowledge base) that had none.
  Both connectors were previously below the project's 75% per-connector
  coverage floor.
- `tests/test_repository_consistency.py`'s connector-count check now fails
  loudly (matching its signature-count sibling) if no doc states the count
  in bold, instead of silently matching zero times forever; README now
  states it (`**27 connectors**`).
- `docs/connectors/cloud.md` (the per-surface page reachable from the site
  nav) no longer omits the GCP pagination/audit-log page-cap sentence that
  `docs/connectors.md` documents; a regression test checks the two stay in
  sync on this point.
- `utils.output._require_private_pipe` now requires a named pipe's mode to
  be exactly `0600`, matching its own error message and the CHANGELOG's
  "Report output safety" description, instead of accepting any mode with no
  group/other bits (e.g. `0700`).
- `SetupError` now redacts its own message through the same sanitizer used
  for scan diagnostics, instead of relying on every call site to have
  hand-built a credential-free message; existing call sites that already do
  so are unaffected since sanitization is idempotent.

### Field-review follow-up

Fixes from the review of the field-review series; each has a regression test.

- A structured configuration the parsers refuse for nesting depth or XML
  entity expansion keeps the scan incomplete (exit 3) again. The series had
  reported it as a syntax warning outside coding-agent settings, so such a file
  hid its workflow evidence behind a complete scan.
- JSONC stripping is linear again: an unterminated string full of escaped
  quotes made it quadratic, so one small file could exhaust the scan deadline.
- The import-statement cache keeps only statements up to 256 characters,
  within 4 MiB of statement text, instead of any statement up to 65,536
  entries. Module names come from scanned code and the index lives for the
  process.
- GitHub Apps match their slug's words as well as the slug, so
  `amazon-q-developer`, `ellipsis-dev`, `mentatbot` and `factory-droid` are
  recognized again instead of dropping out of complete scans.
- `boto3.client(service_name="bedrock-agent-runtime")` and the AgentCore
  clients corroborate `invoke_agent` like the positional form.
- An MCP server keeps the capabilities its code implies when no tools were
  recognized, so a FastMCP shell tool registered with `@mcp.tool(description=...)`
  is `code-exec` again. Tools registered only in tests imply no capabilities.
- MCP enum tool names are found in one pass instead of one text search per enum.
- Documentation: the GitHub Apps rollout note lists the risk changes, the code
  and GitHub Apps connector options are documented, and the evaluation guide
  runs the field-review corpus.

### Report output safety

- A report path that already exists as a character device, such as
  `-o /dev/null`, is now written in place. Previously the report writer renamed
  a private temporary file over it, which, when run as root, replaced the
  system's `/dev/null` with a regular file. An existing named pipe is written
  in place only when the current user owns it with mode 0600 and a reader
  already has it open; otherwise the write fails at once instead of waiting.
  Sockets, directories, block devices and other non-regular paths are refused.
  Regular files are still replaced atomically with mode 0600, and symlinks are
  still refused. This covers `--output` for scans, the canary runner and the
  acceptance verifier, and the inventory stub and record-export manifest
  writers.

### Repository hygiene

- Every documentation page is reachable from the site navigation: the ADRs,
  the tenant canary guide and the 2026-09-24 assurance results were built but
  unlisted. A consistency test now fails on any page missing from the nav.
- Ruff enforces six more rules (`B007`, `B008`, `B034`, `C416`, `E741`,
  `SIM113`) after fixing their few violations: unused loop variables, a
  hand-maintained counter, a redundant comprehension and ambiguous `l` names.

### Type checking and lint coverage

- `mypy` runs with `warn_return_any` and `warn_unreachable`, and ruff's `B904`
  and `UP028` rules are enabled. The sites they reported are fixed at the
  source: untrusted API rows are typed as such so their guards are reachable,
  the AWS manual pagination path no longer runs inside an exception handler,
  and a GitLab variable shadow that hid a dead branch is renamed. The
  `pip install -e ".[dev]"` suite skips the two boto3-only tests without the
  AWS extra.

### Field review of public repositories (2026-09-25)

Behavior changes to review before upgrading (see
[production](https://github.com/aisecnomad/Project-Nexus/blob/main/docs/production.md#field-review-changes)):

- **Finding identity:** a CrewAI `agents.yaml` or `langgraph.json` inside a
  reported project is folded into that project's finding (listed under
  `metadata.manifests`) instead of a second agent finding. `diff` reports the
  former manifest findings as resolved. A2A cards and M365 declarative agents
  stay separate findings.
- **GitHub Apps:** an installation needs an AI signature or an AI-like name,
  whatever its permissions, so read-only apps with an AI-like name are now
  reported as well. Apps with neither, such as Renovate or Dependabot, are no
  longer reported unless `include_unrecognized_apps: true`, which caps them at
  possible confidence. A separate word "bot" in the slug (`changeset-bot`)
  still counts as an AI-like name. Only `workflows` or `actions` write access
  implies `code-exec`, so an app with only `contents` or `pull_requests` write
  access loses it and can drop a risk level (critical to high for the Claude
  app).
- **Scan completeness:** a syntax error in a configuration file that is not
  coding-agent settings (`.claude`, `.codex`, `.gemini`) is a warning; lexical
  checks still read the file. `strict_coverage` keeps it incomplete.

Fewer false incomplete scans:

- Structured configuration accepts JSONC (VS Code settings, dev containers,
  tsconfig) through a shared, faster lenient loader (`shadowscan.utils.jsonc`).
- A Python module over the AST budget keeps its lexical evidence and is reported
  as partially analyzed: a warning in test code, an error elsewhere. New
  `max_ast_nodes` option (default 50000).
- Notebooks whose saved outputs exceed `max_file_size` have their code cells
  analyzed up to `max_notebook_size` (default 20 MiB) instead of being skipped.
  Their outputs are not scanned for credentials at that size, which leaves the
  scan incomplete unless `scan_secrets` is off.

Precision and recall:

- Code signals accept `ambiguous: true` for identifiers common outside the
  product. Such matches count only with an import, dependency or specific code
  pattern of the same signature in the project. Applied to `ClientSession(`
  (aiohttp), `AgentCard(`/`AgentSkill(`/`DefaultRequestHandler(` (A2A),
  `invoke_agent(`/`invoke_flow(` (Bedrock Agents), `create_agent(model=`,
  `AgentsClient(`, `OpenApiTool(` (Azure AI Foundry), `CopilotClient(`
  (Copilot Studio) and `Exa(`/`GoogleSearch(`/`WebSearch` (web search tools).
- The cap on uncorroborated lexical evidence in languages without the import
  binder applies to every signature category, not only frameworks.
- On a host shared with another product and not named for MCP
  (`api.githubcopilot.com`), the URL path decides: `/mcp` or `/sse` is MCP.
- Provider tool loops are recognized with raw-response, streaming and
  helper-function requests.
- MCP server capabilities come from the tool names the server registers
  (`metadata.mcp_tools`). Test-path evidence adds no capability unless the
  project is only tests, and vendor-neutral idioms add none to an MCP server.
- Findings with only supporting technology are titled `AI tooling`.
- New `tools/evaluation/field_review_corpus.json` (8 synthetic cases) in
  `make evaluate`.

Performance:

- Regex signal passes select candidate patterns with one scan over their
  required literals instead of a per-pattern check, synthesized import
  statements are matched once per index, and unresolved imports skip a code
  pass whose results were discarded. Findings are unchanged.

Development:

- `pip install -e ".[dev]"` runs the whole suite: boto3 tests skip without the
  AWS extra, and the dev extra includes setuptools and wheel.
- Internal AI-assisted review logs move from `docs/` to `archive/reviews/`.

### Coverage and release verification follow-up

- Mark unread oversized source and configuration files and outward or unresolved
  symlinks as incomplete even without `strict_coverage`; the flag elevates the
  diagnostic from a warning to an error. Declared generated-file omissions in
  `oversize_skip_globs` remain visible warnings.
- Treat in-root directory symlinks, and file links to excluded or otherwise
  unread targets, as incomplete instead of assuming alias content was scanned.
  Links whose own names are never read (lockfiles, generated bundles, images)
  and source aliases analyzed in the same project with the same test
  classification stay complete.
- Treat malformed or mismatched explicit GitHub/GitLab repository responses and empty GitHub/GitLab
  offline clone inputs as incomplete scans instead of complete empty results.
- Compute the signature-set digest once per incremental scan run instead of
  reserializing it for every input snapshot; changes between runs still invalidate
  the cache.
- Accept GitHub's actual workflow-run path in the release evidence gate and
  require successful exact-commit CI and CodeQL before building a candidate.

### Scanner boundaries and acceptance consistency

- Redact the value of any call whose first argument, or `key=`/`name=`
  argument, is a literal credential key (`os.getenv("API_KEY", "...")`,
  `settings.get("password", ...)`) before publishing source evidence. The
  bounded lexer reads `#` and `//` as text when a comment reading cannot close
  a call, so prose such as `(#123)`, Python floor division and JavaScript private
  fields pass through unchanged. A credential call whose value cannot be
  bounded withholds the excerpt and marks the scan incomplete.
- Keep repository-connector exception logging free of raw exception payloads.
- Bind Google Workspace observations and registry approvals to an immutable
  customer identity. Unresolved identities remain visible for investigation but
  cannot establish approval or complete collection. **Operator action:** grant
  the audit identity `admin.directory.customer.readonly` before live
  collection; `customer` must be `my_customer` or a concrete `C…` ID (a domain
  is rejected at startup); offline scans need the verified `customer` or stay
  incomplete. Unresolved findings keep stable IDs per input or admin account.
- Preserve unresolved Entra permission evidence. Grants or role assignments
  whose service principal is missing, and principals exported with conflicting
  records, become `unresolved-principal` findings that report no type,
  publisher or first-party status.
- Reject contradictory AWS account envelopes: several or invalid `account`
  records, or a resource ARN from another account, leave short identities
  unresolved and the scan incomplete. An offline `account_id` that disagrees
  with the export's account record no longer silently wins.
- Require usable identity for n8n workflow observations; blueprints without an
  ID, including YAML exports, keep their evidence under an unresolved identity.
- Remove the duplicate lexical agent-promotion path. Provider dispatch findings
  must pass source-semantic provenance checks and the configured test-code policy.
  Python single dispatch is recognized whether its result is kept, discarded or
  returned. JavaScript recognition stays deliberately narrow (a small, complete
  top-level program): JS/TS files that the lexical path promoted, such as a
  dispatch inside a function or code without semicolons, now report
  `framework-usage`. Review their findings before relying on agent counts.
- Share source-overlap validation between the holdout acceptance tools so repeated
  examples cannot inflate sample counts or statistical confidence.
- These changes require fresh finding baselines and acceptance evidence. Offline
  regressions do not establish independent human review or live tenant acceptance.

### Markdown report safety

- Defang bare HTTP(S) and `www.` URLs in untrusted report text so copied Markdown
  does not automatically turn attacker-controlled values into clickable links.

### Supported-platform preflight

- Every `shadowscan` command now fails closed, with a clear error, on a host
  that cannot enforce the documented path confinement (Windows, or a platform
  without `O_NOFOLLOW`); `--help` and `--version` still work everywhere.
  `shadowscan.utils.platform.require_supported_platform()` performs the same
  check for embedding callers. `redact` in `shadowscan.utils.text` stays as
  a documented compatibility alias. `sanitize_record` was removed later in
  this release; call `shadowscan.utils.redaction.sanitize`.

### Community policy consistency

- Add a documentation issue form, keep detection reports and private security
  reports on their existing routes, and document safe vulnerability report inputs.
- Hash-lock the documentation toolchain, align local hooks with CI tool versions,
  and scope CodeQL and stale-triage write permissions to their jobs.
- Validate workflow and issue-form safety policies. Label synchronization creates
  or updates declared labels without deleting labels; inactive issues and pull
  requests remain open for maintainer review.
- `tests/test_repository_consistency.py` (run by `make policy`) fails CI when a
  relative Markdown link or heading anchor is broken, a community file is
  missing, `CITATION.cff` disagrees with `pyproject.toml`, the CI matrix
  differs from the classifiers, the Makefile or pre-commit hooks drift from the
  CI gates, the docs toolchain is installed outside its lock, CodeQL steps are
  pinned to different releases, or a documented signature, signal or connector
  count is stale. The CI docs job now installs from `requirements-docs.lock`;
  the install guide states that CI validates Python 3.13; the detection quality
  report asks for the signature involved and a sanitization acknowledgement;
  README's community table links the detection form, maintainers, roadmap,
  changelog and citation.
- A verified repository hygiene audit fixed the drift it found. Pre-commit: the
  secret hook used `types: [python, yaml]`, an AND filter that selected no file,
  so it had never run; it now uses `types_or`, recognises current OpenAI and
  Anthropic key formats and excludes the tests that hold synthetic tokens;
  `check-yaml` skips `mkdocs.yml`, whitespace fixers skip fixtures and the
  digest-bound retained licenses, and `detect-private-key` skips the redaction
  tests, so `pre-commit run --all-files` passes. The `pre-commit` dependency
  closure is pinned in `requirements-ci-constraints.txt`. Documentation: the
  production guide, constraints header and contributor guide state that Linux
  x86_64 is the only validated target, that Python 3.11 to 3.13 are all
  covered, that Windows is unsupported by design, and that the `main` ruleset's
  enforcement has changed during 2026-09 and must be checked live; the quick
  start no longer mixes a live code connector with credentialed tenant
  connectors in one configuration; the replay example uses the exported
  filename; the risk table, GitLab per-file cap (512,000 bytes), default
  `max_file_size`, evaluation corpora count and code connector modes match the
  code; two hardening logs no longer describe same-author passes as independent
  reviews and the two remaining 2026-09-24 review documents carry the internal
  work-log banner. Packaging: PEP 639 `license = "Apache-2.0"` with
  `license-files`, and the `Operating System :: POSIX :: Linux` classifier
  replaces `OS Independent`. Examples: the consumer workflow pins
  `upload-sarif` to a commit rather than a tag object and grants `actions:
  read` for private repositories. HTML report: sorting and evidence drill-down
  are real buttons reachable by keyboard with `aria-expanded`/`aria-sort`, the
  filters have accessible names, the result count is a live region, an `info`
  tile is shown, and pill and light-scheme colors meet WCAG AA contrast. The
  bug report form asks for the full commit SHA and describes exit codes
  accurately; the CSV reporter's formula-quoting is documented in README.

### Private holdout and CLI job deadline gates

- Reject bundled corpora and AI annotation ledgers from holdout acceptance;
  validate the human-review declaration used for the actual evaluation and read
  acceptance policies and annotations with bounded, symlink-free file access.
- Add optional `--job-deadline-seconds` / `options.job_deadline_seconds` for CLI
  scans. The cancellable process watchdog exits `3` when setup, scanning or output
  exceeds the deadline; external process supervision remains required.
- Start an explicit CLI deadline before reading JWTs from stdin, so an open,
  silent input pipe cannot hold the process past its configured deadline.

### Follow-up trust-boundary review (2026-09-24)

- Reject duplicate fields and nonfinite numbers in provider API JSON before
  interpreting collection, pagination or signing-key data.
- Mark offline Slack cursors and AWS truncation markers incomplete, retaining
  observed records while refusing a clean result for uncollected pages.
- Require intact, unambiguous code identities and recognized caller assurance
  before attaching runtime activity; clear stale derived observations.
- Sanitize imported findings before publishing report comparisons and require
  explicit, matching connector completion evidence before resolving findings.
- Render terminal control characters visibly in untrusted CLI display values.
- Bound evaluation corpus reads, reject the reserved aggregate family name,
  and bind annotation checks to the exact corpus snapshot being evaluated.

### Control-assurance fixes (2026-09-24)

- Redact long sensitive assignment keys before source evidence enters JSON or SARIF; bind Power Platform Dataverse token audiences and destinations to validated organization origins.
- Preserve valid neighboring provider records while marking provider errors, malformed Slack responses, missing collections and invalid pagination incomplete.
- Reduce generic-code false positives, recognize OpenAI Responses function dispatch, and fail closed on ambiguous source masking.
- Bound remote clone time, preflight provider repository size, avoid cloning when a usable size estimate is unavailable, terminate clone descendants on cancellation, remove partial checkouts and mark API fallbacks incomplete.
- Add a frozen holdout acceptance gate, tenant canary procedure, safer contributor guidance and a GitHub Action example. Field accuracy still needs independent review and live canaries.

### Scanner assurance and release evidence (2026-09-25)

- Preserve observed ServiceNow native agents if optional name or OAuth
  signature matching times out, mark coverage incomplete, and skip repeated
  matching for remaining records.
- Keep YAML manifest artifact matching within its existing one-second shared
  deadline during parallel scans, while allowing a chunk the manifest pattern
  budget; exhausted deadlines still make coverage incomplete.
- Recognize import-bound OpenAI Responses API function loops only when the
  model-selected call is dispatched and its result returns in the next request
  with matching call identity. Unreachable literal branches and locally
  shadowed execution names no longer establish provider tool loops.
- The offline acceptance verifier excludes previously evaluated source snapshots,
  validates the evaluator's known-gap report, and supports frozen per-kind
  sample and error limits. Its operator declarations still require independent
  human review and real tenant validation before rollout.
- The release candidate workflow binds a successful exact-commit main CI run
  to a wheel, hash-locked runtime and build dependencies, SBOM and retained
  provenance. The reviewed container base and consumer CI example are pinned;
  the workflow does not publish a package or authorize deployment.

### Detection precision, coverage policy and risk explainability

Behavior changes (review before upgrading an enforcement gate):

- Oversize files and symbolic links leaving the scan root are skipped with a
  warning instead of making the scan incomplete. `strict_coverage: true` /
  `--strict-coverage` restores the previous fail-closed behavior. Links that stay
  inside the scan root no longer affect coverage in either mode.
- Evidence found only in test or fixture code no longer establishes an agent
  (half weight, `test-code-only` tag); `include_tests` / `--include-tests` opts out.
- Project findings built only from evidence already reported by an MCP config,
  agent manifest, exported workflow, IaC or credential finding are no longer
  emitted as duplicates.
- Signature-level capabilities are narrower: LangGraph no longer implies memory,
  the OpenAI Agents SDK implies multi-agent only with hand-offs, and Bedrock
  AgentCore memory, code interpreter and browser come from their own resources.

Fixes and additions:

- The Python/JavaScript import binder counts only calls into modules that a
  signature describes. Ordinary large files (e.g. psf/requests' test suite) no
  longer fail with `source binding call limit exceeded`; diagnostics now include
  the scanner's own limit message.
- Provider SDK requests that pass tools (`tools=`, `toolConfig=`) record
  import-bound tool-use capability and provider attribution. The agent verdict
  still requires the model-selected dispatch and feedback loop, which is now
  recognized for Anthropic `messages.create` as well as OpenAI chat
  completions, including process or code execution sinks fed with the model's
  tool input, collected `tool_result` lists and dispatch inside `if` branches.
  Anthropic, OpenAI, Bedrock Converse and Gemini tool-call shapes are matched
  when written as dict keys or compared strings; loop checks accept `!=` as
  well as `==`.
- Shell, process and dynamic-code sinks count as code execution when the same
  file invokes a model, framework or tool-calling protocol.
- Model providers are attributed through LangChain, LlamaIndex and Vercel AI SDK
  integration packages and n8n model nodes (18 providers), and through model IDs
  declared in IaC. IaC projects with wildcard IAM statements are tagged
  `wildcard-permissions`.
- Placeholder credentials (repeated characters, marker words such as `EXAMPLE`,
  very low character diversity) are ignored; Azure OpenAI keys are recognized by
  their standard variable name. MCP inline-secret evidence names its location.
- Risk factors always add up to the score (explicit `confidence-scaling` and
  `bounds` factors). New `risk.danger_score` excludes governance factors;
  `options.risk_basis` (`combined` | `danger`) and validated `options.risk_weights`
  configure the model.
- Tests that need optional cloud SDKs or Git 2.45+ skip cleanly; the container
  base moves to Debian 13 (Git 2.47) and the build fails if Git is older than 2.45.

### Quality, precision and governance pass (2026-09-24)

#### Security

- Third-party connectors are verified when loaded: the class must be a concrete `BaseConnector` subclass whose `name` equals its entry-point name and is not a built-in name or namespace; violations fail closed with `PluginRegistryError`, and `plugin_registry_errors()` returns structured, credential-free diagnostics that the CLI now prints.
- The container build installs the build backend from the hash-locked `requirements-build.lock` with `--no-build-isolation`, pins the base image by digest (refreshed by a Dependabot `docker` entry), and admits only source, packaging and signature files into the build context.
- `Finding.from_dict` rejects malformed report shapes (non-object metadata, non-string list items, non-boolean `shadow`, evidence or risk factors without string identifiers) at the import boundary instead of failing later inside a scan.
- The two diverged copies of the `O_NOFOLLOW`/`dir_fd` offline-file open sequence are replaced by one confined helper in `shadowscan.utils.files`, with tests that both callers refuse symlinked components and special files and enforce their byte limits.

#### Detection

- Signature packs grow to 211 signatures and 912 signals (local inference, guardrails, Chinese-market providers, 2025 agent SDKs, more AI SaaS identity apps). The OpenAI secret regex is shape-specific and no longer claims Langfuse, LiteLLM or OpenRouter keys; dictionary-word display names match only with product context; two vendor misattributions are corrected; code idioms shared by competing frameworks move to heuristic signatures; the Azure OpenAI model pattern requires Azure context; `langchain-text-splitters` is a non-agent utility signature; and LangChain keeps prefix matching for every partner package through the new `exclude_names` / `exclude_prefixes` dependency fields.
- The signature validator enforces ecosystem, language and capability vocabularies, per-signal uniqueness, positive weights, non-empty-match patterns, balanced globs, id-namespace-to-category mapping and cross-signature duplicate regex detection. Custom packs that violate these rules now fail to load.
- Placeholder-looking provider keys (`REPLACE_ME`, `<your-key>`, repeated or sequential characters) become low-weight `example-credential` evidence instead of high-risk secret findings; the check is applied per matched key across filesystem, `.env`, MCP, cloud and blob scans.
- A repository whose only LLM signal is a credential no longer receives a derivative LLM-usage finding; vendor-neutral heuristics cannot create an `agent` finding without a framework, provider, platform, protocol or cloud-service match; projects observed only through environment-variable or display names are tagged `env-names-only`, weighted at half and capped at confidence 0.8.
- MCP filesystem and database servers carry a new `data-access` capability and browser servers carry `browsing`; gateway callers are titled `Agentic caller` only with a non-temporal indicator, and round-the-clock activity alone keeps the informational `always-on` tag.
- When a project's only technology anchors are environment-variable or display names, vendor-neutral heuristics contribute no evidence, indicators or capabilities; a dependency, import, code or file anchor restores their weight.
- Regression cases for each rule join `tools/evaluation/corpus.json`.
- `tools/evaluation/realistic_corpus.json` adds 31 multi-file cases written to resemble real repositories and naive-scanner false positives; the evaluator gains a `known_gap` flag and a `max_secret_findings` assertion, CI runs all three corpora, and docs/evaluation.md states what each corpus does and does not measure. Semantic Kernel C# projects now promote to agents, and a function defined as `create_agent()` no longer matches the LangChain call pattern.

#### Correctness

- SARIF output never emits a `physicalLocation.region` without `startLine` (line-less snippets move to the location's property bag), rule names are restricted to `[A-Za-z0-9_]`, invocation timestamps are ISO 8601 UTC or omitted, and null-valued keys are dropped; `render_sarif()` is validated against the vendored SARIF 2.1.0 JSON schema in the test suite.
- Risk scoring is total over malformed metadata: a non-numeric secret count or a non-object MCP server entry no longer aborts the scan, and the confidence-scaling factor never carries a positive weight.
- `shadowscan connectors` renders configuration keys with real styling instead of literal `[bold]` markup and prints plugin registry diagnostics; scans log the same diagnostics at WARNING.
- Setup failures print actionable, credential-free messages (`inventory path not found: …`, `signature directory not found: …`, a malformed pack named by file and document, an unknown connector key with a suggestion) through the new `shadowscan.errors.SetupError` contract; every other exception stays masked. Connector-level configuration keys now fail closed against each built-in connector's declared keys, YAML syntax errors report line and column without echoing source, and the deprecated `options.connector_timeout` alias logs a one-time deprecation warning.
- `shadowscan signatures test` reports an invalid pack as a click error and, in auto mode, also consults dependency signals across every ecosystem.

#### Performance and maintainability

- The filesystem scanner stops its walk cooperatively before the connector deadline, records one error naming examined and remaining files, and returns the findings collected so far; the engine keeps them and reports the scan incomplete instead of discarding everything.
- Domain, regex-signal and file-glob matching are prefiltered by required literals with engine-consistent case folding and batched deadline bookkeeping; equivalence tests assert identical results and the repository self-scan runs about twice as fast. The per-file budget scales with file size, files over `max_file_size` that match the new `oversize_skip_globs` key (lockfiles, minified bundles, source maps, images, fonts, archives, compiled artifacts) are skipped with a warning while other oversize files remain errors, and incremental fingerprints track oversize files by metadata instead of aborting.
- The gateway log normaliser is split into `shadowscan/connectors/gateway/normalise.py` with one small function per export format behind a registry; goldens generated from the previous code replay byte-for-byte under `tests/fixtures/gateway_golden/`.

- `Engine.run` is decomposed into named seams (`_prepare_run`, `_ConnectorRunner`, `_Supervisor`, `_ExportLedger`, `_postprocess`, `_write_manifest`) with identical ordering, thread-safety and deadline semantics.
- Signature packs are parsed once per `Engine` instead of twice, inventory is loaded once, and `Finding.sanitize()` skips objects unchanged since the last pass under the current redaction policy, so redaction runs once per finding instead of seven times while every call site keeps its defence in depth. Rendering 5,000 findings to JSON drops from about 18 s to under 2 s; sanitization semantics are unchanged.
- `Signal.compiled` is a lazy property; the scanner-source digest used by comparison and incremental caching is one shared helper; helpers with no callers are removed from the connector base, `utils.text`, `utils.safe_yaml` and the identity connectors.

#### Tests and tooling

- The suite collects on a core-only install (optional SDKs are imported with `importorskip`), deadline tests no longer depend on host speed, byte-identical duplicate tests are collapsed, and index-less `Engine()` constructions in tests reuse the session signature index.
- Every configuration key a connector reads is declared in its `config_keys`, shared offline-limit keys are surfaced through one `BaseConnector` list, `enabled` and `label` are documented, and a test parses each connector module so an undeclared key cannot reappear.

#### Governance and documentation

- `CONTRIBUTING.md` documents the actual single-maintainer, self-merge process with automated checks and requires independent human review before any tagged release; `docs/production.md` gives operators the commands to verify ruleset and review state themselves.
- The three 2026-09-24 review documents are relabelled as internal AI-assisted hardening logs (they now live under `archive/reviews/`); the package classifier drops from Beta to Alpha; README gains a Project status section and corrected claims; SECURITY.md states that no versions are released yet.

### Production acceptance fixes (2026-09-25)

- Redact opaque credentials assigned through indexed Python/JavaScript targets
  before capturing source evidence, and escape terminal control characters in
  verbose reports.
- Bind Slack findings to immutable workspace IDs; preserve workspace names only
  as display metadata. Legacy offline exports need a team envelope or explicit
  `team_id`. Refresh Slack comparison baselines after this identity correction.
- Reject Teams records with missing or malformed resource identity, retaining
  valid neighboring observations while reporting incomplete coverage.
- Distinguish repository-local Python modules from third-party agent SDKs and
  recognize supported provider-driven tool loops through structural source
  evidence. Static construction still does not establish runtime execution.
- Add deployment evidence validation and a manually invoked release-evidence
  workflow. Neither tool creates human review, live tenant results, a published
  release, or a production acceptance claim from offline tests.

### Production review round 2 (2026-09-24)

- Stop treating every environment value of a cloud inventory record as a credential to remove from sibling fields: a benign setting such as `STAGE=prod` or `WORKERS=4` no longer redacts ARNs, account IDs and names out of SageMaker findings and `--dump-records` exports, which also restores stable finding IDs when an export is reanalyzed offline. Environment values remain withheld in exports, and values under sensitive names or in recognizable credential formats are still removed everywhere. SageMaker findings now record environment variable names only, like Lambda findings.
- Snapshot Bedrock agent DRAFT details instead of storing the agent record inside itself; the previous self-reference collapsed to a redaction marker in record exports and marked every reanalyzed agent incomplete. Older exports with the collapsed entry are read without a coverage warning.
- Identify potential grants from IAM `NotAction` allow statements against a representative AI-action list, recorded with a `notaction-partially-evaluated` limitation (the wildcard treatment first described here was superseded before it shipped), and treat `sagemaker:*` as an LLM invoke grant during live collection, matching the offline analysis.
- Report OCI custom (fine-tuned) models by `type: CUSTOM` / base model reference instead of a vendor test that excluded every real custom model.
- A `bedrock-logging` export record without a `loggingConfig` key, or carrying an error body, is unknown coverage rather than a "logging DISABLED" finding.
- Show the configuration policy reason when scan setup is rejected (for example the code-scan and live-credential separation rule) instead of a generic message; the rule's message now names `--allow-credential-mixing`.
- Sort Entra delegated scopes so `permissions` are reproducible across runs.
- JWT classification: `client_name`, `app_displayname` and `azp_name` count as agent hints only when their value matches an AI product or agent name signature (every Entra v1 delegated token carries `app_displayname`, so ordinary user tokens were reported as agents); a user-subject token with an RFC 8693 actor and agent claims is `delegated-agent`, never weaker than the same token without `act`; nested claim values are sanitized before truncation so no token prefix is persisted.
- Entra service-principal findings use the scanned tenant as `account` (the publisher tenant is kept as `metadata.owner_tenant`); Google Workspace accepts the Admin SDK `tokenList` envelope and URL-encodes user keys; Atlassian validates `products`; Make pagination isolates invalid pages.
- n8n, Make, Workato and Notion exports containing a provider error body are incomplete coverage instead of an empty inventory; one malformed record in Teams, n8n, Make, Zapier, Workato, Notion, generic SaaS or live Slack lists is skipped with a warning instead of aborting the connector.
- Gateway: response-side tool calls count when inspected requests carried no tool definitions (LiteLLM with body logging off), Bedrock Converse `toolUse`/`stopReason` are recognized, activity buckets use UTC, `llm_hosts_only` keeps requests to known LLM hosts on unlisted paths, Vertex and Portkey/Helicone detection use structural fields, a token in a user or principal field is sanitized before the label is shortened, LiteLLM rows without key material are `service` callers rather than pseudonymized credentials, `identity.arn` wins over the `identity` object, prose `message` wrappers keep the structured event, retained labels and samples are bounded, and a caller's first model/provider/host label survives an exhausted detail budget. Opaque credential labels skip display-name matching.
- Code connectors: cooperative cancellation now stops the tree walk instead of being recorded as one error per remaining file; credential detection runs first and in its own isolation, so a content pass that exceeds its regex budget, a structured file that exceeds the sanitizer budget (excerpts withheld) or notebook outputs and markdown cells no longer hide a real key; one unsafe tree path in API mode skips that file rather than the repository; agent definitions (50 per project) and retained agent manifests (200) are bounded with an incomplete-scan error; directory exclusion names no longer skip files of the same name; `Containerfile` is parsed like a Dockerfile; per-repository diagnostics share the 1000-entry cap; Git author fields use NUL separators with a validated timestamp; Ruby `=begin` blocks scan in linear time; a Python 3.12 tokenizer error mid-file marks the file ambiguous instead of silently masking the remainder; multi-line structured secrets keep excerpt line numbers aligned.
- Environment-style credential names in text (`AZURE_OPENAI_KEY`, `DATABRICKS_TOKEN`, `MODAL_TOKEN_SECRET`, `LITELLM_MASTER_KEY`, ...) have their assigned values redacted in source excerpts, evidence and URL queries (indexed targets such as `os.environ["DATABRICKS_TOKEN"]` included); record field names keep their narrower sensitivity so provider inventories are not over-redacted. A connector's other findings survive one finding that exceeds the sanitizer's output budget.
- Tests that assert successful Git history enrichment skip with a clear reason when the local Git lacks `--no-lazy-fetch` (2.45+) instead of failing; CI enables pip caching and mypy checks untyped function bodies.

### Detection and collection assurance (2026-09-24)

- Require corroborating AI evidence and bind constructors to imported frameworks; resolve common Python and JavaScript/TypeScript aliases. Generic loops and subprocess calls cannot establish confirmed agents.
- Validate agent manifests and operational configuration; descriptions and empty files cannot establish agent presence.
- Preserve unknown Lambda coverage, identify potential IAM NotAction grants with explicit analysis limits, validate Slack workspace scope and report missing n8n definitions as incomplete.
- Add a frozen negative-heavy public corpus with separate AI labeling passes, provenance and annotation checks in CI. This is not field accuracy.
- Add read-only AWS and Slack tenant canaries with explicit controls, scope and coverage assertions, permission-denied tests and private reports. Offline replay does not establish live acceptance.

Live tenant acceptance remains a deployment gate. Neither offline tests nor static findings prove a production tenant was scanned.

### Final reconciliation after PR #33 (2026-09-24)

- Fence incremental cache and record publication against timed-out connectors, and refuse to reuse an Engine while a prior abandoned worker still runs. A separate process deadline remains necessary for blocked SDK or plugin calls.
- Redact short configured credentials in diagnostics. Bound gateway caller/detail/interval state and repository-wide CODEOWNERS work, and avoid excessive work on Go source ranges.
- Keep untrusted SDK diagnostics out of application logs, redact opaque API/Foundry/GitHub token fields and the `GH_TOKEN` fallback, and restrict Kubernetes JWT classification to documented claim shapes.
- Preserve the newer webhook, HTTP header, imported finding, CSP, SARIF, GCP and Azure safeguards from the consolidated candidate.
- Fix the example code-scanning workflow for repositories without an inventory directory and for fork pull requests.
- Record immutable commit/tree identities on GitHub and GitLab code findings, and reject downloaded blob bytes that do not match the enumerated Git object ID.

Package version: 0.1.1. No release tag or published artifact is implied by this
entry. Tenant canaries and container runtime acceptance are still required.

### Security

- Withhold the credential-bearing path of webhook capability URLs (Slack, Discord, Teams, Zapier, Make, IFTTT, Telegram, n8n) in evidence, reports and record exports; `webhookUrl`/`webhookUri`/`webhookId`/`hookUrl`, `AccountKey`, `SharedAccessKey` and `sas_token` fields are sensitive.
- Apply the Keycloak service-account rule to Keycloak issuers only; a `preferred_username` starting with `service-account-` no longer relabels tokens from other issuers.
- Match the Kubernetes JWT claim namespace on the exact `kubernetes.io` prefix.
- Validate headers before requests can echo credential-bearing invalid values; redact additional provider formats and escaped credentials before source excerpts are shortened.
- Redact opaque Azure app settings and OCI Function configuration in record exports. Reject malformed numeric fields in imported findings and restrict HTML scripts to the shipped script's SHA-256 hash.
- Redact multiline YAML credentials before evidence excerpts, and pin GitLab API tree pagination to an immutable commit.
- Route GCP token refresh through bounded response and redirect policy.
- Classify JWT issuer families by parsed hostname labels rather than substring matches.

- Separate repository scanning from live tenant credentials by default; mixing requires explicit `allow_credential_mixing` approval.
- Cloud instance-metadata credentials require `allow_instance_credentials` opt-in; connector settings cannot silently override the global policy.
- Checkouts disable persisted GitHub credentials, and the Docker build context permits only source and packaging inputs.
- Core and cloud runtime dependencies are version- and hash-locked for the documented Linux/Python deployment targets.

### Reliability

- Render inventory, signature and connector text literally in CLI tables: Rich markup in an approval card no longer crashes `inventory check` or restyles the review screen.
- Retry GitHub 403 rate-limit responses (`X-RateLimit-Remaining: 0` or `Retry-After`) but not plain permission denials; all HTTP backoff is jittered and capped at 120 seconds.
- SARIF artifact URIs are percent-encoded, made root-relative only on path boundaries, absolute outside the scan root, and each rule reports its most severe result.
- Preserve valid cloud, identity and SaaS records after individual collection/analysis failures. GCP service-account key coverage now distinguishes unknown inventory from observed zero keys.
- Normalize scalar cloud scope options and reject unknown AWS service selections instead of reporting an empty successful scan.
- Bound diagnostic streams, gateway detail cardinality and numeric aggregates; isolate failures without losing later valid records.
- Deduplicate repeated source observations without dropping distinct custom signal capabilities. Preserve caller scan budgets and bound concurrent manifest matching by both CPU and wall time.
- Add a default 120-second connector deadline with incomplete-scan reporting. This is a soft thread deadline; host job timeouts remain necessary for blocked SDK/plugin calls.
- Protect incremental cache slots with nonblocking POSIX advisory locks. Contention or missing platform locking falls back to full scans without unsafe cache reuse or saves.
- Preserve the required CodeQL check name `analyze` and test hash-locked runtime installation in the Python 3.11/3.12 CI matrix.

### Operations

- Reuse bounded inventory patterns and per-analysis JWKS documents; index source newlines, avoid unnecessary JSONC parsing and reuse OCI clients within one collection session.
- Consolidate additional verified fixes from PR #31 on top of the PR #30 candidate; preserve PR #30's credential isolation, default deadlines and release gates.
- Explain how to select and verify the final reviewed full commit SHA; avoid an install example that silently falls behind later candidate fixes.
- Raise the development Ruff requirement to 0.16.8 and validate wheel installations against the runtime lock.
- Correct README commands, formatting and discovery claims; document the active required checks and independent-review merge gate.
- Document dependency lock maintenance, soft deadline limits, rollout evidence and remaining tenant/container acceptance.
- Clarify that finding confidence is heuristic, that static signals and resource existence need runtime corroboration, and that field precision/recall require a held-out local corpus before risk-gate enforcement.

## Earlier hardening notes — 2026-09-24

The following summarizes the reconciled pre-release implementation.

### Security


- Escaped, multiline and nested sensitive mapping values are redacted before source evidence is emitted; TLS verification rejects all falsy effective settings.
- Live AWS account attribution is checked through STS even with a configured expected account.
- Report imports reject ambiguous JSON, unsafe file paths and invalid security attributes before generating inventory stubs.
- GitHub/GitLab API downloads use enumerated immutable blob IDs; links, submodules and malformed Base64 produce incomplete coverage.
- Accountless short AWS IDs cannot approve a registry entry; their scans report incomplete coverage until an account is supplied.
- Filesystem scans reject symlinked root paths and report skipped in-scope symbolic links as incomplete coverage.
- Injected HTTP sessions cannot retain origin-specific adapters that bypass destination checks; default buffered responses have a decoded-byte limit.
- Scan configuration rejects missing required environment values, duplicate authored YAML keys, invalid gate settings, and unsupported top-level options.
- Finding identity no longer includes `kind`; promotion from framework-usage to agent preserves merge/diff/incremental identity.
- Shared HTTP client bounds JSON response bodies by default.
- Injected `requests.Session` objects still receive the destination-policy adapter.
- Missing `${ENV}` expansions for required secrets fail closed instead of becoming empty strings.
- Full Apache-2.0 LICENSE text and NOTICE.

### Reliability
- Identity/low-code pagination retains valid neighbors and partial observations, rejects provider failures, and recognizes documented Google empty-list envelopes.
- GCP Cloud Run lists concrete locations; unreachable regions are incomplete. Azure ARM pages preserve observations while incomplete diagnostic collections remain unknown.
- AWS and OCI SDK clients use finite transport/retry bounds; AWS Lambda and GCP project limits stop enumeration early.
- Relative inventory globs and work directories resolve beside their configuration file.
- A later Azure Resource Graph page failure retains already observed resources and reports incomplete coverage; GCP caller attribution is scoped by project.
- Concurrent connector completion order no longer determines merged finding ownership or metadata.
- CLI documents exit 3 (incomplete), exit 2 (`--fail-on` on a complete scan), and Click's separate usage-error path.

### Operations
- Repeated gateway headers reuse bounded per-scan classification summaries; regex contention retries retain their original CPU and input deadlines.
- Docker build context uses an explicit input allowlist, Actions checkout drops persisted credentials, and both CI matrix jobs finish independently.
- Incremental fingerprints ignore literal excluded source directories while retaining CODEOWNERS inputs; project-root attribution scales with active ancestors in wide monorepos.
- Disposable non-root worker image (`Dockerfile`).
- CI runs lint, audit, test, and package checks in each Python matrix job, with a concurrency group.
- Example GitHub Action and README use commit-pinned install examples and document incomplete-scan gating.
- `docs/production.md` rollout checklist: split credentials, egress controls, tenant canaries, reports-as-secret.

### Migration
- Finding IDs for promoted resources change with these commits. Rebuild comparison baselines and incremental state when upgrading from an earlier revision.
- Install from a reviewed tag/SHA. Do not follow `main`.

### Known limits
- Connector deadlines are cooperative; blocked SDK/plugin calls still need host process timeouts.
- SDK timeouts and retry limits do not establish a universal deadline for authentication chains or whole scans; workers still require a host deadline.
- Incremental cache writes are atomic and protected by per-slot advisory locks on POSIX. Unsupported platforms and contention use full scans.
