# Release notes

What changed for people who install, configure or operate ShadowScan, one
section per release. [CHANGELOG.md](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CHANGELOG.md)
names each change in a line, the
[engineering log](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/engineering-log.md)
records each in detail, and the
[deployment and migration guide](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/production.md)
has the full upgrade steps.

## Unreleased

Changes on `main` since 0.1.2, for operators. They are not published or
tagged; pin a reviewed commit SHA to use them. Details:
[CHANGELOG.md](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CHANGELOG.md)
and the [candidate change history](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/production.md).

### Before you upgrade

- The repository is renamed to `aisecnomad/Nexus-ShadowScan`
  (formerly `aisecnomad/Project-Nexus`); GitHub redirects the old URLs, and
  commit SHAs are unchanged. OCSF events name the vendor `Nexus ShadowScan` instead of
  `Project Nexus`; SARIF and CycloneDX keep the tool name `ShadowScan`.
- Coverage gaps are budgeted. A gap the scanner can bound -- a handful of
  unreadable entries, a dangling symbolic link or one to a single file, one
  source or data file over `max_file_size` -- no longer marks the scan
  incomplete on its own. Such gaps accumulate against
  `options.max_coverage_gap` / `--max-coverage-gap`, 2% of examined entries
  by default, and are always reported under `stats.coverage` whether or not
  they change the exit code. A gap the scanner *cannot* bound still fails
  closed with no budget: an early stop, a refused page, an expired deadline,
  a symbolic link to a directory, an unparseable manifest or agent card
  outside test code, an agent, MCP or dependency configuration file whose
  name selects it over `max_file_size`, undecodable bytes anywhere but in
  test code while `include_tests` is off, and any sanitizer limit. Test code
  whose evidence is discounted (`include_tests` off) is the exception for
  manifests and undecodable bytes: a malformed fixture is charged to the
  budget at a quarter weight and an undecodable one, read for credentials
  first, at a whole entry, so a few leave the scan complete and a tree
  seeded with them does not. An MCP configuration, coding-agent file or
  agent card keeps the gap in test code too. The budget is judged per scan
  root and per repository.
  `strict_coverage` and `--max-coverage-gap 0` (or `max_coverage_gap: 0`)
  are both strict accounting and restore the previous accounting: every gap
  marks the scan incomplete, and none is discounted as test code or declared
  by `profile: ci`, which both settings refuse (see
  [strict accounting](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/scanning.md#coverage-budget-and-strict-accounting)).
  Expect scans that previously exited 3 on a dangling
  symbolic link in a test fixture to exit 0 now, with the gap listed.
- Risk scores gain capability interactions. Seven capability sets -- the
  lethal trifecta (data access, untrusted content, outbound actions),
  browsing with code execution, autonomy with code execution, and four more
  -- add a named `combination:` factor when the whole set is present, so a
  pairing whose joint risk exceeds its parts is visible in the breakdown.
  Scores rise for findings holding those sets; tune or disable them under
  `options.risk_weights.combinations`. Rebaseline.
- OCSF events always carry the required `time` attribute. Where no scan
  timestamp parses, the render time is published and
  `unmapped.time_source` is `report_render`. Events previously omitted the
  field, which a validating pipeline rejects.
- Rebaseline. Path context, cross-signal corroboration and new signatures
  change confidence, risk, kind and the set of findings, and live collection
  scopes are fingerprinted after collection.
- Consumers that read `metadata.compliance` must switch to `metadata.threats`
  and `metadata.controls`: the key is no longer written, and an older report's
  value is dropped when `diff` or `merge` reads it. References are
  edition-qualified author mappings, not compliance determinations.
- Default risk changes: the new `mcp-server` capability adds 5; findings whose
  only evidence is documentation, example or generated code lose 8, 8 or 10;
  `hidden-instructions` (20), `remote-code-fetch` (15), `invisible-text`,
  `autonomy-understated`, `a2a-plaintext-interface`, `a2a-card-signature-invalid`,
  `tool-name-shadowing` (10 each) and the governance factor
  `mcp-not-in-approved-registry` (15) are new.
- On CPython 3.12.0 to 3.12.3 (Ubuntu 24.04 ships 3.12.3), a file with a very
  long line no longer stalls redaction: the finding is omitted and the scan is
  incomplete (exit 3). Run ShadowScan on 3.11, or on 3.12.4 or later.
- A tree whose directory listing alone takes more than half the connector
  deadline is now incomplete; raise `connector_timeout_seconds`. `cloud.aws`
  exports with registry records from earlier builds replay as incomplete.
- `shadowscan merge` refuses (exit 1) a report with another finding identity
  schema, a non-boolean `inventory_present`, or a reused finding id. It also
  refuses a report written before `inventory_present` existed (the 0.1.x
  releases) when that report records registration: rescan such hosts before
  merging. Fleet reports now carry `collection_scope.fleet.schema`
  `shadowscan.fleet-merge/v2` with per-source times, inventory presence and
  connector status; consumers that pin `v1` must accept `v2`.
- Live `cloud.aws` AgentCore gateway findings use the gateway ARN as their
  resource, so their finding ids change: re-baseline AWS scans that include
  gateways.
- Atlassian finding ids change: exports scanned without a configured `site`
  are bound to each export file's resolved path, and a `site` with an
  uppercase host or an explicit `:443` is canonicalized. A `site` that is not
  a plain HTTPS origin (for example a Data Center context path such as
  `/jira`) stops the connector with exit 3. Configure `site` as
  `https://<host>`, keep one site per input and rebaseline.
- Kubernetes and OpenShift resources with names over 160 characters keep
  their full name, so their finding ids change. These now end a scan
  incomplete (exit 3): a namespace that is not an RFC 1123 DNS label, a
  chunked `List` page (`metadata.continue` or `remainingItemCount`), a name
  over 253 characters, and a container `command` or `args` that is not a list
  of strings.
- `gateway.logs`: Ollama-style requests to a host that is not a known or
  declared model host are no longer callers. List internal model servers
  behind a reverse proxy in the new `internal_model_hosts` option before
  upgrading; setting it changes that source's finding ids.
- More inputs end a scan incomplete (exit 3): a malformed or unsupported
  `uv.lock`, `poetry.lock`, `pnpm-lock.yaml` or `Cargo.lock` with no manifest
  beside it; a malformed or over-budget n8n, Flowise or Dify graph; a live
  process command line over 65,536 bytes; a `SKILL.md` or MCP description
  audit over 64 KiB, with malformed front matter or an unclosed fence; and
  defective network log records (a malformed context, TTL, timestamp or JA4
  value, or over 32 DNS answers). The
  [deployment and migration guide](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/production.md)
  lists each case and what it withholds.
- Low-code autonomy evidence is read more strictly: triggers a person operates
  (n8n manual, chat and form triggers, Workato Workbot commands, Zapier
  Chrome extension or Interfaces steps), and Make on-demand scenarios, which a
  person or a call can start, no longer add
  the `autonomous` capability, a schedule is tagged `scheduled` only, and a
  ServiceNow agent carries `tool-use` only when the export holds its tool
  records. Make now reads `scheduling.type`, so a polling scenario gains the
  `scheduled` tag. Risk levels of affected low-code findings move; rebaseline.
- Keyed incremental cache entries are authenticated with an HMAC and miss once
  after upgrading; unkeyed caches are unchanged.
- The incremental cache entry format moves to 5, so every entry, keyed or
  unkeyed, misses once after upgrading and the first incremental scan
  analyses every repository root again. Entries are keyed on the scan-wide
  `max_coverage_gap` as well, so a scan under another budget also misses
  instead of replaying a verdict taken under the old one.
- An explicit connector deadline is now fixed, 120 seconds included: only an
  unset `connector_timeout_seconds` is raised to fit a large tree. Remove
  `connector_timeout_seconds: 120` from configurations copied from earlier
  sample configurations, or a large repository keeps exiting 3 at 120 seconds.

### What changes in scan results

- New commands: `shadowscan endpoint` scans a workstation profile's AI client
  configuration; `shadowscan merge` combines JSON reports from several machines
  into one fleet report; `shadowscan mcp-registry snapshot` writes a listing to pin.
- `shadowscan dashboard REPORTS... -o page.html` writes a static, self-contained
  fleet page (coverage first, then counts, autonomy floor against shadow status,
  registry reconciliation, threat and control reference counts, drift against
  `--baseline FILE`, history from `--history DIR`); `--inventory-json FILE`
  writes the `shadowscan.inventory/v1` export for BI and SIEM tools without
  credential findings or evidence. Exit 3 when an input is incomplete or the
  baseline is not comparable (the files are still written), exit 1 on invalid
  input; outputs are written 0600 and never through a symbolic link.
- `shadowscan controls REPORTS... [-f markdown|csv|json] [--framework PREFIX]`
  lists, for every NIST AI RMF, ISO/IEC 42001, EU AI Act and AIUC-1 entry, the
  findings that reference it with their evidence scope. A control reads "not
  observed" only when every input is complete, otherwise `unknown (...)` with
  the reason; the output never says compliant, pass or fail and refuses an
  already-merged report (pass the source reports). Schema version 2 Capability
  Cards accept a validated `governance:` block (EU AI Act risk class, intended
  purpose, oversight measures, AIUC-1 certificate, ISO/IEC 42001 scope), carried
  as `metadata.declared_governance` on registered findings.
- `--allow-plugin name=module:Class` (and `options.plugins`) pins a
  plugin's entry point; a mismatch is refused as `target-mismatch`, duplicate
  approvals are refused, and a bare name behaves as before. `shadowscan jwt` and
  `run --set` warn when a credential is passed on the command line; the value is
  never echoed. The warning goes to stderr, so a wrapper that parses `2>&1` as
  a report must read stdout or `-o FILE` alone.
- Approval gates of coding-agent clients read `some-actions` in more cases where
  part of the settings evidence was not read: an oversize settings file skipped
  without a gap, and every project of a repository whose GitHub or GitLab tree
  listing was truncated or partly malformed.
- `identity.entra`: a pre-issued `access_token` whose `tid` is not the `tenant_id`
  given as a tenant ID skips the connector before any request (exit 3) in every
  configuration; give the tenant ID, not a domain, with a pre-issued token.
- `cloud.gcp` record dumps now carry the gaps that made a live scan incomplete
  (an unvalidated engine name, a failed project-number lookup), so a replay is as
  incomplete as the live scan. The CSV report labels unassessed findings like the
  other reports.
- Fleet shadow status has three states: `true` when any source found the
  finding unregistered, `false` when a source matched it to its inventory,
  `null` when no source had an inventory. Findings no source assessed are
  labelled `unassessed`, not shadow; merged reports carry `inventory_present`.
- `shadowscan diff` labels each change with a drift class (`inventory`,
  `capability`, `autonomy`, `governance`, `coverage`) and whether it is
  adverse. New options: `--fail-on-drift CLASSES` (exit 2 on adverse drift),
  `--baseline-sha256 HEX` (exit 1 on a mismatch), `--max-baseline-age-days N`
  (an expired baseline is an incomplete comparison, exit 3), `--shadow-only`.
- Live `cloud.aws`, `cloud.azure`, `cloud.gcp` and `identity.entra` scans can
  attest a comparable collection scope, so `diff` resolves findings between
  two complete live scans. `identity.entra` attests only app-only credentials
  and now reads `GET /organization` (`Organization.Read.All` or
  `Directory.Read.All`); a user token or a delegated scan is never attested.
- Autonomy: agents, MCP servers, workflows, bots, gateway callers, AI apps and
  AI cloud resources carry `metadata.autonomy` (L0 to L5 floor and ceiling,
  oversight, initiation). Claude Code, Codex and Goose approval settings are
  `metadata.approval_gate`; allow rules, hooks, an auto-allowing sandbox and an
  unreadable or malformed settings file keep the gate at `some-actions`.
  Capability Cards declare a level with `schema_version: 2` (version 1 ignored).
- Registry records: `cloud.aws` (service `registry`), `cloud.gcp`
  (`agent_registry`, `gemini_enterprise`) and `identity.entra`
  (`include_agent_registry`, `include_agent_identities`) read vendor agent
  registries, all off by default. `metadata.registry_reconciliation` never
  changes shadow status or risk; only `options.trusted_registries` lets approved
  records register what they bind, and auto-approved, registered-only or replayed
  records need `allow_auto_approved`, `allow_registered_only` or `allow_offline_records`.
- `identity.entra` `auth_mode: delegated` reads a signed-in user's Graph token
  from the environment variable `delegated_token_env` names (default
  `GRAPH_DELEGATED_TOKEN`); with a registry collection it is incomplete (exit 3).
- `options.mcp_registries` pins up to 16 MCP Registry snapshots by SHA-256,
  `approved: true` marking the approved catalog; MCP server findings gain
  `metadata.mcp_registry` and zero-weight tags such as `mcp-unpublished`.
- `endpoint.mcp` `agent_card_urls` fetches A2A Agent Cards over HTTPS as
  `a2a-agent-card` findings; `metadata.agent_card.signature` is checked only
  against the operator's `agent_card_jwks_url`, and `verified` never approves.
- Code scans: `--diff-base REF` scans only the files changed since the merge
  base (tag `diff-scan`; not comparable, never cached, Git 2.45 or later);
  `--triage` is a fast subset scan that is always incomplete; `--format ocsf`
  writes OCSF 1.1.0 findings; opt-in `agent_granularity: source` reports named
  Python agent constructions separately.
- Precision: an uncorroborated lexical code pattern establishes nothing
  (`metadata.potential_frameworks`, `metadata.potential_providers`); model ids
  in source are provider evidence (`metadata.models`); an implemented MCP server
  is titled "MCP server in"; a low-code flow export with an agent node is
  `kind: agent`; an unattributed credential is "Hard-coded credential in <file>".
- Fewer incomplete scans after 326 public repositories: the JavaScript, Rust,
  PHP, F# and C# lexers, stray NUL bytes and lossy text were corrected, and
  malformed templates and fixtures are input-defect warnings that still fail
  closed. A repository can gain findings, including credentials. With
  `scan_secrets: false`, oversize documentation and test fixtures are skipped.
- LLM triage is bounded by `options.llm_triage.budget_seconds` (default 300) and
  a `--job-deadline-seconds` deadline; unreached findings are `status: skipped`.
- `--format cyclonedx` adds implemented MCP servers as services, threat and
  control references and `shadowscan:mcp:registry-*` properties. New
  signatures: Koog, Browserbase, Agency Swarm, Rivet, Devin, the Elixir, R,
  Lua and Rust LLM libraries, and the MLflow and Cloudflare AI gateways.

### Security and safety

- A triage reply steered by scanned content cannot change a finding's risk,
  shadow status, kind or tags; a reply over 16 KiB is refused unread, a reply
  that carries more than one verdict object is `unparseable`, and requests send
  no sampling parameters (current Claude models reject `temperature`); OpenAI
  requests use `max_completion_tokens`, which an OpenAI-compatible endpoint
  must accept.
  `options.llm_triage.structured_output: true` constrains the reply to the
  verdict schema on providers that support it. Offline prompt-injection
  canaries (`python -m tools.evaluation.triage_canaries`) run in the unit tests.
- `--allow-plugin name=module:Class@distribution==version` also pins the
  installed distribution that provides a plugin's entry point. Evidence
  snippets withhold random-looking quoted literals of 20 or more characters as
  a last resort; hex digests, UUIDs and identifiers keep their text.
- MCP launch identity is decided on the configured values, not the sanitized
  record, so a redacted value cannot hide an env name, `cmd` argument or `docker
  -e` value that makes the launch unidentified; every argument and every
  endpoint of a direct remote is checked.
- Settings paths from a GitHub or GitLab tree listing are confined to the
  checkout before any download: traversal, absolute and `.git` paths abort the
  repository and the filesystem connector refuses any unread settings path
  outside the scanned root.
- Redaction also withholds `Bearer token <value>`, keys ending in
  `secretvalue`, `tokenvalue`, `passwordvalue` or `apikeyvalue`, opaque
  literals in setter calls such as `setProperty("openai.key", ...)`, and
  `value`, `key` and `credential` fields inside an `auth` mapping, at any depth
  of the mapping and inside lists under it.
- Delegated Graph tokens have no configuration key; they are read from the
  environment, registered for redaction and never refreshed. Agent Card
  fetches use the shared HTTPS client, and URLs and key locations named inside
  a card are never fetched or used. A scan never contacts an MCP registry.
- Untrusted and replayed registry records never approve a finding. Failures
  inside third-party SDK code report only the exception type, AWS CLI
  positional credential settings are withheld, and the HTTP client ignores
  proxy environment variables and rejects an explicit proxy.

### Operations

- The next release uploads a source distribution beside the universal
  `py3-none-any` wheel. The release workflow builds the wheel from that sdist
  with `python -m build`, checks that both carry the same metadata and package
  files, attests both and publishes both through PyPI trusted publishing. 0.1.2
  was published as a wheel only.
- `docs/operations/operational-controls.md` covers process supervision (systemd
  `Type=oneshot` with `TimeoutStartSec=`, Kubernetes and CI deadlines), egress,
  plugin trust and release evidence. `examples/k8s-network-policy.yaml` is a
  default-deny egress policy; `examples/github-action-drift.yml` and
  `examples/k8s-drift-cronjob.yaml` run weekly drift checks; `make mappings`
  validates the threat and control catalogs. The drift CronJob carries
  `shadowscan-mode: live`, the label the egress policy grants egress to.
- The optional Semgrep workflow runs `semgrep ci` in the `semgrep/semgrep` image
  pinned by registry digest, the Checkmarx One and Black Duck workflows pin
  tagged releases, every commit pin in the repository's and the example
  workflows carries a release comment, and every job container image is pinned
  by digest with its tag named above it; policy tests enforce both.
- The advisory AI review gate (`tools/ai_review`, `.github/workflows/ai-review-gate.yml`)
  runs only for pull requests that carry evidence under `.github/ai-review/`;
  its best outcome is a `neutral` check, never `success`, it posts `COMMENT`
  reviews only, and it must not be a required check. The governance documents record the 2026-10-10 ruleset
  readback: `CI gate` is required, but both `main` rulesets still list four
  `always` bypass actors, so the merge gate is not yet enforced against a
  repository administrator.

### Known limitations

- The registry, A2A, autonomy and drift fixtures are synthetic; nothing was
  validated against a live registry, account, tenant or agent, and the
  benchmarks are author-written, not independent review.

## 0.1.2 — 2026-10-08

Corrects the release workflow's production tag lookup and prepares the next
public alpha candidate. The workflow now uses `refs/tags/v<version>` after
the previous `tags/v<version>` lookup returned HTTP 422 for an existing tag.
Scanner behavior is
unchanged from the 0.1.1 candidate described below.

Version 0.1.1 was published to TestPyPI, installed and verified, and tagged.
Its production preflight failed before a PyPI upload. The immutable tag remains
on its original commit; version 0.1.2 carries the correction through a new
review and CI cycle. Confirm publication on
[PyPI](https://pypi.org/project/NexusShadowScan/0.1.2/) and the
[GitHub release](https://github.com/aisecnomad/Nexus-ShadowScan/releases/tag/v0.1.2)
before installing this version from the production index.

## 0.1.1 — 2026-10-08

Initial alpha candidate of `NexusShadowScan`, with 38 connectors across nine
discovery surfaces. Install with `python -m pip install NexusShadowScan` and
run `shadowscan --help`; see the
[README](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/README.md#install)
for cloud extras and hash-locked deployment instructions.

This version reached [TestPyPI](https://test.pypi.org/project/NexusShadowScan/0.1.1/)
and the immutable `v0.1.1` tag, but not production PyPI.
[PR #159](https://github.com/aisecnomad/Nexus-ShadowScan/pull/159#pullrequestreview-5458962521)
received a non-author approval on a source tree identical to the tagged commit.
Publication and artifact attestations do not establish deployment acceptance.

### Before you upgrade

- Install the `NexusShadowScan` distribution (`pip install NexusShadowScan`)
  into a fresh virtual environment. The
  command and Python imports stay `shadowscan`; the unrelated `shadowscan`
  package on PyPI is not this project. Earlier candidate builds were named
  `project-nexus-shadowscan`; do not install both.
- Rebuild comparison baselines. Finding IDs follow the v2 identity schema
  (sanitized resource fields, independent of `kind`), so older reports cannot
  resolve findings.
- Fail CI on any non-zero exit. Exit 1 means no scan result (invalid usage,
  configuration or setup), 2 a complete scan that reached `--fail-on`, and 3
  an incomplete scan.
- Fix `max_pages` values that are now rejected: 0, negative, fractional,
  boolean or non-numeric.
- Regenerate inventory cards made by `inventory stubs`, or add
  `discovery.discriminators`, so that each approves only its own finding.
- Regenerate earlier reports of Semantic Kernel, go-openai, openai-java or
  Google AI JavaScript code, and rotate any API key they show.

### What changes in scan results

- Gaps are reported, not hidden: limits, malformed or ambiguous exports,
  denied APIs, timeouts, oversize files and links leaving the scan root make a
  scan incomplete (exit 3).
- Evidence found only in tests or fixtures no longer establishes an agent
  unless `--include-tests` is set.
- Confidence counts correlated evidence once, so repeated matches of one
  signal no longer inflate it; some non-code findings report lower
  confidence.
- 220 signatures and 1,018 signals cover current agent SDKs, including Vercel
  AI SDK tool loops (AI SDK 7's `isStepCount`). Custom-pack framework patterns
  apply in every language, and detection-rule files (ShadowScan signature
  packs, Semgrep, Sigma, gitleaks) are treated as data.
- AWS roles are tagged `agent-execution-role` only when an `Allow` statement
  in their trust policy names a Bedrock service.
- `diff` reports gateway findings as not comparable unless every compared
  scan uses the same `SHADOWSCAN_IDENTITY_KEY`.
- SARIF results are warnings (critical, high, medium) or notes (low, info)
  that carry the heuristic level as `risk_level`. Rules no longer set
  `security-severity` or the `security` tag, so GitHub code scanning no longer
  rates ShadowScan alerts as security severities; the
  [severity guide](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/severity.md)
  explains why.
- Three new connectors and surfaces: `endpoint.inventory` (AI clients,
  coding agents, MCP servers, editor and browser extensions and local models
  in home directories, or osquery exports), `network.logs` (AI services
  contacted, from Zeek, Route 53 Resolver, VPC Flow Logs or DNS/SNI exports)
  and `runtime.processes` (AI tools seen running). Endpoint findings for a
  tool that is also seen running are tagged `observed-running`; scores do not
  change. Dashboards that enumerate surfaces or kinds should add `endpoint`,
  `network`, `runtime`, `ai-app`, `local-model`, `network-contact` and
  `runtime-process`.
- MCP configuration findings report static server risks (unpinned packages,
  filesystem servers rooted at `/` or a home directory, shell-wrapped
  launches), and coding-agent configurations report posture (permission
  bypass, unrestricted shell, unsandboxed Codex, an exposed or
  unauthenticated OpenClaw gateway). New risk weights apply; see the October 6
  note in the deployment guide.
- Gateway callers are titled "Agentic caller" from hosted agent runtime
  operations, MCP endpoints or agent-loop cadence, and no longer merely for
  calling `api.openai.com` or `api.anthropic.com`. Counts of agentic callers
  change on re-scan.
- `--format cyclonedx` writes a CycloneDX 1.6 AI bill of materials. Its
  composition is `incomplete` whenever the scan was.

### Security and safety

- Reports are written atomically with owner-only permissions. HTML reports
  carry a strict Content-Security-Policy, CSV cells are neutralized against
  formula injection, and Markdown is defanged.
- Credential redaction covers more forms, including keys passed positionally
  to well-known LLM SDK calls. Known gaps are listed in
  [SECURITY.md](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/SECURITY.md);
  treat reports as confidential.
- Scanned repositories are read without following links, git runs with
  hardened configuration, and live collection enforces HTTPS, origin and
  private-address controls.
- Third-party connectors run only when named in `options.plugins`, and
  repository scans stay separate from live tenant collection unless
  `allow_credential_mixing` is set.

- Opt-in LLM triage (`options.llm_triage`) is off by default. When enabled
  it sends redacted finding summaries (no resource ids, owners, locations or
  snippets) to the model endpoint you configure over HTTPS, reads the key from
  an environment variable, and stores an advisory verdict that never changes
  scores or completeness.
- `runtime.processes` never keeps command lines, and its records are excluded
  from `--dump-records`, because command lines can carry credentials.

### Known limitations

- Confidence is a heuristic evidence score, not a calibrated probability. The
  bundled corpora are author- or AI-labeled regression suites, not field
  precision or recall estimates.
- Live connectors are validated against recorded fixtures and optional
  read-only canaries, not against every tenant configuration.
- Python 3.11–3.13 on Linux and macOS are supported; Linux x86_64 is the
  validated deployment target.
