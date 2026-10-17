# Pending migration notes (Unreleased)

Per-change migration and behavior notes for changes on `main` that are not
in a tagged release yet. Read them together with the
[production deployment guide](production.md) when pinning a reviewed
revision; at release time they fold into the release notes. The
[candidate change history](history/production-change-history.md) keeps the
full dated log.

## October 17 engine review migration (Unreleased)

- **Every incremental cache entry misses once.** The entry format moves to 5:
  entries now record the scan-wide `max_coverage_gap` they were judged under,
  the coverage ledger and the declared omission count. Every existing entry,
  keyed or unkeyed, misses once after upgrading, so the first incremental scan
  analyses every repository root again and takes as long as a scan without the
  cache; plan the first CI run accordingly. A later scan under another gap
  budget misses as well instead of replaying the earlier verdict.
- **An explicit deadline is fixed.** `connector_timeout_seconds: 120` (or
  `--connector-timeout-seconds 120`) is honoured as a fixed 120 seconds; only
  an unset deadline is raised to fit a large tree. Earlier sample
  configurations set exactly that line: remove it from configurations copied
  from them to keep the scaling. A `ScanConfig` given the deprecated
  `connector_timeout` beside an explicit `connector_timeout_seconds` of 120 is
  now rejected as giving both, as any other pair is.
- **Split jobs publish their coverage.** An incremental scan of several
  repository roots now carries `stats[].coverage`, `incomplete_reasons` and
  `declared_omissions` for the job, and an expiry in a later root reports the
  findings of every root already finished, cache hits included.
- **Timeouts are named.** A timed-out connector, and one left unstarted
  because timed-out calls hold every worker slot, count `timeout` in
  `stats[].incomplete_reasons` and `summary.incomplete_reasons`; the exit-3
  line on stderr says `timeout N` instead of "a connector was skipped or
  recorded no diagnostic". A consumer that reads the counts sees them for
  timeouts for the first time.
- **Surrendered findings are bounded.** The findings an overrunning connector
  had produced are prepared for at most 5 seconds per expired job; the rest,
  and any its worker changed into something that is not plain data, are
  omitted and counted in that connector's errors. The scan is incomplete
  either way.

## October 17 connector correctness migration (Unreleased)

Three offline connectors change which findings they report, and
`gateway.otel` changes the ids of the findings it keeps. Keep earlier reports
as historical observations and rebuild comparison baselines (the reports
`shadowscan diff` and `dashboard --baseline` compare against, and any
`--baseline-sha256` pin) from a scan at the reviewed revision; a comparison
across this change reports findings as resolved or new that are neither.

- **`gateway.otel` splits nested OTLP callers by service.** A nested OTLP
  export (`resourceSpans`, `scopeSpans`, `spans`) used to lose its resource
  attributes, so every caller was reported under `service:unknown-service`,
  and callers without a `gen_ai.agent.name` merged into one finding per
  provider, `service:unknown-service/agent:unknown-service`. Each
  `service.name` is now its own finding, `service:<service>/agent:<agent>`,
  where the agent defaults to the service. The finding id hashes the
  resource, so these findings have new ids: carry triage decisions and
  suppressions over to them. Flat span records that carry
  `resource.attributes` themselves keep their ids.
- **`endpoint.host` reports only rows tied to AI.** A row is reported when its
  name or path matches an AI product signature or its `type`/`category` names
  an AI category (`ai`, `agent`, `assistant`, `copilot`, `llm`, `mcp`,
  `model`). Other rows of a general software inventory, which used to become
  0.7-confidence findings, are dropped with one informational note that does
  not mark the scan incomplete, and show as resolved against an earlier
  baseline. Check that the runtimes you expect are still reported; if your
  collector exports them without a recognized name, have it set an AI
  `type` or `category`.
- **`endpoint.ebpf` reads native exports and fails closed on unknown shapes.**
  Tetragon, Falco, Tracee and Hubble events, which the connector did not read
  before, now report the connections they carry, so their findings appear as
  new. A record that matches none of those shapes or the flat record shape is
  no longer skipped silently: the connector records one warning and the scan
  is incomplete (exit 3). Fix the export or the collector rather than
  accepting the exit code; see
  [eBPF event formats](connectors/endpoint.md#ebpf-event-formats).

## October 17 precision and completeness migration (Unreleased)

- **Fewer credential findings.** The generic assigned-credential rule no longer
  reports names of credentials: environment reads, member chains, variables
  passed through in source code, labels made of words, and values with an
  ellipsis (now `example-credential` evidence). A comparison with an earlier
  baseline shows those `secret` findings as resolved; review any `--fail-on`
  threshold that only these findings reached. Literal keys, provider key
  formats and unquoted values in env files are reported as before. A file
  with more than five rejected references before a real key now reports that
  key, which the per-signal cap used to drop.
- **Evidence text.** An environment read by name after a credential name
  (`apiKey = process.env.OPENAI_API_KEY`, `os.getenv("OPENAI_API_KEY")`) is
  shown instead of `[REDACTED]`. Any other value after a credential name,
  including an environment read with a default or fallback literal, stays
  withheld. Excerpts and report text change accordingly; finding ids do not.
- **Completeness.** Scans incomplete only because of a file guessed to be an
  MCP configuration that is not one, an import-bound call between 8,192 and
  65,536 characters, or a malformed or binary fixture in discounted test code
  (`include_tests` false) now complete. Each discounted gap is still listed as
  a warning, and a binary test fixture is still scanned for credentials. Set
  `strict_coverage: true` to keep treating every such gap as incomplete
  (exit 3), as before; product code, calls over 65,536 characters and, under
  a test path too, MCP configurations (by a dedicated name such as
  `.mcp.json`, or by a structure or text that declares servers),
  coding-agent instruction, rule and settings files (`CLAUDE.md`,
  `.cursor/rules/`, `.claude/settings.json`, …) and agent manifests and
  cards are gaps either way, because their findings are not discounted
  there.
- **Tool credential files.** `.npmrc`, `.yarnrc`, `.netrc`, `_netrc`,
  `.pypirc`, `.git-credentials`, `.boto` and `.s3cfg` are read for
  credentials only: a credential a rule recognizes in one is a new `secret`
  finding, located by file and line with an empty snippet. `_netrc`, read
  before as a file without a suffix, no longer gives LLM-usage evidence for
  the hosts its entries name, so a comparison shows a framework-usage finding
  that only a netrc entry established as resolved. Report text withholds
  netrc passwords, accounts and macros and Yarn 1 registry credentials
  wherever they appear, so excerpts that showed them change; finding ids do
  not.
- **Realtime agents.** A project that builds OpenAI Agents SDK realtime
  agents (`RealtimeAgent`, `RealtimeSession`, `RealtimeRunner`) is now an
  `agent` finding with its tool and handoff capabilities and a higher
  autonomy floor, under the same finding id it had as LLM usage. A drift
  comparison reports the change once (`capability`, `autonomy`); review it and
  refresh the baseline.
- **Live connector credentials.** `identity.okta` OAuth bearers need
  `okta.appGrants.read` as well as `okta.apps.read`, or every grants call is
  refused and the scan is incomplete. `saas.slack` sends the configured
  `team_id` with `users.list`, the `admin.apps.*` lists and
  `team.integrationLogs`; set it when the token is an org-level one.
  `saas.github-apps` reads the fine-grained PAT list with `app_token`
  (env `GITHUB_APP_TOKEN`) when set, since GitHub serves that list only to
  GitHub App tokens; with an owner's personal token and no `app_token` that
  listing stays refused and incomplete. `identity.entra` selects only v1.0
  service principal properties: live service principal findings take the
  publisher from `verifiedPublisher` and have no Graph creation time. Its
  opt-in agent identity listing needs `AgentIdentity.Read.All`. These
  requirements come from the vendors' published references; no live tenant
  acceptance was performed for them.

## Unreleased review hardening

- **Git 2.45 for clone mode.** `code.github` and `code.gitlab` clone only with
  Git 2.45 or newer. With 2.32 to 2.44 every clone used to end incomplete
  without a recorded revision; it now uses sampled API mode, which is also
  incomplete. Install Git 2.45+ on the worker (the container image has it).
- **Clone URLs must name the listed repository.** A provider `clone_url` or
  `http_url_to_repo` whose path is not the repository's `full_name` or
  `path_with_namespace` is refused, and the repository falls back to sampled
  API mode (incomplete). A clone URL off the API origin now falls back the same
  way; it used to end that repository with an error and scan none of it.
- **Clones connect only to checked addresses, and directly.** After the clone
  URL check's own lookup, ShadowScan resolves the clone host once more just
  before the clone, refuses loopback, private, link-local and cloud-metadata
  answers of that lookup (unless the connector may reach private origins), and
  pins Git to those answers with `http.curloptResolve`, so Git does not resolve
  the name again; the first lookup's answers never reach Git. Git ignores
  `HTTPS_PROXY`, `ALL_PROXY` and the other proxy variables for clones, as the
  HTTP client already does, so allow the worker direct HTTPS egress to the
  clone host. For `code.github` on github.com the clone host is `github.com`,
  which API listing (`api.github.com`) never needed: allow direct egress to
  both. A worker that reaches `github.com` only through a proxy variable now
  clones nothing and scans every repository in sampled API mode (incomplete).
  For GitHub Enterprise Server and `code.gitlab` the clone host is the API
  origin's host, which API listing already reaches directly. A clone host that
  does not resolve in time, or whose name is not plain ASCII as written in the
  URL, is not cloned, nor is a clone URL naming port 0; the repository uses
  sampled API mode (incomplete).
- **Report paths.** `-o` refuses a path through a directory link owned by
  another user; links owned by root or by the current user are followed. Point
  `-o` at a real directory if a scan now fails with that message. Every link on
  the way is checked, a link inside another link's target included. `..` in the
  `-o` path is resolved before any link is followed: `-o mylink/../r.json`
  writes `r.json` beside `mylink`, not in the parent of the link's target, where
  the kernel's own resolution would put it.
- **Redaction.** JWTs whose header is written with whitespace (encoded as
  `IHsi…`, `eyAi…`, `ewo…` rather than `eyJ…`) are withheld in report text,
  evidence and logs as `eyJ…` tokens are, including directly after a dotted
  name with a segment of 16 or more characters
  (`com.example.authenticationservice.<token>`), which the first version of
  this check missed. A token of either kind is withheld to the end of its
  dotted chain, so a token joined to another by `.` or `-`, or after an
  unrelated `eyJ…` segment, keeps no payload or signature, and an encrypted
  token (JWE) keeps no ciphertext; text joined on by a dot (`<token>.json`, a
  full stop) goes with it. A token after a doubly percent-encoded separator
  (`%253D`, `%252F` in a redirect URL nested in another's query) is withheld
  as after a single one. Known gaps: a token glued directly to letters
  (`abc<token>`), one after a separator encoded three times (`%25253D`), and a
  header encoded as UTF-16 are kept. Report text that held such a token
  changes, and so may finding ids derived from it.
- **identity.jwt.** `expected_issuer` or `allowed_algorithms` without
  `jwks_url` is an error (exit 3) in a configuration file, as it was on the
  command line. Tokens whose header has a non-string `kid` or a `crit` list are
  now reported as unverified instead of being dropped. Agent claim values and
  a string `kid` are redacted, then cut at 200 characters; `claim_names` keeps
  at most 100 names, each redacted, then cut at 64 characters.
- **SARIF.** Evidence locations that climb above the scan root or name a
  network path (`//host/share`) get no physical location, and a line number
  beyond 2,147,483,647 drops the region; a merged report with such locations
  no longer produces an upload GitHub rejects or a URI outside the checkout.
- **Human-read output.** Table, Markdown, HTML and CSV show every Unicode format
  character, variation selector and other blank character as a `\uXXXX`
  escape. Emoji presentation selectors (`U+FE0F`) are among them.
- **Plugins run in spawned workers by default.** `plugin_execution` now
  defaults to `process`, so an allowlisted third-party connector runs in a
  spawned worker the scanner can stop at its deadline, and the worker discards
  the plugin's standard output, standard error and logging. Built-in connectors
  are unaffected. `options.plugin_execution: thread` or
  `--plugin-execution thread` keeps a plugin in the scanner process, where it
  cannot be stopped at its deadline. With `plugin_execution` unset, these now
  make the scan incomplete (exit 3) where the thread backend completed:
  - a plugin result above the 16 MiB JSON transport limit;
  - connector configuration or signature objects that Python cannot pickle,
    which only an application building `ScanConfig` itself can pass (YAML and
    command-line values are plain data);
  - an embedding script without an `if __name__ == "__main__":` guard, which
    runs again in each plugin worker before the plugin starts, repeating its
    side effects, including output, which the worker does not discard; the
    plugin fails if that run exits or raises at module level (for example
    `sys.exit(main())`) or uses up the connector deadline;
  - a plugin that starts `multiprocessing` or `ProcessPoolExecutor` children,
    which the daemonic worker refuses.
- **Exit after an abandoned connector worker.** Without a job deadline, a CLI
  scan that abandoned a timed-out connector worker now exits `3` if report
  output and clone cleanup take more than 30 seconds; the report may then be
  missing or truncated and an existing `-o` file may still hold the previous
  report. A job deadline, when set, bounds output instead. See
  [resource limits](production.md#resource-limits-and-incomplete-scans).
- **Git LFS check of a clone.** The check for Git LFS pointer files walks the
  checkout through open directory descriptors. A clone with a directory nested
  more than 64 levels below its root, or an entry replaced while it is read, is
  now reported as one that could not be inspected for LFS pointer files
  (incomplete) instead of being walked by path.
- **Provider tokens stay out of Git.** Git child processes no longer inherit
  `GITHUB_TOKEN`, `GH_TOKEN` or `GITLAB_TOKEN` from the scanner's environment.
  A clone authenticates only with the origin-scoped header ShadowScan sets, so
  nothing changes for configured connectors.

## October 15 collection and registry assurance migration (Unreleased)

Rescan Make, Zapier, code, gateway and cloud audit-log inputs after upgrading.
Scanner-source fingerprints change; retain previous reports as historical
evidence and establish a fresh comparison baseline under the reviewed revision.
A finding that changes registration or ownership is not evidence that its
runtime behavior changed.

Make requires a valid scenario blueprint with an explicit flow array. Invalid
or unreadable detail responses leave coverage incomplete (exit 3), including
when the scenario listing succeeds. A valid empty flow remains supported.
Zapier also validates pagination metadata: malformed continuation fields cannot
establish that every page was collected. Check these diagnostics and correct the
collection or export; do not suppress exit 3 to obtain a clean gate.

CODEOWNERS reads use the same anchored scan directory as source collection.
A root replacement detected before ownership lookup makes the scan incomplete;
later replacements cannot redirect ownership reads to another directory.
A candidate below a file named like its directory (a `docs` or `.github` file)
is absent, as before. A symbolic link in a candidate's path (a linked `docs`
or `.github` directory) is not followed, even to a directory inside the scanned
tree, and makes ownership incomplete (exit 3).
Continue to scan immutable checkouts and exports: confined reads do not provide
an atomic filesystem snapshot.

An exact inventory binding to a gateway caller name is now only a review
candidate when the caller's identity assurance is operator-asserted, unverified
or missing authenticated assurance. With an inventory supplied, the finding
remains shadow and does not inherit the card's owner or declared governance, or
receive registration risk credit. Review the candidate and authenticate the
caller binding at the log producer; renaming a caller or editing its export does
not establish authentication. Provider-authenticated caller fields retain their
existing matching semantics, subject to the supplied log's provenance and scope.
They include the principals of `cloud.aws` CloudTrail callers and `cloud.gcp`
Cloud Audit Log callers, which now record
`metadata.caller_identity_assurance: provider-authenticated-field`: their exact
bindings still approve them, and such approvals no longer carry the
`registry_match_assurance: unverified` metadata and `registry-identity-unverified`
tag that earlier scans added. The `cloudtrail:unknown` and `audit:unknown`
callers collect events that name no principal; they are `unverified`, so a card
that matched one (through a `cloudtrail:*` pattern, say) now yields a review
candidate. Narrow such patterns to the principals you approve.
See [gateway inventory matching](inventory.md#matching-and-approval).

These changes can increase risk scores and cause existing `--fail-on` gates to
fail. Reconcile verified bindings before approving the new baseline. The
`risk_basis: danger` option continues to exclude governance factors; it does not
authenticate a caller or approve an inventory match. Stored historical reports
are not retroactively reclassified; rescan their inputs before using the new
assurance policy for an enforcement decision.

Regression tests and offline evaluation establish implementation behavior only.
Independent review, fresh held-out evaluation and scoped live tenant acceptance
remain required by the existing rollout procedure; this change does not supply
those approvals or credentials.

## Unreleased medium-severity review corrections

Rescan generic SaaS, Teams and affected JavaScript/TypeScript inputs after
upgrading, and establish a fresh comparison baseline under the reviewed
revision. Generic SaaS reports now withhold copies of known credentials from
projected fields before transformations; credential values no longer establish
product or permission matches. Every value under a credential column name is
learned and withheld from the other fields however it looks: a word such as
`test`, `demo` or `here`, or a sequence such as `Abcd1234` or `12345678`, does
not make it a placeholder. Two kinds of value are not learned. A placeholder as
the whole value (`none`, `****`, `xxxxxxxx`, `changeme`, `your_secret`,
`<secret>`, `${SECRET}`) withholds nothing. A value shorter than eight
characters is not removed from other fields, because sanitization would then
withhold every field containing it and such columns often hold flags (`N`, `-`,
`Yes`); instead a field equal to it is withheld, unless it is a flag (a yes/no
or not-applicable word, or at most one letter or digit), and an app ID equal to
it is withheld from the resource. Known gap: a credential shorter than eight
characters inside a longer field (`ChatGPT hunter2`) is still shown. A record
whose app name a credential withholds entirely is skipped with a warning and
leaves the scan incomplete (exit 3). An unreleased revision of this change also
left out every value the placeholder heuristic (`looks_like_placeholder`)
matches and printed such credentials in app names, owners, statuses and
resources in complete scans; regenerate reports made with it and rotate any
credential they show.

**Finding identity.** When a credential is redacted from a generic SaaS
finding's resource (an app ID equal to a short credential included), its ID is
now derived from the redacted resource and a keyed pseudonym of the raw one
(`keyed_credential_digest`), not from a public digest of the raw resource,
which let a reader confirm a guessed credential offline.
Those findings change ID and record `metadata.identity_scope`: `run` without a
stable key, so their IDs are scan-local and `diff` lists them as not comparable
(exit 3) instead of new or resolved; `keyed` when the scan has the operator's
`SHADOWSCAN_IDENTITY_KEY`, which keeps them comparable between scans using that
key. Distinct raw resources keep distinct IDs. Findings whose resource is not
redacted keep their resource-based IDs. Previously saved reports are not
rewritten: handle affected reports under your existing credential exposure and
retention procedures, and establish a fresh baseline for the changed IDs.

Teams findings retain catalog and installed-version observations together.
Consumers of scalar `version`, `bot_id` or `publishing_state` must allow those
fields to be `null` when no nonempty value or multiple values were observed; use `versions`,
`bot_ids` and `definition_observations` for attributed evidence. Each
`definition_observations` entry describes one distinct definition and source;
installation entries carry `installation_count`, `team_count` and `teams`, a
sorted sample of at most 20 team IDs and names, instead of one entry per
installation, so a widely installed app keeps a bounded finding. A finding lists
at most 20 of these entries, in sorted order, and counts the rest in
`definition_observations_omitted`; `versions` and `bot_ids` likewise list at most
20 values each, with `versions_omitted` and `bot_ids_omitted`, so an export with
thousands of distinct definitions also keeps a bounded finding. Permissions,
scalar fields and conflict detection read every observation. RSC permissions
remain definition-requested permissions, not proof of effective grants.
Contradictory observations of one definition mark coverage incomplete.

Zapier/Workato error envelopes and malformed collections now produce incomplete
coverage even beside empty result arrays, and that page is omitted. A missing
or malformed Zapier continuation keeps the page's Zaps and leaves coverage
incomplete. Retained earlier pages do not establish complete inventory.
JavaScript destructuring shadowing can reduce SDK agent attribution; that
correction is not proof an agent stopped running. Benchmark comparison also
rejects newly unavailable scans independently of detection scores, and requires
every selected repository in both baseline and current metrics. Re-score older
metrics if the gate reports missing run status or completeness information.

Validation uses offline exports, mocked API responses and authored source
fixtures. Follow the tenant canary procedure below for live acceptance.

## Unreleased runtime identity and completeness migration

Rescan runtime inventories, GitHub App installations and Python source after
upgrading to this revision. Runtime evidence now follows the executed target
of a supported launcher. Application arguments and package-source options do
not establish that a named AI tool is running, and launches with options a
launcher's grammar does not recognize are not reported. Package runners that an
interpreter runs (`node /usr/local/bin/npx -y pkg`, Defender's `node.exe
...\npx-cli.js`, `python3 /usr/bin/pipx run ...`) and npm's `npm exec pkg`
process title on a node executable, or as the single argument with spaces
that a live `/proc` shows, are read as those runners: an earlier candidate of
this revision reported none of them, with the scan complete, so rescan runtime
inventories it produced. If command-line limits leave arguments unread where
they could change what runs (no argument left, or a launcher's target not
read), the scan is incomplete (exit 3), including when no finding could be
recovered from the retained prefix. A row an export marks `argv_truncated: true`
loses its final argument, which the export may have cut: an earlier candidate
of this revision classified it as complete, so an exported
`npx -y @modelcontextprotocol/s` left the scan complete and empty and a cut
`server-gi` was reported as an MCP server of that name; rescan offline exports
with such rows. Other cut command lines (a JVM or compiler with hundreds of
options, a long prompt after `claude -p`) are classified from their leading
arguments and leave the scan complete; one counted warning reports them all.

Runtime host and user identities are preserved in full within validated input
limits. Previously shortened identities can split into multiple correct
findings, with different IDs and resource bindings. Reconcile affected hosts
and users, regenerate inventory stubs, and review exact approval bindings.
Keep prior reports as historical evidence and establish a fresh baseline under
the reviewed revision. The scanner-source fingerprint changes on upgrade, so
cross-revision differences cannot establish that an agent stopped running.

GitHub App installation counts must agree with unique collected installations.
Contradictory or malformed count information leaves available observations in
the report and marks coverage incomplete. Correct the export or retry the
authorized collection; an empty page alone is not evidence of an empty estate.
Offline totals are checked across each export file, so a paginated export with
one page envelope per line (`gh api --paginate ... | jq -c .`) is accepted as
one listing; keep each organisation's pages in a file of their own.

Python syntax must be supported by the interpreter running ShadowScan. A file
or notebook cell that cannot be parsed keeps lexical observations, reports
incomplete semantic analysis, and cannot gain unsupported semantic agent or
execution-capability claims. Valid neighboring files and parsed notebook cells
remain analyzable. Syntax newer than the interpreter is a gap: Python 3.14's
unparenthesized `except A, B:` on 3.13, or a PEP 695 `type` statement on 3.11.
Use a supported interpreter that understands the source syntax and rescan
before accepting a completeness gate. Python 2 modules, templates
(`{{cookiecutter.slug}}/main.py`) and other `.py` files that are not Python 3
stay a gap until listed in `exclude`; review them before excluding them. In a
test path the scan discounts (`include_tests` off), source that does not parse
only warns unless `strict_coverage` is set. Notebook cells declared another
language (`%%bash`, `%%writefile requirements.txt`, `%%sql`, `%%html`, and
every cell of an R or Julia notebook) that do not parse as Python keep lexical
evidence without a gap; one that parses is bound as Python whatever the
notebook's metadata or cell magic declares. An earlier candidate of this
revision skipped such cells however they parsed, so a repository could label a
Python notebook `"language": "R"` (its kernel still named `python3`), or use
`%%script env python3`, and have an agent with code-execution tools reported
as framework usage without capabilities on a complete scan; rescan
repositories it scanned.

The new tests are authored regression controls. Independent human review,
fresh blinded holdouts and provider-specific live tenant receipts remain
separate rollout requirements; no release or production acceptance is implied.

## Unreleased Kubernetes and Atlassian migration

Rescan Kubernetes and OpenShift exports after upgrading. Earlier observations
could omit an unread export suffix at the object limit, collapse different long
object names into one identity, or reject a valid CronJob. The corrected scan
retains full valid names and analyzes the nested CronJob pod template. A limit
that leaves objects unread, a chunked `List` page (`metadata.continue` or
`remainingItemCount`), an overlong name, a namespace that is not an RFC 1123
DNS label (not a string, or with uppercase letters, a `/` or more than 63
characters) or a malformed template marks coverage incomplete; inspect
retained findings without treating the report as complete estate coverage.

Kubernetes resources with names longer than 160 characters now have their full
name in `k8s:<cluster>/<namespace>/<kind>/<name>`. Regenerate and review cards
for affected resources; an old shortened exact binding does not identify the
full resource. Preserve previous reports as historical evidence and establish
a fresh baseline under the reviewed revision. Collection fingerprints change
with scanner code, so cross-revision differences do not establish resolution.

Atlassian app keys identify a product across sites, rather than one site's
installation. Configure `site` for offline exports as well as live collection,
and bind approvals with `discovery.accounts: ["https://your-site.atlassian.net"]`.
Existing cards without explicit accounts remain unregistered until their site
scope is reviewed and added. Use separate bindings for unrelated sites.
Discovery without a usable site remains incomplete and its generated stub
leaves `discovery.resources` empty pending identity review. Merely adding that
stub to an inventory cannot approve the installation. Configure the verified
site, rescan and regenerate the card before reviewing its exact binding.

Atlassian finding IDs change on upgrade. Exports scanned without a configured
`site` get a new identity discriminator bound to the resolved path of each
export file, so renaming or moving the file changes its IDs; two files in one
directory input stay separate findings even when they share an app key. A
configured site is canonicalized, so an operator whose `site` used an
uppercase host or an explicit `:443` also sees new IDs (a trailing slash was
already ignored). A `site` that is not a plain HTTPS origin now stops the
connector with an error and exit 3 instead of scanning: a value without
`https://`, `http://`, a path (including a Data Center context path such as
`/jira` or `/wiki`), user information, a query or fragment, a trailing dot or a
non-ASCII host. Configure the canonical `site` as `https://<host>`, keep one
site's exports per scan input, rescan and establish a fresh baseline; earlier
Atlassian IDs do not carry over.

The new tests use offline exports. Live connector acceptance and independently
labeled field accuracy still require the existing rollout acceptance procedure.

## October 14 bounded evidence migration (Unreleased)

Rescan affected inputs after updating to this revision. The scanner-source
fingerprint changes; keep previous reports as historical observations and build
a fresh comparison baseline. A reduced flow count is not proof that an agent
stopped running.

MCP inventory findings change score and metadata: tool descriptions are
additionally screened for hidden HTML-comment content, fetch-and-execute
phrasing and terminal control sequences, supported lockfiles are
credential-scanned like every other read file, and a tool name duplicating
another installed server's tool now carries the `tool-name-shadowing` threat
mapping with a default risk weight of 10 (a default-weights change).
Regenerate retained reports and comparison baselines that cover MCP inventory.

**New opt-in settings** (all default off or to the values shown):

- `code.filesystem` (and `code.github` / `code.gitlab` checkouts):
  `inspect_model_artifacts` and `model_metadata_bytes` (default 65,536) for
  bounded GGUF, safetensors, ONNX and PyInstaller metadata inventory. GGUF
  array values (tokenizer vocabularies) are skipped under their own bounds,
  so real llama.cpp models are inventoried. Hugging Face cache links are not
  followed (see the source guide). An
  extensionless file is searched for a PyInstaller cookie only when it starts
  with an ELF, PE or Mach-O header. When a root's 32 MiB artifact budget is
  spent, the remaining selected files are counted in one warning that marks
  coverage incomplete; extensionless files still get normal text analysis.
- `runtime.processes` (live Linux only): `inspect_maps`, `inspect_fds`,
  `inspect_env_keys`, with `max_inspection_bytes`,
  `max_inspection_total_bytes`, `max_inspection_entries`, `max_mappings` and
  `inspection_timeout_seconds` bounds. Reading another user's maps or
  descriptors needs the same user or `CAP_SYS_PTRACE`. Denied or truncated
  selected inspection makes coverage incomplete; do not grant root merely to
  erase that limitation. Kernel threads are not inspected, and a source that
  fails with `ESRCH` on an unchanged zombie with no threads left (state `Z`
  or `X`, `num_threads` 1) is recorded as `not_applicable` without making
  coverage incomplete. `ESRCH` from any other process, and an empty maps or
  descriptor read from a process whose leader thread exited while other
  threads still run (state `Z` with more than one thread), is `unreadable`
  and makes coverage incomplete (exit 3); earlier revisions reported such a
  process as a complete, empty inspection.
- `network.logs`: `dns_max_ttl_seconds` (default 86,400) and
  `dns_clock_skew_seconds` (default 0) bound DNS attribution. These are on by
  default; the options only tune them.

**Exit-code impact.** These inputs can now end a scan incomplete (exit 3)
where the previous revision completed:

- A supported lockfile (`uv.lock`, `poetry.lock`, `pnpm-lock.yaml`,
  `Cargo.lock`) that is malformed, an unsupported version (`Cargo.lock` v1/v2,
  `pnpm-lock.yaml` 5.x), over a limit or a symbolic link, when no
  `pyproject.toml`, `package.json` or `Cargo.toml` sits beside it. Beside its
  manifest the same gap is a warning naming the lockfile and the reason, and
  the scan stays complete; earlier revisions never read these files. A pnpm
  git, tarball, URL or local package is inventoried by name with
  `version: null`, its source kind and a limitation rather than rejecting
  the file, so an AI package locked from a tarball still produces a
  `lockfile-inventory` finding; an entry whose name cannot be told
  (a v6 `github.com/...` key without a `name` field) is still a lockfile
  gap. A `uv.lock` package without a version is inventoried with
  `version: null`.
- A malformed or over-budget n8n, Flowise or Dify graph (dangling or invalid
  connections, duplicate node names). The workflow finding is kept with
  `workflow_graph.status: incomplete`. A `null` n8n output slot is valid. A
  graph that fails unexpectedly affects only its own n8n workflow; the rest
  of the export is still reported. A JSON, YAML or TOML document whose
  `nodes` list identifies no provider is not a graph, however long.
- A live process command line over 65,536 bytes whose dropped arguments could
  change what runs (no argument left, or a launcher's target not read). The
  process is still classified from its leading complete arguments, with
  `metadata.command_lines_truncated`; other cut command lines leave the scan
  complete.
- `SKILL.md` and MCP description audits over 64 KiB, with malformed front
  matter (`SKILL.md` only) or an unclosed fence. An MCP description that
  starts with a `---` line is audited as text: earlier revisions read it as
  front matter, so lines after it other than `name` and `description` went
  unaudited and an unclosed `---` made the scan incomplete. A line over 4,096 characters does not end the
  scan incomplete: it is audited sentence by sentence, so an instruction in
  its middle is reported. Only a single sentence over 4,096 characters is
  audited in its first and last 4,096 characters and marks the audit
  `partial` (`static_instruction_audit.partial`, status `partial` when
  nothing was found). Earlier revisions audited only the two ends of the
  line, so a long line that hid an instruction in its middle, and that the
  audit marked `partial`, now reports `indicators-observed`, and a long line
  of short sentences is no longer `partial`.
- Network records with a malformed observation context, TTL, timestamp or JA4
  value, or over 32 DNS answers. A malformed context in any record other
  than a VPC flow record, an invalid JA4 value, or an answer list over 32
  withholds flow attribution only for the client the record names, or for the
  whole input when the client is unknown; reaching `max_records` withholds it
  for the whole input. A
  malformed TTL or timestamp keeps the record with that field unknown and
  does not withhold attribution for its client (see the network guide).
- CloudTrail exports with invalid timestamps or conflicting event IDs.
  CloudTrail lineage sampling bounds (100 invocations per caller, 2,000
  invocations and 2,000 STS assumptions per run) only mark lineage `partial`,
  with a warning that leaves the scan complete; live collection never
  retrieves STS events, so live lineage is always `unlinked`.

**Finding changes.**

- New finding identities: `lockfile-inventory` findings at
  `<root label>/<lockfile path>` (dependency inventory only, possible
  confidence); with `inspect_model_artifacts`, `binary-artifact` findings at
  the artifact path; with runtime inspection, ML-runtime indicator findings
  at `runtime:<host>:<pid namespace>:<pid>:<start ticks>:ml-runtime`. These
  identities include the PID and start time, so they change with every
  process restart.
- DNS attribution now requires a matching client/context and an answer valid
  at the flow time; flow times are grouped per connection in bounded buckets,
  and a bucket that straddles an answer's validity is not attributed. Logs
  without TTLs or timestamps keep service observations but claim no flow bytes
  or cadence from them. In the bundled demo this removes one finding (a client
  that borrowed another client's expired ChatGPT answer: 133 to 132 findings,
  129 to 128 shadow, high risk 63 to 62) and lowers Cursor's confidence from
  0.8 to 0.5 (risk high to medium). Other demo finding IDs are unchanged
  (gateway caller IDs are scan-local in every run). JA4 log values are
  context only. DNS answers are kept per client and address as merged
  validity intervals, so repeated lookups use no extra storage. When a DNS
  storage bound is reached, only the affected client/address loses DNS
  attribution: its findings carry a limitation, a warning reports the count,
  and the scan stays complete. The Ollama port rule never depends on DNS
  storage. Provenance gains `valid_until` when later answers extended the
  first answer's validity.
- `cloud.aws` CloudTrail callers no longer count exact duplicate event IDs
  twice, and offline `cloudtrail-event` records whose `eventName` is neither a
  collected invocation operation nor an STS assumption are ignored instead of
  reported as LLM callers. A record with no `eventName` (absent, `null` or
  empty) is not ignored: it is skipped as malformed and the scan is incomplete
  (exit 3). Regenerate such exports with the event name before relying on exit
  codes.
- MCP tools keep the `tool-poisoning` rules of the previous revision; a
  bounded sentence audit adds zero-weight `instruction:*` evidence and
  `metadata.static_instruction_audit`, and can also raise the tag. The
  `SKILL.md` audit also covers the front matter `name` and `description`,
  which skill loaders place in the agent context every session.
- n8n workflows and exported graphs gain non-scoring `workflow_graph`
  metadata; inventory and confidence do not depend on it. Lifecycle findings
  gain `lifecycle_observation`, whose samples never name a finding the report
  omits (`observations_omitted` counts them).

Graph paths, AWS lineage and lifecycle assessments are explained metadata.
They do not provide canonical agent identity, effective permissions, approval,
exfiltration proof, or complete visibility. Missing runtime scope is unknown,
and old observations remain historical even when they name the same tool.
Static MCP/skill instruction heuristics cannot certify arbitrary instructions
as safe, and the scanner never executes a discovered MCP server, skill or
model. Lockfile inventory never runs a package manager and does not establish
installation, execution or agency.

The bundled evaluation corpora give the same predictions before and after this
change. These author-written tests are not independent field precision or
tenant acceptance. Review an independently labeled holdout before using new
evidence for enforcement.

## Unreleased attribution migration

This section covers the Python re-export and governance observation changes.
For network connection attribution and hosted-agent invocation, see
[October 9 scan evidence corrections](history/production-change-history.md#october-9-scan-evidence-corrections-unreleased).

- Supported local Python re-exports can expose agent construction previously
  reported only as framework usage. This remains static integration evidence,
  not proof of deployment or execution; see the [source guide](connectors/code.md).
  Rerun affected source scans before comparing totals. A re-export source or
  chain budget, or a connector deadline that leaves a queued root-level
  consumer's import binding unanalyzed, marks the scan incomplete; ordinary
  local modules, however large, do not. A consumer left unbound keeps its
  lexical import and code evidence.
- A scheduled governance audit can verify visible controls while reporting
  bypass settings as unknown. Do not use that partial observation as the complete
  ruleset evidence required for release or rollout. See the
  [merge-policy procedure](operations/merge-policy.md).

The scanner-source fingerprint changes with these fixes. Preserve earlier
reports as historical observations and rebuild comparison baselines under the
new reviewed revision; do not interpret incomparable findings as resolved.

Before using the changed source classifications for enforcement, commission a
fresh holdout using the [frozen field-evaluation procedure](evaluation.md#build-a-genuinely-held-out-field-set).
Include modular agent code: import-only re-exports, cycles, shadowed bindings
and executable shims. Freeze repository/family sampling and acceptance
thresholds before showing scanner results to reviewers. These new authored
regressions must be excluded from that holdout.

The [acceptance verifier](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/tools/acceptance/README.md)
supports static code, AWS and Slack. A code change cannot substitute for human
labels, approved tenant credentials or live acceptance receipts.

## Unreleased redaction and private-origin migration

**Redaction (credential policy).** A YAML block scalar assigned to a name that
carries a credential only when its value is opaque — bare `key`, unlike
`password`, `api_key` or `client_secret`, which always carry one — is now
withheld when the block holds an opaque value. Previously only the single-line
`key: <opaque>` form was withheld, so a Kubernetes secret or Helm value written
as `key: |` over a base64 blob kept its text unless the value itself had a
recognizable format such as an `sk-` prefix or a PEM header. Each line of the
block is read as the single-line form `key: <line>` reads its value, after a
trailing ` # note` or a `- ` sequence marker is set aside: an identifier made of
words (`ipv4Addr6To4`) and a digest after its algorithm (`sha256:<hex>`) keep
their text there, as on one line. A line that form never reads as a value is
tested as it is: a `#`-led line, which in a `|` or `>` block is content, and a
line with other symbols (`Kx7!mQ2&Lp9aB3cD4e`). A value wrapped over several
lines is joined at one indentation, and each run of lines without blanks is
joined across indentation (`#`-led lines included), so a comment, a sentence, a
URL or a path beside the value does not hide it. A bare `key:` over a nested
mapping leaves its entries to be read under their own names when the first one
is read that way (`algorithm: RS256`, or a nested `key:` block); over an entry
that nothing reads again (`stringData:` over an opaque line, or
`value: !!binary |` with a tag or an anchor before the indicator) the whole
block is read. A path, a sentence, a placeholder and a block under a name that
does not name a credential (`data: |`) still keep their text.

Known gaps, measured only on the regression tests and synthetic fuzzing: a
random value of about 8 to 16 characters that happens to read as words
(`RuEnIhCvXo`) on a line of its own keeps its text, exactly as
`key: RuEnIhCvXo` does on one line; a value wrapped into short pieces with a
note, URL or path between them is shown when no group of adjacent pieces is
opaque by itself; a credential holding `:` or other symbols is withheld only
when it contains an opaque run of letters and digits; and joining neighbouring
short lines can withhold text that is not a secret (`createdAt` over
`orderId2`). Names that always carry a credential withhold their block whatever
it holds.
Regenerate retained reports, exports and cached evidence under the reviewed
revision: changing the scanner cannot erase copies already written. Redaction
remains best-effort: it recognizes credential formats and credential-bearing
names, so an arbitrary secret with neither can still survive, and reports hold
sensitive inventory regardless. See the [threat model](security/threat-model.md).

**Private-origin grants.** Every connector now accepts `allow_private_origin`,
which lifts the loopback, link-local, private and cloud-metadata refusal for
that connector alone. Reaching one internal gateway or agent previously required
`options.allow_private_origin`, which applies to every connector in the
configuration and therefore also let repository, endpoint and cloud connectors
in the same scan leave the public internet. Move an existing scan-wide grant
onto the connectors that need it:

```yaml
options:
  allow_private_origin: false
connectors:
  - name: endpoint.mcp
    allow_private_origin: true
    agent_card_urls: [https://agent.internal.example]
```

Move it only onto connectors that make HTTPS requests, such as `endpoint.mcp`
with `agent_card_urls`; an offline run that reads `input` makes none.

A connector that sets the key uses its own value; one that does not inherits the
scan-wide setting, so a connector-level `false` keeps a connector public under a
scan-wide grant. An in-file `options.allow_private_origin: false` is only that
default, so the connector grant above overrides it. The key takes a YAML boolean
or the strings `true`/`false`, so an interpolated `"false"` cannot enable it,
and any other value fails closed without echoing itself. The grant covers this
scanner's HTTPS clients and the addresses a `code.github` or `code.gitlab` clone
is pinned to; the cloud SDKs carry their own egress controls, so keep
restricting egress at the network where that matters. No default changes, so a
configuration that set neither key behaves as before.

`--deny-private-origin` on the command line (or
`ScanConfig(deny_private_origin=True)` for a library caller) is a scan-wide
refusal of the `allow_private_origin` grant: it overrides the scan-wide grant
and every connector-level `allow_private_origin: true` for this scanner's HTTPS
clients, and a connector that sets the key, plugins included, reads `false`
there. It does not revoke `allow_instance_credentials`: under that opt-in the
cloud connectors still contact the instance metadata service, and the
`cloud.gcp` credential transport accepts a private token endpoint. A pipeline
that must keep cloud connectors off both passes `--deny-instance-credentials`
as well; the cloud SDKs' own requests stay outside this policy, so restrict
egress at the network where that matters. A `ScanConfig` with both
`allow_private_origin` and `deny_private_origin` true is refused, and a
configuration file cannot set the refusal.

## Unreleased review migration

After upgrading to the review corrections, rescan source and regenerate retained
reports. Python `try` and `match` alternatives no longer transfer their last
visited binding to another path. Supported literal unreachable alternatives
remain excluded; uncertain branches retain usage evidence. A lower agent
classification is not evidence that a deployed agent stopped executing.
Guarded optional imports (`except ImportError: pass`, or a handler ending in
`sys.exit()`) again keep their SDK binding, so rescans can restore agent
classifications and tool-use capabilities that the first review correction
lowered. A notebook cell that stops (`raise SystemExit`, `sys.exit()`) no longer
hides constructions in later cells, so such notebooks can rise to agent.
Python literals containing control or Unicode separators no longer shift AST
coordinates; rescans can restore registered-tool execution capabilities that
were previously lost in either project or source inventory mode.

For separate source inventory bindings, explicitly select
`agent_granularity: source` on `code.filesystem`, `code.github` or `code.gitlab`.
The supported subset is import-proved Python constructors assigned to a unique
simple name in a straight-line module, class or function scope in a `.py` file. Each supported binding
uses its source file and qualified binding as a separate resource identity;
unrelated line insertions do not change it. Renaming a file or binding changes
the identity. Dynamic, repeated, control-flow-dependent and unnamed constructions
retain project evidence and expose identity limitations; this option does not
enumerate deployed instances, split notebooks or follow every source language.
Execution capabilities of a tool that such a construction, a registration, a
dispatch loop or other code that obtains the function (a computed tools value,
`bind_tools`, a wrapper, method or local decorator) can also reach stay on the
project finding as well as on each named source finding; approving a named
binding does not hide them.

Review generated inventory stubs for each source finding. A project resource
approval does not approve a separate source resource; a broad inventory glob
can intentionally match both and must be reviewed for that scope. Keep previous
reports and establish a fresh baseline after changing granularity or scanner
revision. Source identity and source-analysis changes alter the collection
fingerprint, so incomparable observations cannot establish resolution.

Supported AWS CLI positional credential settings are now sanitized in command
text and argument arrays, including unlisted global options, other letter cases,
PowerShell and cmd continuations, commented or prefixed source argv and an
executable passed separately from its argument list. Regenerate old reports,
exports and cached evidence under the reviewed revision; changing the scanner
cannot erase already retained copies. Continue to protect audit artifacts and
follow the credential handling policy in [SECURITY.md](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/SECURITY.md).
The additive JSON `inventory_present` field distinguishes an explicitly supplied
empty inventory from a scan without inventory reconciliation. CSV now retains
the entire sanitized permission list, including permissions beyond position 30.

The scheduled governance audit can pass its visible-policy checks while its
retained observation reports partial assurance. Inspect `unknown_fields` and
`complete_readback_verified`; an omitted bypass list is never evidence of no
bypass actors. Complete administrator readback remains required by the strict
verification and release paths. After deployment, retain an actual scheduled or
dispatched audit run and both ruleset observations, then verify a fresh complete
administrator readback against the reviewed policy. Synthetic workflow tests
do not establish the deployed token's response or assurance.

Before enabling enforcement, commission a fresh blinded holdout that includes
exception handling, pattern matching, multiple constructions per project,
ambiguous bindings and registered versus unregistered source agents. Freeze
sampling, labels and acceptance thresholds before showing results to reviewers;
exclude the new authored regression fixtures. Follow
[rollout acceptance](production.md#rollout-acceptance) for complete and permission-denied
tenant canaries. The [acceptance verifier](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/tools/acceptance/README.md)
supports static code, AWS and Slack; passing those scopes does not grant
acceptance to other connectors. Human labels and live receipts remain pending
until operators supply them.

Use this operator sequence; dated candidate notes remain under
[Candidate change history](history/production-change-history.md#candidate-change-history) and describe differences
between candidate builds, not between releases.

## Credential evidence identity migration

Code and cloud credential evidence now carries `credential:hmac-sha256:`
pseudonyms made with a domain-separated HMAC and a private key. A report reader
cannot check guessed low-entropy credentials against a public hash. Each Engine
scan supplies one random key shared by its workers, so identical credentials
within that scan have identical pseudonyms. Without an operator key, another
scan produces different credential pseudonyms. Direct calls to the library's
`credential_id()` or `redact()` outside an Engine use an ephemeral process key.

For stable credential correlation between scans, provide the existing
`SHADOWSCAN_IDENTITY_KEY` through a private secret environment: at least 32
random secret bytes, explicitly encoded as `hex:<value>` or `base64:<value>`.
Ambiguous bare encodings, including ordinary 64-character hex keys, now fail
before collection; prefix an existing hex key with `hex:` to preserve its bytes.
Use the same key for the scans being compared. The key also governs gateway
pseudonyms, so rotating it changes gateway identities too. Keep the key out of
configuration files, logs, command-line arguments and shared reports. No key is
generated into persistent storage automatically, and scan reports/export/cache
files never contain it. A process-mode plugin worker is started without the
key in its environment, even when `options.plugin_env` names it, so a
third-party connector receives it only as the decoded run key, and only when it
declares `uses_run_identity_key`. The worker runs as the scanner's user, which
can read the scanner's own environment (on Linux `/proc/<scanner pid>/environ`),
and a thread-mode plugin shares that environment: keep the key out of jobs that
run plugins you do not trust with it.

The report's `collection_scope.credential_identity_schema` is
`shadowscan.credential-identity/v1`; `credential_identity_scope` is `run` or
`keyed`. Resource-based finding IDs still identify the same source observation;
the credential pseudonym in its evidence has the key's scope. Without a stable
key, incremental scanning does not persist results containing credential
pseudonyms, while clean inputs remain cacheable. With a stable key those
results may be reused. Cache format 4 and private key commitments invalidate
older entries or entries generated under a different key. Key rotation also
changes the collection-scope fingerprint, so `diff` cannot claim resolution
across that change; establish a fresh baseline.

Regenerate reports and baselines made with previous candidate builds. Their
`credential:sha256:` values cannot be converted to the new pseudonyms without
rescanning the source credentials. Restrict or delete the old copies and
rotate exposed low-entropy credentials if their digests were disclosed.
Existing gateway correlation mappings using private `credential:sha256:` exact
bindings remain compatible. Those legacy binding values are private and never
enter gateway reports; gateway public identities retain their existing domain
and behavior. Reports still contain sensitive audit evidence and business data.

Synthetic code/cloud, cache, comparison, gateway-binding and publication
regressions validate these behaviors. They do not establish independent human
review or live tenant acceptance.

## Unreleased changes

Incremental scans preserve exact Git filenames, including whitespace. Agent
classification continues to require semantic verification or corroboration of
lexical source matches even for signatures with an agent-indicator flag.

`shadowscan code PATH --diff-base REF` scans only the files committed since the
merge base with `REF`, plus dependency manifests, `.env*` files and coding-agent
settings files. Use it for
pull-request feedback, not as an inventory: its report is not comparable, so a
pipeline that keeps the last report as its `shadowscan diff` baseline sees
earlier findings as unknown, never resolved, and `--incremental` does not reuse
it. Uncommitted, untracked and submodule changes are not scanned. Keep a full
scan of the default branch as the comparison baseline. The option needs Git
2.45 or later; when the diff cannot be computed the connector warns and scans
the whole tree.

An unexpected connector failure, and an unexpected failure while scanning one
`code.github` or `code.gitlab` repository, reports the exception text only when
ShadowScan code raised it; those messages are fixed or already sanitized. An
exception raised inside a third-party SDK or plugin reports only its type
(`code.github: acme/app: RuntimeError`), because its text can echo request data
or opaque credentials that redaction does not recognize. The scan is still
incomplete (exit 3). Alerting keyed on SDK exception text should key on the
connector name and exception type.

Redaction reads a text with a run glued after a `Bearer`, `Basic` or `SSWS`
credential (`<token>--x`, `<token>=x`) twice, as every rule reads the run and
as the earlier rules withheld it with the credential, and shows on each line
only what both readings show; such a token's tail is withheld with it.
Sanitized evidence around these credentials therefore withholds more: where
one reading's line shows nothing the other's does not, that line is kept, and
otherwise the whole line is withheld; a text with a name glued after a
credential on the line after its scheme is withheld whole, keeping its line
breaks. In such a text a run that starts the line after a scheme credential
(`--verbose`, `---`), or a later line after only blank lines or other such
runs, is withheld as well, with a marker in its place where the rest of the
line is unchanged; so is a run that starts the line after a name glued to the
credential that stays beside it (`<token>--token`), which was read only on the
next sanitization, or never after `--token` and `--password`. Each run of a
chain of such lines goes in its own reading, and the rest of a chain longer
than three goes at once before one more reading: the value after the fourth
run was withheld only on the next sanitization, and the value after the fifth
on none. A text with no glued run reads as the earlier rules read it, those
runs included where each is only a name or separator (`--verbose`, `---`,
`=Section=`), unless removing them lets the rules withhold a value after them.
A run there that holds a value (`--http1.1`, `--max-time=30`) is withheld,
with a marker in its place: the earlier rules showed it, and until this
correction it was removed with no marker, so an excerpt lost an option without
showing that anything was withheld. Finding identity does not use evidence
text. Regenerate retained reports, as after any change that withholds more.

A record read this way keeps its shape. A mapping whose keys read alike once
their credentials are withheld in one reading and not in the other
(`SSWS a--auth` and `SSWS b`) stays a mapping: each member is merged with its
own copy in the other reading, and only the members both readings keep are
shown, a key two members share keeping one value as before. Such a mapping
was withheld as one string, so agent definition front matter lost its fields
(`tools`, `permissionMode`) with the scan still complete, an agent card
stopped the connector's analysis of that file, and a finding with such keys in
its metadata or evidence attributes failed to report. Readings of one value
that do not pair up stop with a sanitization limit error, which marks the scan
incomplete (exit 3), instead of changing a container into a string.

Plugin approvals can pin the import target and the providing release
(`--allow-plugin name=module:Class@distribution==version`); a pin is checked
against installed metadata, not file hashes, so keep installing plugins from
reviewed, hash-pinned requirements. Give JWTs
and connector credentials through files, stdin or `${ENV_VAR}` references:
the CLI warns, but still runs, when they arrive as arguments. A credential-file
key (`credentials_file`, `service_account_file`, `token_file`) set with
`--set` warns only when its value looks like an opaque credential rather than
a location: a value with a path or a file-name shape around a random name
(`/run/secrets/<hex>`, `acme-prod-123456-1a2b3c4d5e6f.json`) is a location,
while a bare opaque token, or one under a directory that is itself an opaque
run, still warns, and `tokens` always does. Incremental
cache entries are authenticated only when a stable identity key is
configured; without one, keep the state directory writable only by the
scanner account.
