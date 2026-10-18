# Changelog

What changed in each version of ShadowScan, newest first. Inside a version the entries are grouped by
theme, and inside a theme the newest come first.
[RELEASE_NOTES.md](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/RELEASE_NOTES.md) says what
operators do when they upgrade, and the
[deployment and migration guide](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/production.md)
has the full steps.

Each entry says in a sentence or two what changed and, where it matters, what the change does not
establish. Three flags mark the entries an operator may have to act on: **(behaviour change)** for
findings, exit codes, report fields or defaults that differ; **(breaking)** for an option, API or schema
that is removed or renamed; **(rebaseline needed)** for finding identities, scores or classifications that
change, so earlier reports and baselines no longer compare. Dates are 2026. Reviews named here as
AI-assisted are not independent human review, and results on author-written corpora are not measured field
accuracy.

Until October 16 this file was the engineering log, one long entry per change. That log is kept word for
word in
[`archive/changelog/CHANGELOG-through-2026-10-16.md`](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/archive/changelog/CHANGELOG-through-2026-10-16.md)
for the reasoning, regression-test notes and rejected alternatives behind each summary below; it is a
record and is not updated. The log itself continues in
[`docs/engineering-log.md`](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/engineering-log.md),
one detailed entry per change. New entries go here, one short bullet under the heading it belongs to.

## Unreleased

Changes on `main` since 0.1.2. They are not published or tagged; pin a reviewed commit SHA to use them.
Look for the flags above before moving a baseline or a gate onto a newer commit.

### Security and redaction

- From the October 18 integration of #252-#258: credential review fixes (env-file passwords, typed
  reads, pasted names, repeated credentials, labels and cut-read evidence); credential precision, the
  ci profile's credential limits, incomplete-reason handling, the ADR-005 ownership move and plugin
  worker environments; the credential quota is disclosed, Bedrock owner tags are collected, and
  repeated tags count once. (Oct 17)
- Fuzzing the redactor and the source lexer (see Release, CI and supply chain) found a fault in
  CPython 3.12's own tokenizer that reached two places in the scanner, and a third place that reads
  tokens was hardened with them. All are fixed with regression tests; none exposed a credential. On
  CPython 3.12 a NUL byte after an indented or malformed line makes the interpreter's own tokenizer
  fail with an exception that says nothing about the text (python/cpython#140576; 3.12.13 still has
  the fault). The assignment scanner of `sanitize_text`, the source lexer and the re-export
  prefilter now read tokens through `shadowscan.utils.python_tokens`, which raises one
  `TokenizerFault` for any failure the tokenizer does not document: the redactor treats the rest of
  the text as undecided and withholds it, the lexer masks the rest of the file and marks it
  incomplete (exit 3), and the prefilter calls the module no import-only shim. (Oct 17)
- From #247: process-mode plugin workers inherited `SHADOWSCAN_IDENTITY_KEY`, so a connector not
  declaring `uses_run_identity_key` could read the raw operator key; it is now removed before
  import. Thread-mode plugins share the scanner's process and environment, so this does not apply to
  `--plugin-execution thread`. (Oct 16)
- `clone_environment()` sets `http.sslVerify=true` explicitly (no behaviour change). Not carried
  from #246/#247: DNS pinning (`main` has `clone_pins`), Git CA-bundle propagation (no effect),
  abandoned-worker pruning (already done). (Oct 16)
- #235: `_redact_yaml_multiline_values` is linear again (nested `key:` input risked exit 3) and a
  note in a `key: |` block no longer keeps its credential (word-like random 8-16 character values
  now show); regenerate retained reports and cached evidence and rotate any key they show. (Oct 15)
- #235: `--deny-private-origin` now overrides a connector's own `allow_private_origin: true` via new
  `ScanConfig(deny_private_origin=True)` **(behaviour change)**; it does not revoke
  `allow_instance_credentials`, so also pass `--deny-instance-credentials`. (Oct 15)
- Clone pinning (#234, #236, #237): `clone_pins()` replaces `validate_clone_destination()`, pinning
  Git to a second bounded lookup (`http.curloptResolve`, proxies ignored); clones need direct HTTPS
  egress to the clone host (`github.com` for `code.github`, which API listing never needed), so
  unresolved, refused or proxy-only clones fall back to sampled API mode (incomplete) **(behaviour
  change)**. (Oct 15)
- #234: `process` is the documented `plugin_execution` default; unset, a plugin result over 16 MiB,
  unpicklable config, an unguarded embedding script or a plugin spawning children makes the scan
  incomplete (exit 3); `thread` opts out **(behaviour change)**. (Oct 15)
- JWT gaps: whitespace-header tokens after a long dotted segment (#237) and tokens in dotted chains,
  JWE or after `%253D` were kept, now withheld; finding ids derived from them change and older
  reports may still show them **(rebaseline needed)**. #237's `make secrets` and AI review sanitizer
  caught only 11 of 440 header layouts, now any. (Oct 15)
- Also in this review: `identity.jwt` redacts `kid` and claim names before cutting them, so
  `metadata.kid` and `metadata.claim_names` change (#237); output paths follow only root/user-owned
  links, `..` resolved lexically (#237); Git children lose provider tokens, LFS walk no-follow
  (#232); resolver threads capped at 32 (#236); exit watchdog yields to a job deadline (#234); #231
  docs/tests only. (Oct 15)
- A YAML block scalar under a name that carries a credential only when opaque (bare `key`, unlike
  `password`/`api_key`) is now withheld if the block holds an opaque value; `key: |` over a base64
  blob used to keep its text. (Oct 15)
- Every connector now accepts `allow_private_origin`, lifting the private/metadata-address refusal
  for it alone (before: scan-wide `options.allow_private_origin`); connector-level `false` beats a
  scan-wide grant, and `--deny-private-origin` overrides both. (Oct 15)
- `shadowscan.utils.http` resolves names in a bounded worker (`_resolve_bounded`, up to 20 s, less
  under client limits) as `getaddrinfo` has no timeout; expiry fails closed and a late answer is
  never connected to; only a supervisor is a hard limit. (Oct 15)
- `HttpClient` refuses a duck-typed `session` with `TypeError` (only `requests.Session` or a
  `unittest.mock` double pass), since its proxy, adapter-identity and verify checks would have been
  silently skipped **(behaviour change)**. (Oct 15)
- Redaction withholds JWTs whose whitespace-written header does not encode to `eyJ` (`IHsi`, `eyAi`,
  `ewo`) via a second, budgeted reading that needs an `alg` member; `tools/check_secrets.py` and the
  AI review sanitizer match the base64url shape instead. (Oct 15)
- `write_private_text` refuses a path through another user's directory link; `identity.jwt` refuses
  `expected_issuer`/`allowed_algorithms` without `jwks_url` and marks a non-string `kid` or a `crit`
  header unverified; config diagnostics no longer echo a pasted token. (Oct 15)
- `plugin_execution` now defaults to `process`: third-party plugins run in isolated child processes,
  not the scanner's address space; `thread` restores the old behaviour, and some plugins and
  embedding scripts now fail closed (exit 3) **(behaviour change)**. (Oct 15)
- `validate_clone_destination()` resolved the clone host and refused private, loopback, link-local
  and metadata addresses before Git ran, but pinned nothing; the integration review fixes replace it
  with `clone_pins()`. (Oct 15)
- Generic SaaS inventory withholds every value learned under a credential name except whole-value
  placeholders and values under 8 characters (which withhold only equal fields, so a short
  credential inside a longer field still shows); a name withheld entirely by a credential now leaves
  the scan incomplete instead of silently omitting the app; regenerate reports made with the earlier
  revision.
- `validate_url` rejects backslashes and Foundry token endpoints match a full-host regex; Bedrock
  API keys, Zapier MCP URLs and underscore-scheme `user:password` URLs are withheld; excerpts and
  provider text are redacted before shortening. (Oct 15)
- Plugin workers start with `PYTHONSAFEPATH`, and plugin names must be lowercase ASCII
  `namespace.provider` **(breaking)**; LLM triage summaries withhold e-mail/IP addresses; fleet
  merge drops source `llm_triage` blocks. (Oct 15)
- Every plugin finding is attributed to the plugin, with an id from the plugin's own name and the
  finding's resource whatever `id=` it set, so a plugin can neither report under a built-in
  connector's name nor take the id of that connector's finding; ids of plugin findings that set
  their own change **(rebaseline needed)**. (Oct 15)
- `sanitize` keeps every container a container of its type: a mapping whose keys read alike once
  credentials are withheld collapsed to a string, losing agent front matter at exit 0; unpaired
  readings now raise a limit error (exit 3). (Oct 14)
- A run starting the line after a name glued to a `Bearer`, `Basic` or `SSWS` credential
  (`<token>--token`, `--password`, `--auth`, `--cookie`) is now examined like any later-line run; a
  value on the next line was shown and is withheld on the first pass. (Oct 14)
- A later-line run holding a value (`--max-time=30`) stays withheld and is now marked `[REDACTED]`;
  the October 14 change had removed it with no marker, so an excerpt lost a curl option without
  showing that anything was withheld. Name-only runs (`--verbose`) are kept. (Oct 14)
- ShadowBench cases runner removes hard links, FIFOs, sockets and device nodes from `work/` after a
  stage; a uid 65534 tool could hard link into `work/` another account's file it could read and
  write, which the runner then made root-owned and the adapter read as root. (Oct 14)
- After a `Bearer`, `Basic` or `SSWS` credential, a value-less line-start run (`--insecure`, `---`,
  `=Section=`) is no longer silently deleted from texts with no glued run (curl flags and YAML
  separators had vanished without a marker); value-holding later-line runs stay withheld. (Oct 14)
- When the two readings of a glued-run text do not pair up line by line the whole text is still
  withheld (keeping lines both readings show alike was tried and not carried: it exposed values);
  the scheme pass outside `sanitize_text`/`sanitize` withholds a glued run again. (Oct 14)
- Cases runner: version probes get their own PID namespace, `work/` returns to root without
  group/other write before the symlink sweep, stages get their own IPC namespace and tmpfs over
  `/var/tmp` and `/dev/shm` (host `/tmp` still shared); `fetch_code` disables git filter drivers.
  (Oct 14)
- Fixes a regression that left the tail of a `Bearer`, `Basic` or `SSWS` credential holding `--` or
  `=` plus a letter (or one after `token`) in sanitized text; such text is now read twice, showing
  only what both readings show. (Oct 11)
- `shadowscan run --set credentials_file=<value>` (and the other credential-file keys) warns again
  when the value is an opaque credential rather than a file location; location-shaped values stay
  quiet. (Oct 11)
- The AI review gate's sanitizer now withholds private keys quoted without a footer, with escaped
  line breaks, in a blockquote or encrypted (the base64 body was published), and a key body no
  longer hides a following URL password. (Oct 11)
- `shadowscan run --set` no longer warns when `credentials_file`, `service_account_file` or
  `token_file` holds a file location; credential-looking values there, and `tokens`, still warn.
  **(behaviour change)** (Oct 11)
- An incremental cache entry whose `warnings` list holds anything but text is now a cache miss and
  is rescanned; before, an unkeyed entry with such a list loaded and the objects reached the
  report's warnings. (Oct 11)
- Redaction: the last-resort pass also withholds literals cut before the closing quote, with no
  length cap; the `auth` block rule withholds credential lists and no longer overrides `env` (#190);
  the linearity suite covers the #187 patterns.
- Plugin pins lacking distribution `Name`/`Version` metadata are refused (`distribution-mismatch`),
  a connector approved twice is `conflicting-approval`, and traversal, absolute or `.git` settings
  paths in tree listings abort the repository.
- Hardening from review: too-deeply nested evidence JSON becomes `malformed_findings` instead of a
  crash, a quoted private key is withheld as a whole block, and a superseded run posts no
  contradictory review (`!cancelled()`).
- LLM triage refuses a reply naming `verdict` more than once (`status: unparseable`), sends no
  sampling parameters, bounds replies at 4,096 tokens and adds opt-in
  `options.llm_triage.structured_output`; offline injection canaries ship.
- `--allow-plugin` and `options.plugins` accept pinned `name=module:Class` (`target-mismatch`) and
  `name=module:Class@distribution==version` (`distribution-mismatch`, checked before import);
  duplicate approvals are refused.
- Redaction withholds the value in `Bearer token <value>`, keys ending in `secretvalue`,
  `tokenvalue`, `passwordvalue` or `apikeyvalue`, setter-call literals and `auth` mapping fields,
  plus a last-resort pass for generated-looking literals.
- `shadowscan jwt TOKEN...` and `run --set` with a credential value warn on stderr that arguments
  show in process listings and shell history (value never echoed); wrappers parsing `2>&1` as a
  report break. **(behaviour change)**
- Keyed incremental cache entries carry `payload_hmac_sha256` and unverifiable ones are rescanned
  (existing entries miss once); the HTTP policy judges NAT64 `64:ff9b::/96` by its embedded IPv4,
  keeping private and metadata forms refused.
- Fixed: on CPython 3.12.0 to 3.12.3, redacting a long single line could take quadratic time because
  `tokenize` copies the physical line for every token; CI ran a later 3.12, so it never showed
  (Ubuntu 24.04 ships 3.12.3).
- `shadowscan merge` refuses autonomy bases with non-string or out-of-vocabulary values and ignores
  an unreadable `approval_gate.scope`.
- Add `examples/k8s-network-policy.yaml` (default-deny egress; live-mode pods get DNS and public
  HTTPS only); pin that LLM triage replies cannot change risk, shadow status, kind or tags. Ignore
  `*.pyo`, `*.egg`, `*.whl` (#176).
- LLM triage is bounded by `options.llm_triage.budget_seconds` (default 300) and the job deadline
  (unreached: `status: skipped`); replies parse in linear time and over 16 KiB are refused, after a
  hostile reply lost a report. Still advisory.
- New `options.trusted_registries` (exact type and id): only those registries' approved records
  register findings and approve bound resources, rebuilt every scan; setting it counts as having an
  inventory, so unmatched findings read as unregistered; `allow_auto_approved` and
  `allow_registered_only` opt in weaker records.
- Records replayed from an offline export no longer approve (a forged export line had sanctioned any
  runtime) unless a trusted entry sets `allow_offline_records: true`. Tests are synthetic; nothing
  validated against a live registry.
- A launch is unidentified (`mcp-registry-unidentified`) when options, env vars, relative or UNC
  launchers, mounts or a command plus URL can change what runs, so no catalog vouches for it; checks
  use configured, not redacted, values.
- `mcp-insecure-transport` and `a2a-plaintext-interface` read URLs as WHATWG parsers do
  (`http:/host`, `http:\\host` and `http:///host` are plaintext remote hosts);
  `mcp-insecure-transport` also flags an authority holding a backslash or user information; the
  shared launcher parser also now assesses `npx.cmd`-style launchers.
- A record binds only its own project's resources; another project's engine, agent or
  `RuntimeReference` approves nothing, closing a cross-project approval by a trusted app. Synthetic
  fixtures only; nothing validated against a live project.
- Descriptors are parsed as bounded strict JSON and kept only as sanitized summaries (raw documents,
  authorizer settings and OAuth `customParameters` never exported). Test data is synthetic; nothing
  was validated against a live account.
- `auth_mode: delegated` takes a user Graph token only from the env var in `delegated_token_env`,
  redacts it, checks unverified `tid`/`scp`/`idtyp`/`exp`/audience claims, never refreshes and never
  falls back to app-only.
- Card `signature` is verified only against the operator's `agent_card_jwks_url` (card/header
  `jku`/`jwk`/`x5u`/`x5c` ignored); `verified` never approves a finding, and a verified card is
  projected as the form it signed.
- Only the exception type is reported when a connector or `code.github`/`code.gitlab` repository
  fails in third-party code, so SDK text stays out of reports (#171); Go SDK import aliases resolve
  before credential evidence is published.
- Positional SDK credential arguments (incl. import aliases) are resolved before source evidence is
  published; export size, strict-JSON or sanitizer rejections abort dump publication, keeping the
  prior file.
- Supported AWS CLI positional credential settings are withheld in command text and argument arrays,
  including nested copies in evidence and caches; variable references and documented placeholders
  are preserved.
- `aws configure set` credential values are withheld after newer global options, in other letter
  cases, for `aws.cmd`, across continuations and split executable/argv forms
  (`spawn("aws", [...])`); commented-argv scanning stays linear.
- The hidden-comment check now reports HTML comments of any length (skipped beyond 4,000 bytes
  before) and unclosed ones Markdown passes through as HTML; instruction checks read the confined
  snapshot, incomplete past 512 KiB.
- Agent instruction files are scanned for hidden HTML comments, fetch-and-execute pipes and
  invisible or bidirectional characters; tags `hidden-instructions` (20), `remote-code-fetch` (15),
  `invisible-text` (10) raise the risk of the findings that show them. **(behaviour change)**
  (Oct 8)
- The crawler UA pass tokenizes only `mozilla/` lines in linear time; the old regex went quadratic
  on unclosed and escaped quotes, so a planted file could stall the walk past the connector deadline
  and discard the tree's findings.
- The benchmark runner and exit probe now refuse privileged execution and use private directories
  with symlink-rejecting atomic writes **(behaviour change)**; namespaces need an externally
  isolated disposable host and do not establish filesystem isolation.
- Lossy text decoding now checks every bounded window, so an ASCII prefix cannot hide an invalid or
  control-character body; benchmark candidate URLs need an exact parsed GitHub or GitLab hostname,
  so host-like text in a path or query cannot fake provenance.
- Stray NUL bytes no longer evade matching: the code connector matches names with NULs removed
  (`api.open<NUL>ai.com` runs as `api.openai.com` in bash), and any source file with NUL bytes is
  lexed both with and without them, masking only what both mask and staying incomplete unless they
  agree.

### Collection and coverage

- `go.mod` require blocks are read in linear time, and never as a dependency named `(`. (Oct 18)
- From the October 18 integration of #252-#258: every coverage gap takes one decision (strict
  accounting, then a ci declaration, then the test-code discount, then the budget) and verdicts are
  judged per root and per repository, so exit 3 means something again; `diff` no longer resolves what
  the ci profile or the budget stopped reading; engine review fixes (surrendered findings, explicit
  deadlines, the cache key and split jobs); connector deadlines scale to their input and an overrun
  keeps its findings; connector correctness, CI check names and benchmark framing. **(behaviour
  change)** (Oct 17)
- A JavaScript-family string that ends in a backslash (`"\`) no longer makes the lexer return a span
  longer than the text; spans are clamped to it. Found by the same fuzzing. (Oct 17)
- `FilesystemConnector` (`shadowscan/connectors/code/filesystem.py`, 5,456 lines) is now a
  1,009-line façade over four collaborator classes in modules of their own, the split ADR-005
  describes: `CodeOwnership` (Git history and CODEOWNERS), `TreeWalker` (the walk and its
  fail-closed coverage accounting), `FileScanner` (the reading, redaction and analysis of one file)
  and `ProjectFindings` (finding construction), with the records they share in `scan_records.py`. No
  module of the split exceeds 2,000 lines. The methods moved unchanged apart from renamed calls and
  the wiring between the parts, every name importable from `filesystem.py` still is, and tests now
  patch the class or module that owns a name. Old and new code gave the same findings, diagnostics,
  log messages and connector state on 1,560 direct runs of `code.filesystem` (in two orders of the
  runs) and the same command-line output on 165 inputs, with Git 2.47. (Oct 17)
- `KubernetesConnector.analyze` (ruff `C901` complexity 66) is now a short driver over helpers that
  each own one concern: reading records and `List` envelopes, the NetworkPolicy pre-pass, an
  object's identity and pod spec, its containers, exposure tags and the finding. Findings, ids,
  tags, evidence, warnings and their order are unchanged: old and new gave byte-identical results on
  20,940 runs over the fixtures and mutated exports, for the Kubernetes and OpenShift connectors,
  with and without a small object limit. (Oct 17)
- Clone mode needs Git 2.45 (`MINIMUM_CLONE_GIT`), as metadata reads pass `--no-lazy-fetch`; clones
  on 2.32-2.44 ended incomplete without provenance and now fall back to API mode **(behaviour
  change)**. A provider clone URL must name the listed repository. (Oct 15)
- With timed-out connector workers and no job deadline, a 30-second daemon-thread watchdog keeps the
  CLI from hanging in report emission or clone cleanup; it calls `os._exit()` as a last resort, so
  the report may be missing or truncated. (Oct 15)
- Make scenarios require a valid blueprint and explicit flow array, so invalid detail responses mark
  collection incomplete rather than reading as an empty workflow; Zapier validates pagination
  metadata before accepting an inventory's end. (Oct 15)
- CODEOWNERS reads stay anchored to the directory opened for collection: a root replaced before
  lookup leaves the scan incomplete, and a link in a candidate's path is not followed (ownership
  incomplete). (Oct 15)
- Zapier/Workato reject provider error envelopes and malformed collections (page omitted; bad Zapier
  continuation keeps its Zaps, incomplete); Teams findings stay bounded (`installation_count` and
  `team_count`, at most 20 listed items), show requested RSC permissions, not verified grants, leave
  ambiguous scalar version and bot fields `null` and mark coverage incomplete on contradictory
  observations of one definition.
- No backtracking package regex runs on over-long runtime-process arguments; the Python tokenizer
  charges its matching budget between tokens (long lines fail closed on CPython 3.12.0-3.12.3);
  excerpts judge literals from the shown part plus 256 characters. (Oct 15)
- GitHub App installation inventories check declared totals against unique installation IDs across
  all live pages or an offline export; inconsistent or malformed counts mark coverage incomplete
  while keeping valid observations. (Oct 15)
- Unparseable Python source and notebook cells keep lexical observations but mark semantic analysis
  incomplete (no agent classification for unparsed ranges); cells declared another language are
  still parsed, and Python 2 stays a gap until `exclude`d. (Oct 15)
- Agent-run review fixes (corpora predictions unchanged): non-registry pnpm packages inventoried
  (`version: null`); `ESRCH` is `not_applicable` only for a zombie with no threads left, otherwise
  `unreadable` (exit 3); long instruction lines audited per sentence; invisible operators raise
  `tool-poisoning`. **(behaviour change)** (Oct 14)
- An independent cross-check found three more: AI events outside the CloudTrail lineage list (now
  counted, with an untraced warning), misread display-format STS expirations, and n8n
  `openAiAssistant` not classed as an agent; a record with no `eventName` is now malformed (exit 3);
  a Kubernetes object without a valid `kind`, or a non-quantity `nvidia.com/gpu`, now makes the scan
  incomplete (exit 3), and `0` GPUs no longer make a GPU workload. **(behaviour change)** (Oct 14)
- Bounded `uv.lock`, Poetry, `pnpm-lock.yaml` and `Cargo.lock` parsing adds `lockfile-inventory`
  findings (inventory only; no package manager runs; credential-scanned, values redacted); an
  unusable lockfile warns beside a manifest, else leaves the scan incomplete. (Oct 14)
- Non-scoring metadata: `workflow_graph` for n8n/Flowise/Dify exports (a bad graph marks coverage
  incomplete but keeps the finding), CloudTrail assumed-role lineage (`partial` at sampling bounds;
  live lineage is unlinked), `lifecycle_observation` on endpoint/process findings. (Oct 14)
- Opt-in `inspect_model_artifacts` (GGUF, safetensors, ONNX, PyInstaller) and Linux
  `inspect_maps`/`inspect_fds`/`inspect_env_keys` use bounded, confined reads; nothing is unpickled
  or executed, no process memory or env values kept. Command lines over 65,536 bytes leave the scan
  incomplete. (Oct 14)
- `gateway.logs` adds `internal_model_hosts`; Ollama-style and `/generate` routes count as model
  traffic only with a model field or on a known or declared model host, and help-desk chat widgets
  and registries on parsed non-model hosts are no longer callers (excluded requests get one advisory
  warning and the scan stays complete); k8s/OpenShift recognise serving-engine images and a
  `command` or `args` that is not a list of strings makes the scan incomplete; n8n HTTP model-call
  and `mcp` rules reworked. (Oct 14)
- Kubernetes/OpenShift: unread object suffixes and chunked `List` pages (`metadata.continue`,
  `remainingItemCount` above zero) make the scan incomplete (exit 3); full object names are kept, so
  finding IDs change for names over 160 characters; names over 253 characters and non-RFC 1123
  namespaces are rejected, not shortened; CronJob pod specs are analyzed. **(behaviour change)**
  **(rebaseline needed)** (Oct 14)
- `cloud.gcp` records an invalid engine name or failed project-number lookup so `--dump-records`
  replays are incomplete, and oversize settings files or truncated GitHub/GitLab listings make
  approval gates read `some-actions`.
- `identity.entra` skips the connector before any request (exit 3), in every configuration, when a
  pre-issued `access_token`'s `tid` differs from a `tenant_id` given as a tenant ID; a domain
  `tenant_id` cannot be compared, so give the tenant ID with a pre-issued token. **(behaviour
  change)**
- On those versions each token's line copy counts against the assignment work budget, so a hostile
  line ends in `SanitizationLimitError` (finding omitted, scan incomplete, exit 3) instead of
  stalling; use 3.12.4 or later. **(behaviour change)**
- Settings readers no longer abort `endpoint.inventory` on non-string values
  (`permissions.defaultMode`, `approval_policy`); malformed or unreadable settings
  (`settings-file = unreadable`) cap the approval gate at `some-actions`.
- `identity.entra` no longer attests a scan made with a user-issued or undecodable `access_token`:
  it still completes, with an advisory warning, and `shadowscan diff` reports such a comparison
  incomplete instead of resolving findings a narrower view did not see. **(behaviour change)**
- A Bedrock action group with malformed function entries no longer claims an every-action approval
  gate from the readable ones, and the scan is marked incomplete with a warning.
- A cut-short local walk (`max_files`, `max_entries`, deadline) keeps that root's approval gate at
  `some-actions`, also in `code.github`/`code.gitlab` clone mode; case-variant settings files
  (`.CLAUDE/settings.local.json`) are now read; a `server.json` package without a string type and
  identifier, or past 16 packages, is a parse error that makes the scan incomplete.
- New `cloud.gcp` options `agent_registry` and `gemini_enterprise`, off by default, read Agent
  Registry and Gemini Enterprise agents (`agent_registry_version` picks `v1` or experimental
  `v1alpha`); with both off and `discovery_collections` unset, no new API calls, but a project whose
  only AI API is Agent Registry now gets an enabled-APIs finding.
- New export records `registry-coverage` and `project-number`; an unreadable record, incomplete
  replay or foreign-project record voids every completeness claim. Replaying a dump with a failed
  listing is incomplete again (exit 3).
- New opt-in `cloud.aws` service `registry` reads AWS Agent Registry and AgentCore records
  (`registry_arns`: other accounts' approved ones); `services` now excludes `registry` by default,
  so existing configs add no API call or finding.
- `listing_complete` needs a listing with no denial, failed page, skipped record or
  `max_registry_records` cap hit (default 1000); gaps make the scan incomplete (exit 3), and a
  rejected runtime, gateway or record withdraws registry claims.
- AgentCore gateway findings are now named by gateway ARN via `GetGateway`, since ids from
  `ListGateways` could never match registry bindings. Live gateway finding ids change, so
  re-baseline them. **(rebaseline needed)**
- A failed `GetGateway` call, or a runtime or gateway without its ARN, makes the scan incomplete
  (exit 3), live or replayed alike; registry records from exports written before the new coverage
  markers replay as incomplete, so regenerate them. **(behaviour change)**
- `identity.entra` gains opt-in `include_agent_registry` (Agent 365 packages as
  `microsoft-agent-365` registry records, bounded by `max_package_lookups`) and
  `include_agent_identities` (Entra Agent ID), both off by default.
- Caller-scoped listings (delegated, or a user token as `access_token`) give
  `listing_complete: false`, `unknown` bindings and exit 3; replays with a mismatched or null
  `tenantId` are incomplete. Synthetic tests, not live-validated.
- `code.filesystem` and `endpoint.inventory` record Claude Code, Codex and Goose approval settings
  as `metadata.approval_gate`, `cloud.aws` Bedrock action-group confirmation and `cloud.azure` Logic
  Apps `metadata.trigger_types`.
- `endpoint.mcp` adds an opt-in A2A card probe: `agent_card_urls` (refused above `max_agent_cards`,
  default 100), same-origin redirects only, private/loopback refused unless
  `options.allow_private_origin`, in-card URLs never fetched.
- Each card is an `a2a-agent-card` finding; fetch, size, JSON or validation failures make the scan
  incomplete, and `input` plus `agent_card_urls` is refused (exit 3). A card declaring a protocol
  version other than 0.x or 1.x is still reported, with a warning that makes the scan incomplete, in
  `code.filesystem` as in the probe; A2A 1.0 `supportedInterfaces` now fill `url` and
  `protocol_version`, empty before for 1.x cards. Card records replay from `--dump-records`,
  re-validated.
- Attestation needs a completed connector, successful listings and a confirmed principal (AWS: STS
  account, not caller ARN); plugins, timed-out jobs and delegated Entra scans never attest
  **(rebaseline needed)**. Not validated live.
- `identity.entra` reads `GET /organization` after authenticating (`Organization.Read.All` or
  `Directory.Read.All`, or `User.Read` delegated): a denied or ambiguous answer only leaves the
  scope unattested, but a returned tenant that differs from a GUID `tenant_id` stops the scan;
  `cloud.azure` reads configured subscriptions under the same rules.
- VPC Flow Log `SKIPDATA` and invalid or contradictory statuses now count as incomplete coverage
  (`NODATA` stays valid). **(behaviour change)**
- Record exports enforce strict JSON and replay byte limits, rejecting a failed replacement
  atomically.
- C# files not naming `Microsoft.Extensions.AI` skip the tool-loop proof, so large unrelated files
  no longer exhaust the token budget and mark the scan incomplete. Authored regressions; no
  independent labels or live-tenant acceptance.
- In `agent_granularity: source` mode, tool regions of a file's verified constructions resolve in
  one pass, so a module with many named agents sharing `tools=TOOLS` no longer exceeds the per-file
  deadline and goes incomplete.
- `shadowscan endpoint` is incomplete (exit 3) when a known path cannot be inspected (symlink,
  denied access, redirected `%APPDATA%`) yet scans the rest, and reads the profile's
  `AppData/Roaming`, not `%APPDATA%` **(behaviour change)**.
- `shadowscan endpoint` covers every `endpoint.inventory` location, so profiles without AI clients
  stay `diff`-comparable; `code.filesystem` `include` scans skip the incremental cache; an
  unselected link target is a coverage gap.
- `diff_base` (`shadowscan code PATH --diff-base REF`) scans files committed since the merge base
  plus manifests and `.env*`, tags `diff-scan`, is neither comparable nor cached, and needs Git
  2.45+ (else a full scan with a warning).
- Malformed `code.filesystem` input (bad TOML/JSON, configs, manifests, MCP `servers`) yields
  file-attributed input-defect warnings that keep partial findings yet fail closed (exit 3);
  `strict_coverage: true` promotes them to errors.
- Integrity and ambiguity failures (duplicate keys, conflicting dialects, resource-limit hits,
  undecodable files, unscanned symlink targets) still fail closed; malformed templates and fixtures
  get no completeness exemption.
- The JS/TS/TSX lexer now lexes brace-less JSX elements as attribute values
  (`title=<span>…</span>`), which wrongly marked real repositories incomplete; malformed JSX still
  fails closed.
- Credential-regex allowance now scales with input size, so keyword-dense megabyte files no longer
  abort the secret pass (`MatchTimeoutError`); `shadowscan.signatures.validate` also rejects secret
  patterns below a CPU-time throughput floor.
- The walk lists manifests and MCP/agent config before source and stops listing after half the time
  a file can still start, so deadlines cut the low-signal tail; slow-to-list trees now exit 3
  **(behaviour change)**, so raise `connector_timeout_seconds`.
- `triage: true` (`shadowscan code --triage`) runs a fast subset scan of manifests, MCP/agent
  config, flow exports and IaC, skipping source analysis, credential detection and content sweeps;
  it is always reported incomplete, so it cannot pass as a full scan.
- Fixed false `incomplete source lexical analysis`: a Rust ordinary double-quoted string may now
  span lines (an unclosed one stays incomplete), and `.js`/`.mjs`/`.cjs` files with JSX are also
  read as JSX (`.ts` never is).
- Fail-open fixes: Rust C raw strings and `\x7F`/`\u{...}` char literals, misread as quotes that
  masked code across lines, are now recognized; a `<` after `<` no longer opens JSX in `.js`,
  `.mjs`, `.cjs`, `.jsx` and `.tsx` (`mask<<shift>limit`), which masked code while the file reported
  complete; the code it masked is now visible, and a file this leaves ambiguous is incomplete (exit
  3). **(behaviour change)**
- On the v2 real-world repositories (a tuning set, not held out) 77 of 100 lexically flagged files
  now complete (notebook cells excluded). Ruby heredoc interpolation, binary content, config parse
  failures, deadlines and notebook cells still mark scans incomplete.
- `.js`/`.mjs`/`.cjs` files are read as plain JavaScript, and as JSX when ambiguous or holding a
  closing tag; if both complete only what both mask stays masked (so `src/*.js` in JSX text cannot
  hide code), and if neither does the file is incomplete (exit 3).
- From a 326-repository benchmark (28% of scans incomplete, exit 3; finding IDs unchanged): the JS
  check for SDK bindings shadowed by a method parameter ran a quadratic pattern over whole files and
  exceeded the 0.1 s budget on a 22 KB file; it now runs per window.
- Lexers no longer call ambiguous (exit 3), or misread as code: multi-line Rust/PHP/F# strings, PHP
  8 attributes, F# type variables, C# `@"""` strings, JSX in `.js`, TS non-null before division and
  Qt `.ts` files; unclosed, Ruby and heredoc strings stay incomplete.
- Files with a few stray NULs in valid UTF-8, or non-UTF-8 text without NUL, are read with a warning
  instead of skipped (`strict_coverage` counts each as a gap); dense NUL, UTF-16/32 without BOM and
  mostly-invalid content stay gaps. Agent front matter with `: ` parses again.
- Truncated model-id literals, catalog assignments or data-file references now mark coverage
  incomplete (references only if a data file is discounted as a catalog), so a model past the limit
  cannot give an empty scan reported complete; the limit counts only vendor-stem candidates.
- More lockfiles go unread and `*.log`/`*.har`/`*.snap` join `oversize_skip_globs`; with
  `scan_secrets: false`, oversize docs (and test fixtures unless `include_tests`/`strict_coverage`)
  are skipped with a warning, but by default stay exit-3 gaps so planted keys are not lost
  **(behaviour change)**.
- `scan_timeout` is now analyzing-thread CPU time with a 4x wall cap, so a descheduled scanner no
  longer hits `MatchTimeoutError` **(behaviour change)**; NuGet central package files
  (`Directory.Packages.props`) now declare dependencies; throughput work leaves findings unchanged.
- The JSX walk no longer reads valid JavaScript (`yield <a> 1`, `of <a> 1`, a left shift) as masking
  elements: `.js`/`.mjs`/`.cjs` are read as plain JavaScript first, and in the JSX reading only
  reserved words like `return` or `typeof` let `<` open an element after a word.
- A `.ts`/`.tsx` file starting `<TS>` or `<tileset` is no longer masked whole as Qt or Tiled XML
  (only well-formed XML with a declaration or doctype counts); PHP `#[` files are lexed as PHP 8 and
  pre-8, masking only what both mask; heredoc markers close where no name character follows.

### Detection and signatures

- From the October 18 integration of #252-#258: precision, completeness and connector requirements
  from an outside review; risk scoring gains capability interactions. (Oct 17)
- IDs of generic SaaS findings whose resource a credential redacts now come from the redacted
  resource plus a keyed pseudonym: they change and are scan-local (`metadata.identity_scope: run`)
  unless `SHADOWSCAN_IDENTITY_KEY` is set **(rebaseline needed)**.
- JS/TS destructuring declarations (aliases, nested patterns, defaults, rest) now invalidate
  shadowed SDK constructor bindings; property keys, initializer references and members like
  `options.const` declare nothing.
- MCP client configs and CloudFormation/ARM JSON are recognised from parsed structure, not a
  byte-prefix window, so padding cannot hide them; the Kubernetes connector inspects
  `initContainers` and `ephemeralContainers` (privileged ones add `privileged-pod`). (Oct 15)
- Runtime process classification reads the executed launcher target, not later arguments or
  package-source options (interpreter-run `npx`/`pipx` count as the runner); a cut command line
  marks coverage incomplete if dropped arguments could change what runs. (Oct 15)
- Correlation compares Azure resource IDs case-insensitively, treats `gserviceaccount.com` service
  accounts as one global identifier, and stops reading `projects/` repo paths as GCP names;
  `identity.entra` replays naming another or no tenant get `metadata.account_attributed: false`.
  (Oct 14)
- `SKILL.md` and MCP tool descriptions get a bounded sentence audit (zero-weight extra signal for
  MCP; lines over 4,096 characters mark it `partial`; text over 64 KiB, malformed front matter or
  unclosed fences mark coverage incomplete). From #217: hidden-comment, fetch-and-execute and
  terminal-control screening, and a default risk weight of 10 for `tool-name-shadowing`
  (default-weights change). (Oct 14)
- DNS-to-flow attribution now needs a matching client and context and an answer valid at flow time
  (`dns_max_ttl_seconds`, `dns_clock_skew_seconds`); the demo drops one finding (133 to 132) and
  Cursor confidence 0.8 to 0.5. Live DNS enrichment stays deferred (#210). **(behaviour change)**
  (Oct 14)
- Name signals marked `ambiguous: true` (Gemini) stay `ai-name-hint` possible products with no tags
  or agent indicator, so tag-based risk weights can stop matching, until a non-name signal
  corroborates them; OAuth URLs count by parsed hostname only; unattributed apps' non-AI evidence is
  bounded at 0.35 (`UNATTRIBUTED_APP_MAX_WEIGHT`). (Oct 14)
- Correlation: `metadata.related` keeps only exact identifier links (provenance in
  `metadata.related_details`); shared AWS-managed and Bedrock model ARNs are not compared, and name
  similarity or unverifiable scope goes to `metadata.related_candidates` as review hints. (Oct 14)
- `lowcode.servicenow` ignores generic or ambiguous AI names and `saas.notion` ignores a bare "bot"
  name; Wudpecker and Tactiq are recognised as meeting note-takers by name and domain
  (benchmark-derived: Wudpecker is the ShadowBench estate positive the 2026-10-11 run missed, Tactiq
  was added with it). (Oct 14)
- Not carried from draft PRs #216, #203, #204 (among others): a global name-weight cap, signature
  `negative_context`, Okta weight cuts, a benchmark-derived Slack client ID, User-Agent gateway
  exclusions. Finding ids unchanged except `gateway.logs` with `internal_model_hosts`. (Oct 14)
- A Workato recipe whose Workbot trigger line carries no trigger name records no initiation instead
  of reading as event-triggered; the connector no longer guesses. (Oct 11)
- Triggers a person operates (n8n manual/chat/form, Workbot commands, Zapier Chrome/Interfaces) and
  Make `on-demand` (a person or a call can start it) no longer count as autonomy evidence; Workato
  recipes are no longer all read as event-triggered; ServiceNow `tool-use` needs the agent's
  `sn_aia_tool` records and its `autonomous` capability an `autonomous` flag or `agent_type`,
  Salesforce `RecordBeforeDelete` flows now carry `autonomous`, and the gateway `always-on` tag is
  initiation evidence only when corroborated, so risk levels move (the README demo now shows 63 high
  and 54 medium findings). **(behaviour change)**
- Scans without an inventory or trusted registries now clear `shadow` and `registry_match`; `merge`
  reads registration only from `inventory_present` sources, and conflicting matches become
  ambiguous. **(behaviour change)**
- Adverse drift covers new findings, added permissions or capabilities, removed mitigating tags,
  changed tool digests, higher autonomy, findings turning shadow and lost registry matches; risk
  changes stay unclassified.
- Mapping errors corrected (`exposed-llm-server`, `unauthenticated-mcp` leave LLM07; privilege tags,
  `code-exec`, `saas-actions` leave ASI08); a `secret` maps to LLM02 and AML.T0055 only with an
  exposure tag like `hardcoded-credential`.
- Servers match registry listings only by exact package, URL or manifest identity, adding
  `metadata.mcp_registry` and zero-weight review tags such as `mcp-unpublished` and
  `mcp-registry-deleted`; publication never lowers risk.
- Agent-type findings carry `metadata.autonomy`: proven floor, not-ruled-out ceiling, L0 Chatbot to
  L5 Fully Autonomous. An L2 ceiling is configuration evidence, not proof of behaviour; rules are
  synthetic, author-written.
- New risk tags `a2a-plaintext-interface` and `a2a-card-signature-invalid` (10 each) raise scores
  for non-loopback `http://`/`ws://` interfaces and malformed signatures **(behaviour change)**.
  Tests are synthetic, no live agent.
- Network flows are attributed by connection identity; hosted-agent invocation evidence binds to one
  event's method, provider and operation, so management requests no longer imply runtime activity
  and attempts do not establish success.
- An explicit `FunctionInvokingChatClient` registered via DI or held in fields is now framework
  usage, not an agent (`UseFunctionInvocation()` stays an indicator); standalone .NET tools stay
  framework usage **(behaviour change)**.
- Lifecycle observations match on the complete case-insensitive device value, so different DNS
  domains and short/FQDN spellings no longer alias, and repeated correlation clears stale endpoint
  activity tags **(behaviour change)**.
- A bounded subset of local Python import-only re-exports is resolved without importing or executing
  scanned code; unsupported or ambiguous bindings stay conservative, and consumers left unbound are
  reported incomplete.
- Python try/except and match branches join conservatively, so one alternative's import cannot bind
  another path; opt-in `agent_granularity: source` gives named constructions their own identities
  (static evidence, not instance counts).
- Tool execution evidence stays on the shadow project finding when anything beyond a named
  construction's literal tools list can reach it (computed lists, `bind_tools`), so approving a
  named binding no longer hides the capability.
- Guarded optional imports are restored after the try/except join fix (handlers ending in
  `sys.exit()` or `quit()` do not continue); notebook cells bind separately, so a cell that stops
  Run All no longer makes later cells unreachable.
- Projects that construct and serve an MCP server report the `mcp-server` capability; Spring AI
  `defaultTools(new ...)` chains establish an agent; `provider.databricks` ignores a bare `mlflow`
  dependency, so a classic-ML training project no longer gets a low-confidence LLM-usage finding.
  **(behaviour change)** (Oct 8)
- Path context scales evidence by 0.5 in docs/example dirs and 0.4 for generated files; fully
  discounted projects get `docs-only`, `example-code-only` or `generated-code-only`, capped
  confidence and lower risk **(rebaseline needed)**.
- Projects with independent signal types gain a `corroboration:cross-signal` item (0.10, or 0.15 for
  three or more), raising confidence and likelihood **(rebaseline needed)**.
- Eleven new signatures (Agency Swarm, Rivet, Devin, Bumblebee/Instructor (Elixir), LangChain
  (Elixir), R LLM clients, Lua LLM clients, Rust AI crates, Homebrew AI tools (heuristic), MLflow AI
  Gateway and Cloudflare AI Gateway); `import` and `code` signals accept the languages `c`, `cpp`,
  `elixir`, `r` and `lua`, and `conda` dependency signals cover the OpenAI, Anthropic, Hugging Face,
  LangChain and LlamaIndex packages. An author-written 130-case `benchmarks/sab_realworld` benchmark
  covers them, not independent validation.
- Data files are deny-list catalogs only for whole-word `blocklist`/`denylist`/`blacklist` names, so
  allowlist, egress, firewall/WAF and substring names no longer drop findings (a firewall file
  allowing OpenAI egress reported nothing).
- Generated code is recognized by file name only (`*_pb2.py`, `*.generated.*`), so `codegen`
  directories and `*.auto.*` files are ordinary source again; a manifest-bearing docs/example
  project root keeps full weight.
- `import Nx`/`library(torch)` no longer report LLM usage; `platform.mlflow-ai-gateway` ignores bare
  `mlflow`; `coding-agent.devin` ignores lowercase `devin.md`: a known recall gap for a root file
  (on the authored benchmark, case `rw-repo-057` becomes a false negative and coding-agent recall
  falls from 1.00 to 0.90).
- Crawler user-agent domain discounts apply only within a complete quoted UA value, so a provider
  endpoint in another value on the same line, or a later occurrence of the same host, remains
  detection evidence.
- Exported low-code flows with a verified agent node (n8n, Dify `agent_mode: enabled`) now yield
  `kind: agent`, matching `lowcode.n8n`; plain LLM chains stay `workflow`. Kind and title change,
  identity does not **(behaviour change)**.
- Provider domains quoted inside crawler user-agent strings
  (`…-Bot/1.0; +https://provider.example/`) no longer count as provider usage; the discount is
  recorded as a visible note naming the hosts.
- The `mcp.` host regex needs a common TLD, and hosts-file/ad-block/resolver/proxy-rule hosts no
  longer count as product use (non-source documents only); provider-less `secret` findings are
  retitled `Hard-coded credential in <file>` (`unattributed-credential`) **(behaviour change)**.
- New `mcp-server` capability (server idioms like `FastMCP(` and `@mcp.tool`, not client idioms)
  scores 5 risk points like `tool-use`, raising MCP server projects' default risk by 5 (behaviour
  change; `risk_weights.capabilities` accepts it; see `docs/production.md`).
- Model-id patterns are now anchored: `gpt-4-turbo-docs.md` and `command-line` stop matching and
  `text-embedding-004` is Gemini only; LiteLLM-style routes (`bedrock/`, `ollama/`) attribute the
  routed provider; `voyage-*` and Cohere `command*` are new **(behaviour change)**.
- `AnthropicBedrock(` now attributes `provider.aws-bedrock` and `AnthropicVertex(`
  `provider.google-vertex-ai`, previously Anthropic code evidence **(behaviour change)**; new
  signals cover LangChain4j and Spring AI modules, Voyage AI, OllamaSharp and `framework.koog`.
- `framework.stagehand` keeps only the agent SDK; new `platform.browserbase` (`browsing`, no agent
  indicator) means hosted-browser-only projects are not agents **(behaviour change)**. Some
  framework idioms now declare `languages`; bare OpenAI `chat.completions.create(` is `ambiguous`.
- Implemented MCP servers are first-class: import-bound SDK constructions become evidence, the
  finding is titled `MCP server in <dir>: ...` with `metadata.mcp_server`, and lexical
  Go/Java/.NET/Rust idioms carry `mcp-server` only if the SDK is imported or declared.
- Model identifiers are now provider evidence: quoted literals in source/notebooks and model-key
  values in config files hit anchored `model` signatures; source ids can anchor a `model-ids-only`
  finding (capped at 0.6), config ids anchor nothing (`data_mention`) **(behaviour change)**.
- Uncorroborated lexical patterns, weak mentions (below 0.3), test-path mentions (unless
  `include_tests`) and CI images (`ci_image`) no longer establish frameworks, providers or findings;
  they appear as `metadata.potential_frameworks` / `metadata.potential_providers`, with a note
  naming dropped projects **(behaviour change)**.
- Configuration naming four or more products is no longer discounted as a catalog: `.devcontainer/`
  and top-level `config/`/`conf/`/`settings/` data, files assigning variables, and data files named
  by a quoted code path (by name, not under docs/website directories) **(behaviour change)**.
- The `mcp.<vendor>.<tld>` host form of `protocol.mcp` matches country-code TLDs (bar `py`, `md`,
  `rs`...) and more generic ones again **(behaviour change)**; candidates followed by a call, index,
  underscore or assignment are code, and in source must start a string or URL.

### Reports and CLI

- From the October 18 integration of #252-#258: the reporter layer is typed by a `Renderer`
  protocol (#252); OCSF events always carry the required `time` attribute; OIDC-only sign-in clients
  named with a common word are no longer findings (#253). **(behaviour change)** (Oct 17)
- `shadowscan/cli.py` (1,922 lines) is now the package `shadowscan/cli/`: the options shared by
  every command, report output and deadline handling stay in `__init__.py` and each command group
  has a module of its own. The `shadowscan` command, its options, output and exit codes are
  unchanged, and `python -m shadowscan.cli` and the names tests patch on `shadowscan.cli` keep
  working. Old and new gave the same output for every `--help` text and for runs of the report
  formats, `diff`, `merge`, `dashboard`, `endpoint` and `inventory` on the fixtures, apart from the
  scanner-source digest inside a report's fingerprint. (Oct 17)
- SARIF locations resolve `.`/`..`, drop ones above the root or naming a network path, cap
  `startLine` at the 32-bit limit and escape lone surrogates; `terminal_text` and saved reports
  escape every Unicode format, variation-selector and blank character. (Oct 15)
- Out-of-range report timestamps are omitted from OCSF, CycloneDX and SARIF instead of aborting the
  report; `inventory check` and `signatures list` strip terminal control sequences from untrusted
  fields. (Oct 15)
- OCSF `metadata.product.vendor_name` is now `Nexus ShadowScan` (was `Project Nexus`); SARIF
  `informationUri`/`helpUri` and the CycloneDX VCS reference follow, while the SARIF and CycloneDX
  tool name stays `ShadowScan` so GitHub code scanning keeps matching alerts. **(behaviour change)**
  (Oct 14)
- `signatures list --category`, `signatures test --ecosystem` and `inventory stubs --kinds` reject
  unknown values instead of matching nothing; `code --mode` without a remote target is a usage
  error. **(behaviour change)** (Oct 11)
- `dashboard` and `controls` read `inventory_present` as `merge` does, refusing older reports that
  record registration (exit 1, "rescan before merging"); `merge` keeps match state only from sources
  whose verdict it adopts; the CSV report labels a finding that only inventory-less sources assessed
  `unassessed` when the report has an inventory, and leaves the cell blank when none was involved.
  **(behaviour change)**
- Adds `shadowscan dashboard REPORTS... -o dashboard.html`, a static page (no external assets, one
  hashed script) led by a coverage panel where an unrun connector reads "not collected", never 0;
  tests use synthetic reports, not a live fleet.
- `--inventory-json FILE` writes a versioned `shadowscan.inventory/v1` export for BI and SIEM
  (credential findings counted, not listed; no evidence snippets); `--baseline`, `--history DIR` and
  `--as-of` add drift, history, staleness.
- Dashboard exits 3 when an input or source is incomplete or the `--baseline` comparison is not
  comparable (files still written), and 1 on invalid input; outputs are 0600, never via symlink.
  `merge` now records `inventory_present` and connector runs (`shadowscan.fleet-merge/v2`).
- `shadowscan merge` no longer counts inventory-less findings as shadow; shadow merges as
  `true`/`false`/`null`. A non-boolean `inventory_present`, or a missing one with registrations
  (v0.1.x), is refused, exit 1. **(behaviour change)**
- Add `shadowscan controls REPORT.json` (`--format markdown|csv|json`, `--framework`): per NIST AI
  RMF, ISO/IEC 42001, EU AI Act and AIUC-1 entry, referencing findings by risk level and evidence
  status; `merge` output refused (exit 1).
- Add `diff --fail-on-drift CLASSES` (exit 2; incomplete stays 3), `--baseline-sha256 HEX`
  (mismatch: exit 1) and `--max-baseline-age-days N` (expired or undatable baseline: exit 3).
- A merged fleet report's `started_at` is `null`, not the merge time, when any source lacks a valid
  timezone-aware start time, so an age limit cannot pass an undated baseline. **(behaviour change)**
- Threats and controls are derived at export and never read back, so they cannot change identity,
  risk, `diff` or merging. Add `python -m shadowscan.mappings.validate` (`make mappings`); the
  container build context now ships the catalogs.
- `merge` re-classifies using the widest oversight and initiation (bypass in one report plus a
  schedule in another now reaches L5, not L4) and keeps the lowest declared level, so
  `autonomy-understated` ignores report order.
- Live `cloud.aws`, `cloud.azure`, `cloud.gcp` and `identity.entra` scans can attest a comparable
  `collection_scope`, so `shadowscan diff` can resolve findings between two complete live scans
  instead of always exiting 3.
- CSV exports all permissions; table, Markdown and HTML reports show inventory reconciliation for a
  supplied zero-agent inventory; JSON reports gain the additive `inventory_present` field.
- `shadowscan merge` refuses a finding id reused for another identity (exit 1), validates source
  completion, counts and fingerprints, keeps an incomplete source incomplete and retains the highest
  source risk.
- New `shadowscan endpoint` scans AI client config locations of a workstation profile without
  walking the home directory (new `code.filesystem` `include` option); findings get an
  `endpoint:<hostname>` prefix (`--label`). (Oct 8)
- New `shadowscan merge` combines JSON reports from several machines (`metadata.merged_from`),
  `diff`-comparable only if every source was complete and comparable; `--format cyclonedx` AI-BOM
  covers endpoint and fleet reports. (Oct 8)
- `diff_base` scans are `comparable: false`: `shadowscan diff` lists earlier findings outside the
  window as unknown, not resolved; `--incremental` never reuses them; `--diff-base` applies to local
  PATHS only (remote repositories in the same run are scanned in full; without PATHS it is a usage
  error) **(behaviour change)**.
- New `--format ocsf` emits OCSF 1.1.0 Detection Findings (class_uid 2004) for SIEM pipelines,
  completeness marked; `shadowscan diff --shadow-only` displays only shadow findings while counts,
  incompleteness and exit codes use the full comparison, and its JSON document always carries the
  full comparison plus a `shadow_only_view` id list.
- CycloneDX now lists an implemented MCP server (a finding with the `mcp-server` capability, not an
  MCP configuration) as a `services[]` entry in group `mcp-server` with languages, transport, tools
  and files (capped at 20/10, disclosed as `tools-omitted`/`files-omitted`).

### Governance, registries and identity

- Gateway callers with operator-asserted, unverified or missing assurance stay shadow when an
  inventory is supplied; exact card bindings are review candidates only **(rebaseline needed)**.
  `cloud.aws`/`cloud.gcp` now record `metadata.caller_identity_assurance`: provider-authenticated
  principals keep exact approval without the `registry-identity-unverified` tag earlier scans added,
  and the `unknown` caller of events without a principal is a review candidate. (Oct 15)
- Rescan and rebuild baselines: long runtime identities now give full resource bindings and may
  change finding IDs, so regenerate inventory cards **(rebaseline needed)**; verified with authored
  fixtures only, not field accuracy or live tenant acceptance. (Oct 15)
- Atlassian app approvals (carried from #218) need an explicit site/account constraint; unscoped
  cards need a reviewed `discovery.accounts` binding; discovery without a usable site keeps its
  evidence with incomplete coverage (unbound inventory stub), so configure the canonical site and
  keep one site per input. Finding IDs change for no-`site`, uppercase-host and `:443` exports; a
  non-origin `site` exits 3 **(rebaseline needed)**. Offline fixtures, not live tenants. (Oct 14)
- A control no finding references reads `not observed` only when every report is complete; otherwise
  `unknown (scan incomplete)`, `(inventory not supplied)` or `(risk class not declared)`. Incomplete
  input still writes output and exits 3.
- Output is labelled "Evidence references, not compliance determinations" (author mappings, not
  independently reviewed), never says a control is met and has no score. Catalogs gain a required
  `review` field (only `author`).
- Capability Cards (`schema_version: 2`) accept a `governance:` block, recorded as
  `metadata.declared_governance` (declared, not verified, never changing risk); new rules map
  declared EU AI Act classes to Articles 12, 14, 26 and 50.
- `shadowscan diff` labels each changed field with a drift class (`inventory`, `capability`,
  `autonomy`, `governance`, `coverage`) and an adverse flag; it also compares autonomy,
  `tool_definition_sha256` and registry reconciliation status, and `diff`, `merge` and
  `inventory stubs` now reject a report whose finding metadata is malformed at those paths.
- `metadata.compliance` is replaced by edition-qualified `metadata.threats` and `metadata.controls`.
  Author mappings, not compliance determinations, not independently reviewed; old values are dropped
  on `diff`/`merge`. **(breaking)**
- Vendor registry record contract (`metadata.registry_record`, `shadowscan/registries.py`): only
  built-in connectors declaring `emits_registry_records` may emit; a malformed record makes the scan
  incomplete (`engine.registries`, exit 3).
- `metadata.registry_reconciliation` matches by exact binding identity, never name, and changes
  neither shadow status nor risk. Only `approved`, `registered` and `pending` records register what
  they bind; others are `not-comparable`.
- Add `options.mcp_registries` (up to 16 SHA-256-pinned snapshots; `approved: true` marks the
  approved catalog) and `shadowscan mcp-registry snapshot`. A bad snapshot is unused and makes the
  scan incomplete (`engine.mcp-registry`, exit 3). Tests use a synthetic snapshot; no live registry
  fetch or tenant acceptance.
- New factor `mcp-not-in-approved-registry` (15) applies only when approved registries are
  configured and loaded, to enabled servers no approved registry lists or can identify; it is
  excluded from `danger_score`.
- Records bind only the exact reasoning engine or Dialogflow CX agent they reference, in scope only
  after a complete Vertex AI or Dialogflow CX listing; identity and URL matches are hints, and
  Gemini Enterprise listings are never complete.
- A registry-created `DETECTED_FROM` binds the exact AgentCore runtime or gateway ARN; API-created
  provenance binds nothing. Auto-approved records are not human review and approve via
  `trusted_registries` only with `allow_auto_approved`.
- An org's own package with no approval request is `registered`, not `approved` (needs
  `allow_registered_only`); failed lookups and unknown types are `unknown`; publisher-declared ids
  cannot approve tenant objects **(behaviour change)**.
- Capability Card `schema_version` 2 declares `autonomy_profile.level` (0-5; v1 levels ignored with
  an advisory); a level below the observed floor adds `autonomy-understated` (weight 10);
  `options.risk_weights.autonomy` defaults to 0.
- A level outside 0-5, a non-mapping `autonomy_profile` or a `schema_version` other than 1 or 2
  makes the inventory invalid; `merge` rejects a source whose autonomy block is malformed; replayed
  endpoint approval entries the settings reader could not have written are dropped with a warning
  that makes the scan incomplete.

### Benchmarks and evaluation

- From #249: README cross-tool chart, generated by `tools/readme_visuals.py` from the committed
  2026-10-11 `metrics.json`; shows surface coverage and in-scope recall with interval, with
  authorship and "not a verdict on any product" caveats. (Oct 16)
- Discovery benchmark comparisons reject newly unavailable runs regardless of F1, need every
  selected repository in both metric sets and never call failed or incomplete negative scans clean;
  offline fixtures do not establish live tenant acceptance or field accuracy.
- Not carried from #229 (would make the README less accurate or break a test): removing the
  statement that later ShadowScan runs on the ShadowBench estate (after the 2026-10-11 run) are
  in-sample, and dropping ShadowScan from what the benchmark author wrote. (Oct 15)
- README benchmark tests now read the Benchmarks section up to the next heading, and the in-sample
  test also requires the explanation: rules changed with the run's errors in view, so fewer errors
  are not evidence of better field accuracy. (Oct 15)
- Cases scoring counts a missing row on a surface the tool does not run as `unsupported`, not an
  error, so `--surfaces`/`--cases` partial runs stop charging phantom errors; committed 2026-10-11
  metrics are unchanged. (Oct 14)
- Bundled corpora and the estate replay are author-written offline inputs, not measured production
  precision, independent review or live tenant acceptance. Rules changed with the 2026-10-11 run's
  errors in view, so later ShadowScan runs on the ShadowBench estate are in-sample (7 of 12 errors
  gone is no evidence of better field accuracy); rebuild baselines **(rebaseline needed)**. (Oct 14)
- From the agent-run review of #199 (not independent human review): on the code surface,
  out-of-taxonomy reports on a negative case are now a case-level false alarm; re-scoring 2026-10-11
  changes only AgentDiscover (code specificity 100% to 90%, balanced accuracy 64% to 62%). (Oct 14)
- Scoring fails closed: `score` refuses a results file whose `rows_sha256` differs unless `--force`
  (2026-10-11 tools stay `rows_unbound`), exits 2 on malformed estate `runs.json` rows, and
  Numbat/vet wrappers stop recording bad runs as empty inventories; committed estate results
  unchanged. **(behaviour change)** (Oct 14)
- ShadowBench adds two author-written tracks, `cases` and `estate` (fictional Adatum Logistics),
  across all nine surfaces (#193, #194, #195); not independent review, field precision or a vendor
  verdict. (Oct 12)
- Vendor letter grades and two PDFs are not carried; estate org renamed Vantor to Adatum (identical
  re-scoring); an uncommitted `.vscode/` file is replaced and `AGENTS.md` marks benchmark corpora
  untrusted. (Oct 12)
- Scoring fails closed on both tracks: failed, missing or incomplete runs earn no true negative, and
  unvouched results or a drifted freeze are refused unless `--force` or `--allow-freeze-mismatch`.
  (Oct 12)
- `cases` tools run as uid 65534 with `no_new_privs` in fresh namespaces. Re-scored `cases` (raw
  rows unchanged): ShadowScan estate recall 619 of 738 (was 622), AgentDiscover code precision 96%
  (was 9%). (Oct 12)
- Closes gaps measured by the author-written head-to-head benchmark
  (`archive/reviews/head-to-head-2026-10-08.md`; ten open-source tools, synthetic estate; not
  independent review); six corpus cases added. (Oct 8)
- The `benchmarks/sab_realworld` harness compared labels like `crewai` with IDs like
  `framework.crewai`, so signature recall read 0; results regenerated (agent-tier accuracy 0.60, was
  0.70; signature recall 0.90), author-written.
- The v2 scorer validates result metadata and detections against the declared corpus, and labels
  v2-added entries held out only for the frozen run recorded before commit 7e523ba (9fdaf85), which
  tuned the lexer on them; other runs report them as not held out.
- Discovery-benchmark scoring and the gate now count incomplete runs (exit 3): `metrics.json` gains
  `incomplete_runs` and `compare` fails when a baseline-complete repository turns incomplete
  **(behaviour change)**; 43 of 87 ShadowScan runs in the 2026-10-09 baseline were incomplete.
- `--repos` benchmark runs are now scored over the selected repositories only (unselected ones
  scored as missing, so the gate always reported a recall regression); isolation is a rebuilt
  environment and a dead proxy that clients may ignore, not a network or filesystem sandbox.
- Adds `tools/evaluation/benchmark_followup_corpus.json`: 24 authored synthetic cases (16 positive,
  8 negative, no `known_gap` waivers) reproducing misses and false positives from the 87-repository
  benchmark; labels are author-written, not independent review.
- Adds the `tools/discovery_benchmark/` harness: it runs `code.filesystem` and other open-source
  code-surface discovery tools on the same pinned public repositories (unprivileged, no network or
  credentials) and scores precision and recall per repository, category and value.
- Adds `benchmarks/shadow-ai-discovery/`: pinned corpus (positives, controls, vocabulary
  near-misses), session-labeled expected facts with evidence pointers, results and report; labels
  are author-written, not independent human review, and cover the code surface only.

### Release, CI and supply chain

- From the October 18 integration of #252-#258: lint, tests and tooling review fixes, and a failing
  CI test step names each failing test in the checks API from the legs' JUnit reports. (Oct 17)
- The test jobs run the suite on one pytest-xdist worker per CPU (`-n auto --dist worksteal`),
  including the coverage-traced Python 3.11 leg that took about 40 minutes run serially;
  `make test-parallel` uses the same options. pytest-cov combines the workers' data before the
  floors are checked. The 60-minute job limit is unchanged because CI timings with parallel workers
  are not yet known. (Oct 17)
- The release workflow names its two attested bundles `provenance.sigstore.json` and
  `sbom.sigstore.json` (they were `provenance.json` and `sbom.json`), the suffix that
  release-signature checks such as OpenSSF Scorecard's Signed-Releases look for among a GitHub
  release's assets. It still creates no release: `docs/operations/publishing.md` has the maintainer
  attach the wheel, the sdist, `SHA256SUMS` and both bundles to a release created by hand, and shows
  how to verify a download against them. **(behaviour change)** (Oct 17)
- `make self-scan` (part of `make check`) and a CI step scan this checkout with
  `examples/shadowscan.self-scan.yaml` and require a complete report: findings do not fail the step,
  an incomplete scan (exit 3) does. The few paths that deliberately trip a scanner limit, and the
  docs site that `make docs` builds into a checkout, are named exclusions with a reason each, and
  `tests/test_self_scan.py` keeps the list explained, narrow and in step with make, CI and the
  documents. A plain `shadowscan code .` in the checkout still exits 3. (Oct 17)
- New `tools/complexity_gate.py` (`make complexity`, part of `make check` and `make check-fast`, and
  a step of the CI test job) holds every function above ruff's `C901` limit of 20 and every
  `shadowscan` module above 2,000 lines to `tools/complexity_baseline.json`: nothing listed may
  grow, nothing new may join, and an improvement fails the check until `--update` lowers the
  baseline, so the room it made cannot be spent again. `--rebaseline` records a reviewed rise as a
  visible diff of the baseline. The gate fails closed (exit 2) when ruff or the baseline cannot be
  trusted. See `docs/testing.md`. (Oct 17)
- New `tools/fuzz` fuzzes `sanitize_text`, `sanitize` and the source lexer with Atheris 3.1.0,
  hash-locked in `requirements-fuzz.lock` (Linux x86_64 only). `make fuzz` and the weekly `Fuzz`
  workflow run it, the workflow with a read-only token and no stored corpus; a failing lexing input
  is kept as an artifact, but the input that beat the redactor is never printed or uploaded. The
  same checks run as Hypothesis tests in the ordinary suite (`tests/unit/test_fuzz_targets.py`), and
  `make audit` and the dependency audit cover the new lock. Atheris is not an engine OpenSSF
  Scorecard's Fuzzing check recognises, so that score does not change. See
  `docs/operations/fuzzing.md`. (Oct 17)
- `pyproject.toml` caps `click`, `rich`, `PyYAML`, `requests`, `PyJWT[crypto]` and the cloud SDKs
  (`boto3`, `google-auth`, `azure-identity`, `oci`) at the next major; `regex` stays uncapped (a
  year cap would shut out security fixes). (Oct 15)
- The caps protect unlocked `pip install NexusShadowScan` from resolving an untested major;
  deployment and CI keep the hash-locked `requirements.lock`, whose pins already fit the caps, so
  the reviewed version set is unchanged. (Oct 15)
- Module-level helpers of `connectors/code/filesystem.py` (6,249 lines) moved verbatim into
  `path_context.py`, `project_evidence.py`, `model_identifiers.py`, `source_text.py` and
  `excerpts.py`; `filesystem.py` re-imports every name importable before. (Oct 15)
- No behaviour change: with a fixed `SHADOWSCAN_IDENTITY_KEY` the offline demo report is identical
  apart from timestamps and `collection_scope.fingerprint`; ADR-005 records the move, its four
  collaborator-class moves stay open. (Oct 15)
- The optional Black Duck job now needs `BRIDGECLI_DOWNLOAD_VERSION` (passed as
  `bridgecli_download_version`), so it cannot fetch the vendor's current, unreviewed CLI; with no
  `x.y.z` pin it fails at its first step (first merged: skipped, reporting success). (Oct 15)
- The pin fixes a version, not content: the bundle comes from `repo.blackduck.com` over HTTPS with
  no checksum check, and tools the Bridge CLI fetches for a scan are not covered. (Oct 15)
- Build lock is now installed by `make install`, `make install-dev` and both CI test jobs (rerun
  `make install`); the former-name check accepts the old slug only in listed forms and covers
  Unreleased; `distributions.py` rejects a `.` or `./` sdist member instead of an `IndexError`.
  (Oct 14)
- Carries Dependabot #200 (nine CI constraint pins; `requirements-ci.lock` regenerated with the
  documented uv command, since Dependabot cannot refresh hash locks) and #201 (upload-artifact
  7.0.2, download-artifact 8.0.2, codeql-action 4.38.3, by full SHA). (Oct 14)
- Hygiene: macOS legs install `requirements-build.lock` (release evidence records the build frontend
  version since #202); `.github/labels.yml` gains `breaking-change` and `do-not-merge`;
  `make check-fast` added; `.gitignore` covers local credential stores (`.netrc`, `.pypirc`,
  Terraform state). (Oct 14)
- Repository renamed from `aisecnomad/Project-Nexus` to `aisecnomad/Nexus-ShadowScan` to match the
  `NexusShadowScan` distribution and `shadowscan` command; links and metadata follow, released
  entries and frozen benchmarks keep the old name, and the governance audit keys on
  `github.repository_id`. (Oct 14)
- Releases now ship an sdist beside the universal wheel (0.1.2 was wheel only), built with
  `python -m build --no-isolation` from the clean `git archive`; `tools/release/distributions.py`
  requires one wheel and one sdist with identical core metadata and no tests; the SBOM is attested
  for both. (Oct 14)
- The AI review gate's published review now states when findings named files outside the diff and
  were dropped; the publishing runbook's rebuild recipe guards `TMPDIR`. (Oct 11)
- AI review gate: also runs on label changes so `ai-review: blocked` applies without a push,
  publishes nothing for a run a newer push cancelled, and keeps in-diff findings when another names
  a file outside the diff. (Oct 11)
- `make build` and CI's wheel build stamp archives with the HEAD commit time (`SOURCE_DATE_EPOCH`)
  so rebuilds reproduce released bytes; Black Duck and Checkmarx One workflows skip Dependabot pull
  requests. (Oct 11)
- Semgrep runs `semgrep ci` from a digest-pinned image, the Checkmarx step no longer sends the job's
  `security-events: write` token to the vendor tenant, and the AI review gate opens evidence
  directories without following symlinks.
- Adds a deterministic, fail-closed AI Review Gate: missing or malformed evidence blocks it, AI
  cannot approve or merge, and human approval and required checks stay the merge gate. Not
  independent human review; no release authorization.
- The gate can block but never pass (the PR author commits its evidence): otherwise it is `neutral`
  (`advisory_only`), which GitHub counts as passing, so `tools.governance_check` refuses rulesets
  requiring it (`advisory_check_required`).
- Add opt-in Checkmarx One (#179) and Semgrep (#180) SARIF workflows and harden Black Duck's (#182):
  SHA-pinned actions, timeouts, runs only when configured, fork PRs skipped (Black Duck also
  read-only). Black Duck had failed every run.
- CI's container job uses Google's Docker Hub mirror (`https://mirror.gcr.io`) and pre-pulls the
  digest-pinned base image after HTTP 429 failures. `make typecheck` works without cloud SDKs; a
  test checks documented `python -m` modules exist.
- Add weekly `examples/github-action-drift.yml` and `examples/k8s-drift-cronjob.yaml` (no pull
  request trigger, pinned actions, only per-class counts in the summary). Tests are synthetic: no
  live tenant acceptance or measured precision.
- `benchmarks/` is now linted, format-checked and type-checked in `make`, CI and pre-commit. These
  regression changes do not establish live tenant acceptance or independently measured field
  precision.
- The scheduled governance audit separates visible-policy checks from complete policy assurance:
  withheld bypass settings stay unknown, release verification still needs a full policy readback.
  Not human-reviewed or live-tenant validated.
- Reuses PR #163's scheduled governance observation (visible drift fails, withheld bypass settings
  stay unknown, release verification stays strict); independent human field labels and live tenant
  acceptance remain deployment requirements.

### Documentation

- From the October 18 integration of #252-#258: a condensed `README.md` (#252), fact-checked
  `docs/api/` narratives (#253), and the engineering log moved to `docs/engineering-log.md`. (Oct 17)
- New `docs/operations/openssf-best-practices.md` answers each of the 67 passing-level OpenSSF Best
  Practices criteria with a status (Met, Confirm, Attest, N/A, Gap) and the evidence in this
  repository, and lists what silver and gold would still need. The page claims no badge, and nothing
  in the repository records an application for one. It records one gap for the maintainer to decide:
  JWTs verified through a JWKS set no minimum RSA key size (`crypto_keylength`). Tests keep every
  criterion answered once and tie the page's statements about cryptography to the code. (Oct 17)
- This file is condensed from 7,050 lines of per-change entries to one summary per version, grouped
  by theme; the original is kept word for word under `archive/changelog/`. A test caps the file's
  size and the length of an entry, and `CONTRIBUTING.md` says where a new entry goes. (Oct 17)
- Hero banner enlarged in the generator as #249 proposed, minus its connector and signature count
  pills (they would go stale); #249's raster figures (0.90 estate recall, four tools absent from any
  committed run) are not carried. (Oct 16)
- New `docs/security/threat-model.md` lists each trust boundary with its control and enforcing
  module, and states residual risks: best-effort redaction, plugin not a sandbox, external
  transports outside the HTTPS client's policy, offline replay not live acceptance, author-written
  corpora, no independent review. (Oct 15)
- From #229: "The Why" and "How it works" now follow the name table, ahead of install; the benchmark
  note says the maintainer wrote ShadowScan, both corpora, their labels and the harnesses with AI
  coding assistants. (Oct 15)
- The README leads with install, quick start, a full command reference (including `inventory check`,
  `mcp-registry snapshot`, `signatures show`) and the offline demo; deep reference now lives only in
  `docs/` pages, cutting it from 777 to about 515 lines. (Oct 15)
- Review fixes kept statements the condensed draft dropped: that the unrelated `shadowscan` PyPI
  package is not this project, the exact `shadow` rule, the advisory-only LLM triage exception,
  retention limits and the plugin allowlist's "not a sandbox" limit. (Oct 15)
- README banner and architecture diagrams are now SVGs generated from code by
  `python -m tools.readme_visuals` (`make readme-visuals`); a test fails on stale images, missing
  surfaces, connectors or report formats, or an embedded version, count or slug. (Oct 15)
- Replaces #222's stale rasters (old slug, `v0.1.2`, counts) and removes
  `discovery-tool-scorecard.png` (grades for 11 named tools from a benchmark not in this repository,
  per #199) and the unreferenced `cross-tool-comparison.webp` (no synthetic-results caveat).
  (Oct 15)
- README estate row now says labels were frozen after a label-completeness pass in which every
  runnable tool ran once, and docs say rules changed with the 2026-10-11 estate run's errors in
  view, so a later ShadowScan run on the ShadowBench estate is in-sample. (Oct 14)
- Carried from #220: bundled corpora predictions are unchanged; new tests are author-written
  synthetic fixtures, not independent review, live tenant acceptance or production precision. Rescan
  after upgrading and keep earlier reports as historical observations; lower attribution is not
  evidence that a workload stopped **(rebaseline needed)**. (Oct 14)
- README benchmark summary now says 4 of the 22 code-surface controls and near-misses reported clean
  came from incomplete runs, and that an incomplete clean run is not a clean result; the
  detection-matrix generator fails on an MCP ecosystem with no display name. (Oct 14)
- README gains a name table, an abridged SARIF result, a benchmark summary (maintainer wrote the
  corpora, labels and harnesses; the code-surface run left 43 of 87 repositories incomplete) and a
  generated detection matrix (`make readme-matrix`); the runbook gains rename steps. (Oct 14)
- Documentation only, no scanner change: `docs/architecture.md` follows `Engine.run()` order and
  covers every module, corrected against the code (analysis runs inside each collection job; setup
  refusals exit 1, not 3). (Oct 12)
- README gains a "How it works" overview, `--diff-base`, `--job-deadline-seconds`, process plugins,
  pinned approvals and unlisted signatures; `docs/index.md`, API pages and `ROADMAP.md` are updated,
  ADR-005 stays proposed. (Oct 12)
- Docs fixed: `cloud.azure` and `cloud.gcp` need no SDK extra with a pre-issued token,
  `cloud.kubernetes` and `cloud.openshift` are offline only, and `saas.generic` marks the scan
  incomplete on any unnamed record. (Oct 11)
- Add `docs/operations/operational-controls.md` (from #175): supervision and deadlines, egress (the
  HTTP client ignores proxy variables and rejects explicit proxies), plugin trust, SBOM/provenance
  (wheel attestations, no image attestation).

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

The initial alpha candidate. It reached TestPyPI and the immutable `v0.1.1` tag, not production PyPI; see
[RELEASE_NOTES.md](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/RELEASE_NOTES.md) for what it
asks of an operator.

### Security and redaction

- Opt-in `options.llm_triage` sends a redacted top-findings summary to an operator-named model, with
  keys from the environment and advisory-only replies; `runtime.processes` keeps command lines out
  of findings and `--dump-records`. (Oct 6)
- `SHADOWSCAN_IDENTITY_KEY` accepts explicit `hex:<value>` and `base64:<value>`; bare values valid
  under both encodings (including ordinary 64-character hex) now fail with a credential-free
  `SetupError` asking for a prefix. **(breaking)**
- Credential evidence uses domain-separated HMAC-SHA-256 pseudonyms (per-scan key, or stable
  `SHADOWSCAN_IDENTITY_KEY`) not public SHA-256 digests; cache format 4 forces fresh scans; old
  reports stay guessable. **(rebaseline needed)** (Oct 3)
- Saved HTML, CSV and Markdown reports now expose zero-width characters, byte-order marks, Unicode
  tag characters and lone surrogates the way terminal tables do; printable characters and
  intentional format whitespace remain. (Oct 3)
- HTTP transport, streamed-body and shared diagnostics keep only controlled exception categories,
  the HTTPS origin and status; URL paths, userinfo, queries, fragments and credential-bearing
  request or response objects are discarded. (Oct 3)
- Incremental scans with `use_git: true` now run the bounded Git metadata preflight before
  fingerprinting, cache hits included; unsafe metadata disables reuse and the full scan reports
  incomplete coverage while keeping source findings. (Oct 3)
- Git metadata enrichment stays opt-in and rejects `include`/`includeIf` indirections and
  unsupported config syntax before Git runs, bounding captured output; credential sanitization
  covers more forms (remaining limits: security policy). (Oct 2)
- Hostile-input fixes: `framework.vercel-ai-sdk` patterns were quadratic and one 1 MiB `.gitmodules`
  line froze the scan for over an hour (now linear or refused); `gateway.logs` no longer trusts
  client-written host or `model` tokens, so a request that only such a token made LLM traffic now
  makes the scan incomplete (it used to be skipped, exit 0). **(behaviour change)** (Oct 2)
- Redaction no longer shows credentials in escaped-quote values, `bearer => S`, braced ODBC
  passwords or nested URLs; `cloud.azure` requires GUID subscription ids and plain ARM resource ids
  (others are skipped and the scan is incomplete), so a crafted id cannot aim its token at another
  ARM action (`listKeys`). (Oct 2)
- `gateway.logs` query strings/logfmt quotes cannot hide or misattribute calls; `identity.entra`
  resolves labels per resource; plugin `sys.exit()` is a failed connector (exit 3, behaviour
  change); inventories in scanned paths warn. (Oct 2)
- Redaction withholds literals after operators `=>`, `==` and `||=`, tokens after word characters,
  URL passwords holding a raw `/`, `?` or `#` and secret-named `--dump-records` fields;
  Markdown/SARIF link escaping is not viewer-checked. (Oct 2)
- Connector diagnostic sanitization keeps credential context across errors, warnings and skip
  reasons and covers JSON stats; GCP, Azure, OCI and Slack live collectors keep their local
  classification and scope over provider fields. (Oct 2)
- Name/value credential redaction no longer does quadratic work on long lines of repeated record
  names; the shared HTTPS transport bounds slow status/header delivery, but system DNS and SDK calls
  still need a supervisor. (Oct 2)
- Redaction newly withholds `--passphrase`/`--pat`/`--auth` values, PGP private key blocks, every
  `Cookie` header cookie, URL keys `auth`/`pwd`/`pat` and Fireworks `fw_` keys, with some
  over-redaction (`ffmpeg -pass 1`); a quadratic JWT pattern is now linear. (Oct 1)
- Redaction covers more constructor, env-fallback, credential-record and command/query forms;
  regenerate stored reports and incremental baselines before sharing **(rebaseline needed)**.
  Ambiguous comments and computed values still need confidential handling. (Oct 1)
- Keys passed positionally to well-known LLM SDK calls are withheld; `cloud.aws` never treats
  `Deny`/`NotAction`/`NotPrincipal` trust statements as trust (malformed policy = incomplete); every
  connector caps `max_pages` at 1000. (Oct 1)
- `code.filesystem` IaC wildcard-action and agent front-matter patterns now run on the bounded regex
  engine; planted long space runs used to backtrack quadratically and could discard every code
  finding. AI-assisted review, not independent. (Oct 1)
- Response-derived IDs in `identity.entra`, `saas.microsoft-teams` and `lowcode.make` are
  percent-encoded before request paths; zero or non-numeric `max_users`/`max_pages` now stop the
  connector with a configuration error **(behaviour change)**; `cloud.aws` errors omit provider
  message text. (Oct 1)
- Optional `options.plugin_execution: process` / `--plugin-execution process` runs approved
  third-party connectors in spawned workers; deadline expiry, crashes or malformed/oversize output
  fail closed. Default stays `thread`; lifecycle isolation, not a security sandbox or rollback of
  external effects.
- Agentforce metadata (`GenAiPlanner`, `BotDefinition`, ...) declaring XML entities or attribute
  defaults is no longer parsed and makes the scan incomplete, as Expat before 2.4 does not bound
  entity expansion. **(behaviour change)** (Oct 2)
- Scan-wide `options.allow_instance_credentials` now replaces the per-entry value in every connector
  entry, not just `cloud.*`, so third-party connectors cannot self-grant instance-credential
  approval; plugins declaring the cloud surface or listing the key in `config_keys` also get it
  **(behaviour change)**. (Sep 28)
- Report redaction withholds many more credential forms (constructor literals, env fallbacks, CLI
  options, .NET XML settings, token prefixes) and no longer leaks a nested `api_key` under
  `openai:`; finding IDs change only where a field is now withheld. Regenerate reports, rotate shown
  keys **(rebaseline needed)**. (Sep 28)
- Opaque values nested under a sensitive credential container are remembered before redaction, so
  repeats in sibling report fields and exports are redacted; GitHub/GitLab clones check checkout
  size during and after cloning and stop Git on overflow, leaving the scan incomplete (may
  overshoot; use a disk quota). **(behaviour change)** (Sep 27)
- Google Workspace domain-wide delegation strictly parses service-account JSON and pins the
  assertion audience and token exchange to Google's HTTPS token endpoint; the incremental cache
  refuses `.git` indirection and binds fingerprints to runtime, parser and Git versions; JSON/SARIF
  refuse `NaN`/infinities. (Sep 27)
- `utils.output._require_private_pipe` now requires a named pipe mode of exactly `0600` (not any
  mode without group/other bits, such as `0700`); `SetupError` redacts its own message through the
  diagnostics sanitizer. Added `cloud.gcp`/`cloud.oci` tests lift both above the 75% floor.
- Redact the value of calls whose first, `key=` or `name=` argument is a literal credential key
  (`os.getenv("API_KEY", "...")`) before publishing source evidence; an unboundable value withholds
  the excerpt and marks the scan incomplete.
- Bare HTTP(S) and `www.` URLs in untrusted report text are defanged, so copied Markdown no longer
  turns attacker-controlled values into clickable links.
- Every `shadowscan` command now fails closed with a clear error on hosts that cannot enforce path
  confinement (Windows, or no `O_NOFOLLOW`); `--help` and `--version` still work, and embedders can
  call `shadowscan.utils.platform.require_supported_platform()`. **(behaviour change)**
- `redact` in `shadowscan.utils.text` stays a documented compatibility alias, while
  `sanitize_record` was removed later in this release; call `shadowscan.utils.redaction.sanitize`.
  **(breaking)**
- Provider API JSON with duplicate fields or nonfinite numbers is rejected, imported findings are
  sanitized before report comparisons, terminal control characters render visibly in untrusted CLI
  values, and evaluation corpus reads are bounded. (Sep 24)
- Long sensitive assignment keys are redacted before source evidence enters JSON or SARIF, and Power
  Platform Dataverse token audiences and destinations bind to validated organization origins.
  (Sep 24)
- Third-party connectors are verified at load (concrete `BaseConnector`, `name` equals entry-point
  name and is not built-in) and fail closed with `PluginRegistryError`; `Finding.from_dict` rejects
  malformed shapes; `shadowscan.utils.files` merges two `O_NOFOLLOW` open copies. (Sep 24)
- Opaque credentials assigned through indexed Python/JavaScript targets are redacted before source
  evidence is captured, and terminal control characters are escaped in verbose reports. (Sep 25)
- A benign value like `STAGE=prod` no longer redacts ARNs and names from SageMaker findings and
  `--dump-records` exports (stable IDs on reanalysis), environment-style credential names in text
  (`AZURE_OPENAI_KEY`, `os.environ[\"DATABRICKS_TOKEN\"]`) have their assigned values redacted in
  source excerpts, evidence and URL queries. (Sep 24)
- Short configured credentials are redacted in diagnostics; opaque API/Foundry/GitHub token fields
  and the `GH_TOKEN` fallback are redacted, untrusted SDK diagnostics stay out of application logs,
  and Kubernetes JWT classification is limited to documented claim shapes. (Sep 24)
- Redaction widened to webhook capability URL paths, `AccountKey`/`SharedAccessKey`/`sas_token`
  fields, Azure app settings, OCI Function config and multiline YAML credentials; JWT checks
  tightened (Keycloak-only service-account rule, exact `kubernetes.io` prefix, hostname-label
  issuers).
- Repository scanning and live tenant credentials are separated by default (mixing needs
  `allow_credential_mixing`), instance-metadata credentials need `allow_instance_credentials`
  (connector settings cannot override it), and checkouts drop persisted GitHub credentials.
  **(behaviour change)**
- Headers are validated before requests can echo credentials, HTML scripts are limited to the
  shipped script's SHA-256 hash, malformed numerics in imported findings are rejected, GCP token
  refresh gets bounded response/redirect handling and GitLab tree pagination pins a commit.

### Collection and coverage

- New connectors `endpoint.inventory`, `network.logs`, `runtime.processes` (new surfaces `network`,
  `runtime`; kinds `ai-app`, `local-model`, `network-contact`, `runtime-process`); symlinks never
  followed, gaps make scans incomplete. (Oct 6)
- Added the `endpoint` surface, offline analyzers (`endpoint.host`, `endpoint.mcp`,
  `endpoint.ollama`, `endpoint.models`, `endpoint.ebpf`, `gateway.otel`, Kubernetes/OpenShift); live
  MCP, Ollama and Kubernetes collection stays unsupported.
- Git submodule inventory reports controlled failure categories and numeric OS errors without paths
  or subprocess output; the macOS fast-exit regressions aid investigation but do not establish a
  root cause or a fix. (Oct 3)
- Incremental fingerprints now include the number of entries coverage probes inspect in
  default-excluded directories; moving a vendored file deeper could exceed `max_entries` yet reuse a
  cached complete scan, and now forces a full scan that reports incomplete coverage when the entry
  limit is exhausted. (Oct 3)
- `code.filesystem` bounds enumeration before retaining entry names via new `max_entries` (default
  1,000,000, separate from `max_files`, forwarded by GitHub/GitLab); a limit keeps assessed findings
  and marks the scan incomplete (exit 3).
- JS import and `require` line numbers are computed incrementally (`line_counter`), so files with
  thousands of imports no longer end incomplete; `code.filesystem` rejects boolean, fractional or
  non-numeric `max_file_size`/`max_files` and boolean, non-finite or out-of-range `scan_timeout` as
  configuration errors. **(behaviour change)** (Oct 2)
- Strict text decoding stops NUL bytes silently excluding source; malformed config, unsupported
  encodings, ambiguous GCP permissions, unresolved Auth0/ServiceNow records and SaaS exports without
  an app name make coverage incomplete. (Oct 2)
- Parser fixes: the catalog rule no longer discounts deployment/CI config; Dockerfile `escape` and
  Java Unicode escapes follow BuildKit/javac; notebooks lex per cell; Git LFS pointers and some PEP
  263 codecs are coverage gaps. (Oct 2)
- Engine fixes: the incremental fingerprint of an offline `code.github`/`code.gitlab` checkout
  follows `default_excludes` (`shadowscan diff` had counted findings as resolved);
  `lowcode.servicenow` pages to `X-Total-Count`, and a response without a valid one makes the scan
  incomplete; `identity.jwt` tokens stay out of `repr()` and `str()`. (Oct 2)
- Integer options are validated like `max_pages`: `max_lambda`, `max_ecs_api_calls`, `max_projects`,
  `min_events` and `max_teams` must be positive and `cloudtrail_days` and `audit_days` non-negative;
  booleans, fractions and text (`cloudtrail_days: 0.5` silently switched CloudTrail lookups off) are
  now configuration errors. **(behaviour change)** (Oct 2)
- `lowcode.servicenow` reads until an empty page; `code.filesystem` decodes BOM-marked UTF-8/16/32
  files, flags NUL-bearing analyzable files (exit 3), rejects string `exclude`/`paths`; JS lexer:
  `o.of / 1` no longer hides code. (Oct 2)
- Termination or `--job-deadline-seconds` stops `git clone`s and deletes the checkout (not
  SIGKILL/OOM); `code.github`/`code.gitlab` list fully in stable order, so
  `max_repos`/`max_projects` cover the first N by name or id, not the most recently active; Git <
  2.32 falls back to incomplete API mode **(behaviour change)**. (Oct 2)
- Inputs that used to pass now fail: unknown `options.risk_weights` capability or provider keys stop
  scan setup (`capabilities: {code-execution: 99}` changed nothing at exit 0); string `topics`,
  `repos` or `projects` stop `code.github`/`code.gitlab` (`--set topics=llm` examined no repository
  and finished complete); an inventory glob matching no file and a custom signature pack directory
  with no pack are errors; `shadowscan diff` exits 3 on a report whose counts disagree with its
  `findings`. **(behaviour change)** (Oct 2)
- New incomplete (exit 3) outcomes: `saas.generic` and `lowcode.zapier` exports with no name column
  (was complete, exit 0), gateway timestamps that no supported format parses, malformed logfmt lines
  (a repeated key or an open quote), conflicting `identity.entra` labels for one resource and role,
  Git LFS pointer files in clones or API mode, and GitLab listings that do not add up to `X-Total`.
  **(behaviour change)** (Oct 2)
- CSV inventories keep quoted line separators (approval identity kept); Notion and Atlassian reject
  provider error envelopes; malformed Google Workspace suspension flags make coverage incomplete
  (valid users kept); malformed incremental entries force a fresh scan. (Oct 2)
- Invalid GCP project IDs make coverage incomplete instead of entering authenticated requests; an
  invalid gateway UTC timestamp does too, without hiding the caller's valid observations. (Oct 2)
- Coverage is incomplete, not silently lossy, for JS/TS calls over the analysis budget,
  binary-looking `.ts` files (comments could fake an MPEG prefix to hide agents; operators may
  exclude known media paths from the scan scope), failed cache-decision hooks (only exception types
  exposed) and all-blank Zapier records with unknown JSON keys or CSV headers. (Oct 2)
- AI-assisted audit (not independent human review): scans could finish `complete` while skipping
  content; NUL-byte files, special files named like configs, `.mcp.json/` and stray offline-input
  files now mark them incomplete **(behaviour change)**. (Oct 1)
- Code scans list default-excluded directories once per root and default-scope AWS and GCP scans
  name the regions or locations not scanned, as notices that do not mark the scan incomplete; the
  AWS CloudTrail management-events notice no longer forces exit 3; a symlinked card in an inventory
  directory now stops setup instead of being skipped. **(behaviour change)** (Oct 1)
- Python direct-reference requirements keep declared package identity and semantic analysis handles
  constant-false loops (bounded analysis, not interprocedural proof); optional Git enrichment is
  capped at 16 KiB, kills children on overflow or deadline and marks coverage incomplete.
  **(behaviour change)** (Oct 1)
- `code.filesystem` symlinks now count toward `max_files` and link checks stop at the connector
  deadline; repos with more links than the remaining budget become incomplete **(behaviour
  change)**. A file merely mentioning "mcp"/"servers" is ordinary config again. (Oct 1)
- Where `O_NOFOLLOW_ANY` exists without Linux `O_PATH` (incl. macOS), confined reads use one
  kernel-checked lookup and still reject symlinks in every component; signature directory traversal
  now fails on unreadable subdirectories, so a partial pack cannot become accepted policy.
  **(behaviour change)**
- Code collection detects declared submodules whose source is not materialized and reports
  incomplete coverage instead of a complete empty result; remote clones check the Git tree too, and
  submodule URLs are never fetched. **(behaviour change)** (Oct 1)
- A `CLAUDE.md` to `AGENTS.md` link within one project no longer marks the scan incomplete; MCP
  parsing skips `*.lock.yml` and cookiecutter `{{...}}` paths; oversize cassettes stay gaps unless
  `oversize_skip_globs` is set. (Oct 1)
- From a scan of five public agent repositories: the JSX lexer no longer marks valid TSX incomplete
  (139 false incomplete files removed; unbalanced tags still fail closed), and `setup.py` marks a
  project root only if it references setuptools, distutils or scikit-build, or calls `setup(...)`.
  (Oct 1)
- Now exit 3 **(behaviour change)**: HTTP bodies slower than twice the client timeout, links in any
  `code.filesystem` path component, invalid `id`/`full_name` in `code.gitlab`/`code.github`
  listings. Now complete: Python modules over `max_ast_nodes` or the import binder's nesting limit
  whose imports match no signature, 0711 directories, unrendered Helm/Jinja YAML. (Sep 28)
- `shadowscan.utils.text.sanitize_record` and `HttpClient.paginate_cursor` are removed (breaking;
  use `shadowscan.utils.redaction.sanitize`); caching, credential approval and run identity are now
  connector class hooks (`cache_roots_separately`, `inherits_instance_credentials_approval`,
  `uses_run_identity_key`). (Sep 28)
- Offline exports, inventories, imported reports, manifests, notebooks and agent/MCP configs reject
  duplicate or non-finite JSON/JSONC/YAML data, making collection incomplete rather than
  establishing absence; conflicting provider records are quarantined; built-in connector options use
  one fail-closed schema. **(behaviour change)** (Sep 27)
- A structured config refused for nesting depth or XML entity expansion keeps the scan incomplete
  (exit 3) again; the series had downgraded it to a syntax warning that hid workflow evidence behind
  a complete scan. JSONC stripping is linear again.
- Syntax errors in non-coding-agent configs are warnings (`strict_coverage` keeps them incomplete);
  JSONC loads via `shadowscan.utils.jsonc`; large notebooks are analyzed to `max_notebook_size` with
  outputs unscanned (incomplete unless `scan_secrets` is off). **(behaviour change)** (Sep 25)
- Unread oversized source and configuration files (declared `oversize_skip_globs` omissions stay
  warnings), outward, unresolved or in-root directory symlinks, links to unread targets, malformed
  GitHub/GitLab responses and empty offline clone inputs now make scans incomplete even without
  `strict_coverage` (it raises warnings to errors); links whose own names are never read and source
  aliases analyzed in the same project stay complete. **(behaviour change)**
- Unresolved identity evidence is preserved: Entra grants with a missing or conflicting principal
  become `unresolved-principal` findings, contradictory AWS account records leave the scan
  incomplete, and ID-less n8n blueprints keep evidence under an unresolved identity.
- New optional `--job-deadline-seconds` / `options.job_deadline_seconds`: a cancellable watchdog
  exits `3` on overrun and now starts before JWTs are read from stdin, so a silent pipe cannot stall
  the CLI; external process supervision remains required.
- Offline Slack cursors and AWS truncation markers mark the scan incomplete, findings resolve only
  on explicit matching connector completion evidence, and runtime activity attaches only to intact,
  unambiguous code identities with recognized caller assurance. **(behaviour change)** (Sep 24)
- Provider errors, malformed Slack responses and invalid pagination mark scans incomplete while
  valid records are kept; remote clones get a time bound and size preflight, partial checkouts are
  removed, API fallbacks are incomplete and ambiguous source masking fails closed. **(behaviour
  change)** (Sep 24)
- Observed ServiceNow native agents are preserved when optional name or OAuth signature matching
  times out (coverage incomplete), and YAML manifest matching stays within its one-second shared
  deadline during parallel scans. (Sep 25)
- Oversize files and symlinks leaving the scan root are skipped with a warning instead of making the
  scan incomplete; `strict_coverage: true` / `--strict-coverage` restores the old fail-closed
  behaviour, and in-root links no longer affect coverage. **(behaviour change)**
- The filesystem scanner stops before the connector deadline and the engine keeps partial findings
  as an incomplete scan; new `oversize_skip_globs` skips lockfile/bundle-type oversize files with a
  warning, and unknown connector config keys fail closed. **(behaviour change)** (Sep 24)
- Slack findings bind to immutable workspace IDs (names are display-only), so Slack baselines must
  be refreshed and legacy offline exports need a team envelope or `team_id`; malformed Teams
  resource identities are rejected and coverage is marked incomplete. **(behaviour change)**
  **(rebaseline needed)** (Sep 25)
- Provider error bodies in n8n, Make, Workato and Notion exports, and `bedrock-logging` records
  lacking `loggingConfig`, now give incomplete or unknown coverage, not an empty inventory or
  "logging DISABLED"; one malformed SaaS record is skipped with a warning, not fatal. **(behaviour
  change)** (Sep 24)
- Code connectors run credential detection first and isolated, so regex or sanitizer budget
  overruns, notebook outputs and markdown cells no longer hide a real key; cancellation stops the
  tree walk, and more than 50 agent definitions per project or 200 retained manifests make the scan
  incomplete. (Sep 24)
- Unknown Lambda coverage is preserved, IAM `NotAction` grants are identified as potential grants
  with explicit analysis limits, Slack workspace scope is validated, and missing n8n definitions
  make the scan incomplete. **(behaviour change)** (Sep 24)
- Incremental cache and record publication are fenced against timed-out connectors (blocked
  SDK/plugin calls still need a process deadline); GitHub/GitLab code findings record immutable
  commit/tree identities and reject blob bytes that mismatch the Git object ID. (Sep 24)
- A default 120-second connector deadline now reports incomplete scans; it is a soft thread
  deadline, so host job timeouts remain necessary for blocked SDK or plugin calls. **(behaviour
  change)**
- Valid cloud, identity and SaaS records survive individual failures, GCP key coverage separates
  unknown inventory from observed zero keys, unknown AWS service selections are rejected, and
  incremental cache slots use nonblocking POSIX advisory locks (full scan on contention).

### Detection and signatures

- An invalid A2A card that still names its agent and declares an endpoint, skills or capabilities
  gets its own `protocol.a2a` finding (`incomplete-agent-card`) instead of vanishing; it never
  counts as an agent and the scan stays incomplete.
- OpenClaw state-directory `config.json` (`.openclaw/`, `.clawdbot/`, `.moltbot/`) and
  `.moltbot/moltbot.json` belong to `coding-agent.openclaw` alone, one finding per state directory;
  #155 had placed them under `platform.openclaw`.
- `heuristic.unattributed-api-key` gains a signal for `sk-` keys with 20-31 characters after the
  prefix (LiteLLM virtual keys), gated by character-mix and entropy checks; `sk-ssh-…`/`sk-ecdsa-…`
  never match. These keys were missed before.
- Goose (first-run config, missed in all six benchmark homes) and Cline signatures widened, new
  `coding-agent.openclaw` signature; endpoint findings link to running processes
  (`observed-running`, `metadata.lifecycle`) at zero weight. (Oct 6)
- MCP configs report server risks (`mcp-unpinned-package`, `mcp-broad-filesystem`,
  `mcp-shell-command`) and coding agents risky settings; `mcp-plain-http` (+10) also scores `ws://`
  and `HTTP://`. New default weights **(behaviour change)**. (Oct 6)
- `gateway.logs` classifies agentic callers from request metadata (`agent-runtime-api`,
  `mcp-client`, `agent-loop`); `identity-app` signatures, name aliases and `chatgpt.com` browsing no
  longer make callers agentic. **(behaviour change)** (Oct 6)
- New runtime risk tags with OWASP/MITRE references and a CycloneDX 1.6 AI-BOM output; new tag
  weights can change scores **(behaviour change)**. No GGUF/safetensors parsing or MCP rug-pull
  baseline; no device name, so no lifecycle links.
- Unregistered tools and unrelated execution helpers no longer grant an agent `tool-use` or
  `code-exec` or raise its confidence; evidence stays visible at zero weight, unproven features in
  `potential_capabilities`. **(behaviour change)** (Oct 3)
- Attribution rejects discarded callbacks to unknown JavaScript factories, shadowed helpers and
  unrelated MCP receivers; JS/TS binding skips provably dead literal branches. Bounded static
  recognition, not whole-program reachability. (Oct 3)
- Configured capability analysis covers ADK, Strands, AutoGen, LlamaIndex and Semantic Kernel
  constructors; empty or unresolved options keep SDK features as potential capabilities instead of
  adding them to risk, and weak planning wording alone no longer establishes autonomous operation.
  **(behaviour change)** (Oct 3)
- MCP registration analysis separates executable registrations from comments and examples; empty or
  disabled provider tool options no longer establish tool-use, and analysis limits must not imply
  complete capability coverage. (Oct 2)
- Top `likelihood` bucket `confirmed` is now `strong`, and `Likelihood.CONFIRMED` is
  `Likelihood.STRONG` (breaking; old reports still read). Data and prose files that only name 4+
  products stop establishing a technology (source code, manifest-named files and files naming 1-3
  products are unchanged) **(behaviour change)**; sole-evidence provider tables go unreported.
  (Oct 2)
- npm dependency aliases are attributed to their declared registry target, keeping
  development-dependency status; invalid alias targets mark source coverage incomplete while valid
  neighbouring dependencies stay visible. (Oct 2)
- MCP tool attribution ignores commented and string examples and counts only referenced enum
  members; recheck capability labels and enforcement baselines on reports made before this
  correction **(rebaseline needed)**. (Oct 2)
- Gradle/Dockerfile extraction and matching ignore comments (commented credentials still reported);
  named Python URL requirements keep declared package identity. Paired cases are authored, not a
  fresh field-accuracy measurement. (Oct 2)
- Generic Genkit initialization and flow/tool declarations no longer establish an agent or tool-use
  capability; concrete agent definitions and model calls with registered tools are still detected.
  **(behaviour change)** (Oct 2)
- MCP servers that declare themselves disabled (`disabled: true`, `enabled: false`) are now
  reported, with the tag `declared-disabled` and `disabled: true` in `metadata.servers`;
  `identity.jwt` findings without `jwks_url` carry `metadata.verified: false`. **(behaviour
  change)** (Oct 2)
- Gateway attribution reads hosts only from the trailing unquoted `host=` token, treats generic
  vendor hosts as hints, and no longer matches routine other-provider scopes in
  `policy.privileged-scopes`, so risk levels can drop **(behaviour change)**. (Oct 1)
- `identity.jwt` labels GitHub Actions, GitLab CI and Kubernetes service-account tokens `workload`
  and marks tokens scanned without a JWKS `signature_verified: false`; gateway registry matches on
  operator-asserted or unverified caller names carry `metadata.registry_match_assurance` and the
  `registry-identity-unverified` tag. (Oct 1)
- Outside the code surface, repeated evidence of one signal counts once; Vercel AI SDK multi-step
  tool loops (incl. `isStepCount`) are agents; detection rule files are data, listed in
  `metadata.detection_rule_files`. (Oct 1)
- Ordinary Spring AI `ChatClient`, LangChain4j `AiServices` and standalone Java tool declarations no
  longer establish an agent or tool use; empty tool/handoff collections add no capability
  **(rebaseline needed)**. Regression evidence only, not fresh field accuracy. (Oct 1)
- Real-format credentials in test, fixture or `cassettes/` paths stay `secret` findings,
  downweighted (half weight, `test-code-only` tag unless `include_tests`); a bare env-var mention
  (`GOOSE_PROVIDER`) no longer yields a coding-agent finding. Offline evidence only, not field
  precision. (Oct 1)
- Gemini CLI `httpUrl` is an MCP endpoint alias; GitHub Actions MCP settings no longer fail on the
  `on:` key and embedded JSON servers are reported; `GOOGLE_GENAI_USE_VERTEXAI` no longer attributes
  Google ADK; credential-file path args are redacted, not inline secrets. (Oct 1)
- In agent front matter, YAML values PyYAML cannot construct now report
  `invalid agent definition YAML` (conda environment files report `invalid YAML`; those scans were
  already incomplete); the definition is listed with `agent_definitions` metadata, which can raise
  the finding's risk score. Config and inventory files with such values still fail at setup (exit
  1). (Sep 28)
- Generic graph/flow construction and disabled, empty or schema-only tool options no longer
  establish an agent or action execution. Regenerate discovery baselines **(rebaseline needed)**;
  holdout labels, tenant acceptance and independent release review remain separate requirements.
  (Sep 27)
- GitHub Apps match their slug's words, so `amazon-q-developer`, `ellipsis-dev`, `mentatbot` and
  `factory-droid` are recognized again; an MCP server with no recognized tools keeps its
  code-implied capabilities (a FastMCP shell tool is `code-exec` again), but tools registered only
  in tests imply none.
- CrewAI `agents.yaml` / `langgraph.json` inside a reported project fold into its finding
  (`metadata.manifests`) instead of a second agent finding, so `diff` reports the old ones resolved;
  A2A cards and M365 declarative agents stay separate. **(behaviour change)** **(rebaseline
  needed)** (Sep 25)
- GitHub Apps need an AI signature or AI-like name regardless of permissions (read-only AI-named
  apps appear; Renovate-style apps only with `include_unrecognized_apps: true`); only
  `workflows`/`actions` write implies `code-exec` (Claude app critical to high). **(behaviour
  change)** (Sep 25)
- `ambiguous: true` signals (e.g. `ClientSession(`, `AgentCard(`) count only with a same-signature
  import, dependency or specific pattern; the uncorroborated-lexical cap now covers every signature
  category; MCP capabilities come from registered tool names (`metadata.mcp_tools`). (Sep 25)
- The duplicate lexical agent-promotion path is removed, so lexically promoted JS/TS files now
  report `framework-usage` (review agent counts); offline regressions do not establish independent
  human review or live tenant acceptance. **(behaviour change)** **(rebaseline needed)**
- Test- or fixture-only evidence no longer establishes an agent (half weight, `test-code-only`;
  `include_tests` / `--include-tests` opts out), duplicate project findings are dropped, and
  signature capabilities narrow (e.g. LangGraph no longer implies memory). **(behaviour change)**
- Provider SDK requests passing `tools=`/`toolConfig=` record tool-use capability and attribution,
  and the model-selected dispatch and feedback loop an agent verdict requires is now recognized for
  Anthropic `messages.create` as well as OpenAI chat completions.
- Risk factors always sum to the score (explicit `confidence-scaling` and `bounds` factors); new
  `risk.danger_score` excludes governance factors, selectable via `options.risk_basis` (`combined` |
  `danger`) and validated `options.risk_weights`.
- Signature packs grow to 211 signatures and 912 signals; vendor-neutral heuristics cannot create an
  `agent` finding without a framework, provider, platform, protocol or cloud-service match, and a
  stricter signature validator makes violating custom packs fail to load. **(breaking)** (Sep 24)
- JWT `client_name`, `app_displayname` and `azp_name` are agent hints only when they match an AI
  product or agent signature (ordinary Entra v1 user tokens were reported as agents); a user token
  with an RFC 8693 actor and agent claims is `delegated-agent`. (Sep 24)
- IAM `NotAction` allow statements yield potential grants (limitation
  `notaction-partially-evaluated`), `sagemaker:*` counts as an LLM invoke grant in live collection,
  and OCI custom models are found by `type: CUSTOM` or base model reference. (Sep 24)
- Confirmed agents need corroborating AI evidence and constructors bound to imported frameworks
  (common aliases resolve); generic loops, subprocess calls, descriptions and empty files cannot
  establish agents, and manifests are validated. (Sep 24)

### Reports and CLI

- CycloneDX (`--format cyclonedx`) replaces the earlier candidate exporter: agents and other
  findings are `application` components, risk is `shadowscan:heuristic-risk`, per-tag
  `shadowscan:tag:<tag>` properties become one `shadowscan:tags` list, credentials excluded;
  regenerate BOMs, update consumers. **(breaking)** (Oct 6)
- SARIF no longer presents the heuristic risk as a CVSS-like severity (#134): rules drop
  `security-severity` and the `security` tag; the level goes to `shadowscan/heuristic-risk` and
  `risk_level`; hits are `warning` or `note`, never `error`. **(behaviour change)** (Oct 2)
- Reports list skipped connectors in `collection_scope.not_run`; incomplete CSV starts with
  `SCAN-INCOMPLETE`; `diff --fail-on-new` exits 2 on new or higher-risk findings; a plugin raising
  `SystemExit` or another `BaseException` except `KeyboardInterrupt` (which still ends the scan) is
  an incomplete connector (exit 3). (Oct 1)
- Usage errors exit 1 instead of 2, so exit 2 only means a complete scan reached `--fail-on`; `diff`
  lists scan-local gateway findings as `not_comparable`; opt-in `SHADOWSCAN_IDENTITY_KEY` (env only,
  32+ bytes) keeps gateway IDs stable **(behaviour change)**. (Oct 1)
- CSV also inserts the `'` marker after `,`, `;`, tab, `|` or a line break inside a value when a
  formula could start (OWASP CSV injection); consumers stripping only a leading `'` must strip these
  or read `json`. Markdown writes `@` as `[@]` in untrusted text **(behaviour change)**. (Sep 28)
- A report path that already exists as a character device (`-o /dev/null`) is now written in place;
  before, root replaced `/dev/null` with a regular file. A named pipe is written only if the user
  owns it (mode 0600) with a reader open; sockets, directories and block devices are refused
  **(behaviour change)**.
- HTML report sorting and evidence drill-down are keyboard-reachable buttons with
  `aria-expanded`/`aria-sort`, filters have accessible names, an `info` tile is added and
  pill/light-scheme colors meet WCAG AA; CSV formula-quoting is documented.
- SARIF output no longer emits a `physicalLocation.region` without `startLine`, restricts rule names
  to `[A-Za-z0-9_]` and is tested against the SARIF 2.1.0 schema; setup failures print
  credential-free messages via `shadowscan.errors.SetupError`. (Sep 24)
- Entra service-principal findings use the scanned tenant as `account`; the publisher tenant is kept
  as `metadata.owner_tenant`. (Sep 24)
- SARIF artifact URIs are percent-encoded and root-relative only on path boundaries, with each rule
  reporting its most severe result; CLI tables render inventory, signature and connector text
  literally, so Rich markup no longer crashes `inventory check`.

### Governance, registries and identity

- Inventory approval warnings add resource-shape probes and flag near-universal patterns as advisory
  sampled evidence (only star-only globs are called universal); scope constraints, including
  observation discriminators, still limit approval.
- Evidence policies can add 95% Wilson lower-endpoint thresholds (operator-selected targets, not
  measured accuracy). A versioned merge policy and checker change no live repo settings;
  administrator activation, independent human review, fresh holdout labels and tenant acceptance
  stay external. (Oct 1)
- From an internal AI-assisted grading pass: a card must list `accounts` before a resource pattern
  can approve a finding, now driven by
  `shadowscan.utils.identity.PROVIDERS_REQUIRING_CARD_ACCOUNT_SCOPE` instead of a hardcoded
  `google-workspace` check; behaviour for existing providers is unchanged.
- Google Workspace observations and registry approvals bind to an immutable customer identity;
  unresolved ones cannot approve or complete collection. Operator action: grant
  `admin.directory.customer.readonly`; `customer` must be `my_customer` or a `C…` ID. **(behaviour
  change)**

### Benchmarks and evaluation

- The evaluation runner supports explicit checks for expected and forbidden finding kinds, product
  signatures and model providers; selected authored cases guard against attribution noise but do not
  establish field accuracy. (Sep 27)
- Holdout acceptance rejects bundled corpora and AI annotation ledgers, validates the human-review
  declaration used for the actual evaluation, and reads policies and annotations with bounded,
  symlink-free file access.
- Adds a frozen holdout acceptance gate, a tenant canary procedure and a GitHub Action example;
  field accuracy still needs independent review and live canaries. (Sep 24)
- The offline acceptance verifier excludes previously evaluated source snapshots, validates the
  known-gap report and supports frozen per-kind sample and error limits; rollout still needs
  independent human review and real tenant validation. (Sep 25)
- `tools/evaluation/realistic_corpus.json` adds multi-file cases modeled on real repositories and
  naive-scanner false positives; the evaluator gains `known_gap` and `max_secret_findings`, and
  docs/evaluation.md says what each corpus does and does not measure. (Sep 24)
- Adds a frozen negative-heavy public corpus (separate AI labeling passes, provenance and annotation
  checks in CI), which is not field accuracy, and read-only AWS and Slack tenant canaries; offline
  replay does not establish live acceptance, which remains a deployment gate. (Sep 24)

### Release, CI and supply chain

- Release policy now permits unsigned annotated tags on the exact reviewed commit; personal SSH or
  GPG signatures are optional and the default tagging command disables automatic signing. (Oct 8)
- Publishing still runs through the protected workflow and PyPI trusted publisher with provenance,
  SBOM and attestations; independent review, CI, CodeQL, immutable tag protection, digest checks and
  environment approval stay required. (Oct 8)
- Fixed: the release-evidence workflow could never pass its merge-rule step, because GitHub returns
  ruleset `bypass_actors` only to write-access callers and the build job's token is read-only; the
  workflow had never run. (Oct 7)
- New required `ruleset_readback` input (an administrator's `gh api` output) supplies only the
  withheld `bypass_actors`: `verify --live` rejects it unless it equals the job's own read in every
  returned field, `updated_at` included. (Oct 7)
- Merge-rule receipts record `bypass_actors_source` and `observed_updated_at` (older receipts still
  verify); mismatch errors echo only plain lowercase field names, so a crafted key cannot inject log
  or workflow commands. (Oct 7)
- Distribution renamed from `project-nexus-shadowscan` to `NexusShadowScan`
  (`pip install NexusShadowScan` once a release is published; container check
  `pkg:pypi/nexusshadowscan`); command, imports, entry points and schemas keep `shadowscan`.
  **(behaviour change)** (Oct 7)
- New `publish` input (`none`, `testpypi`, `pypi`): `publication-gate` needs one wheel with matching
  digests (and tag `v<version>` for `pypi`); an approval-gated `id-token: write`-only job uploads
  via trusted publishing, no token stored. (Oct 7)
- Fixed: the exactly-one-wheel checks passed an artifact with two wheels because `set -e` ignores a
  failing first command in an `&&` list; they now fail in an explicit `if`. (Oct 7)
- `pre-commit run --all-files` failed on `main` (blank last line in benchmark `REPORT.md`; mypy
  flagged the Open Shadow AI helper's `import-not-found` ignores as unused); the writer now ends
  with one newline and the ignores allow `unused-ignore`.
- The first scheduled merge-policy audit failed with an ambiguous "does not match" error because a
  response missing a managed field looked like a wrong ruleset (`bypass_actors` needs write access);
  the verifier now names omitted fields. (Oct 6)
- The job still fails until an administrator applies the reviewed payloads and a complete readback
  matches (2026-10-06 readback: `bypass_actors, rules` differ); `docs/production.md` and
  `docs/operations/merge-policy.md` record the state. (Oct 6)
- README now leads with the reviewed-revision, hash-locked deployment install and labels floating
  VCS installs development-only; the Dockerfile documents the live-apk trade-off and a test enforces
  matching pins across stages.
- The dependency-audit workflow checks both live `main` rulesets against reviewed payloads
  (read-only API); disabled, weakened, malformed or unavailable evidence fails the job. It applies
  nothing and does not establish independent review. (Oct 3)
- Ruleset preparation refuses conflicting check-provider bindings; prepared policy files do not
  activate GitHub enforcement, and independent review and live tenant acceptance remain external
  prerequisites. (Oct 3)
- DCO now checks every commit in the pull-request range, including merge commits, whose conflict
  resolutions or other content previously passed without the merge author's certification. (Oct 3)
- The secret gate scans tests, signature packs and evaluation corpora instead of exempting
  directories; synthetic fixtures need exact path, family and SHA-256 approvals in
  `tools/secret_allowlist.json`; stale or missing ones fail. (Oct 3)
- `test-macos (3.11)` failed `main` after #135: Git 2.47+ background `maintenance run --auto` raced
  `shutil.rmtree`; test helpers that commit now pass `-c maintenance.auto=false`. The scanner's own
  Git commands never start maintenance. (Oct 2)
- The CI lock takes Dependabot's development-tool updates from #136 (platformdirs 4.12.2, virtualenv
  21.14.0), with the docs lock moving platformdirs too; Dependabot edits only constraints, so its PR
  failed the lock consistency tests. (Oct 2)
- Worker image drops the build backend; Wolfi `python-3.12` pinned to `3.12.15-r0` because `-r1`
  lacks SHA-224 and broke pip installs (drop once fixed); the consumer workflow example no longer
  runs `python -m` from the scanned checkout. (Oct 2)
- #134 landed via an integration PR rebuilt on `main` (it predated #123, #132, #133); other fixes,
  including the SIGINT clone test after #133, come from an AI-assisted review with regression tests
  and no second-person review. (Oct 2)
- Ruleset payloads and tooling activate no GitHub settings; authored tests do not establish
  independent review, field accuracy or live tenant acceptance. Review changed capabilities and
  scores, then re-baseline. **(rebaseline needed)** (Oct 2)
- #107 and #110–#122 landed together through #123 (one squash commit). The review fixes are
  AI-assisted with no second-person review, and unchanged results on the author-written offline
  corpora say nothing about field precision. (Oct 2)
- Worker image moves to a digest-pinned Wolfi base (Debian had 55 unfixed HIGH entries), stripping
  setuid/setgid bits; `bounded_safe_load_all` removed (#112, #121); Ruff `BLE`/`RUF100` apply
  (#121); docs reorganised (#122). (Oct 2)
- CI no longer cancels `main` push runs; stricter policy tests; `tools/coverage_gate.py` fails
  closed. Baseline-affecting changes: see `docs/production.md` **(rebaseline needed)**.
  Author-written evaluation corpora say nothing about field precision. (Oct 2)
- Wheel validation uses a private temporary environment with cleanup; the connector coverage gate
  requires the report to name every `shadowscan/connectors/` module and rejects malformed counts
  (75% minimum unchanged). (Oct 2)
- Finding merge logic and cross-surface correlation move to `shadowscan/merge.py` and
  `shadowscan/correlation.py` (public API unchanged); Hypothesis redaction property tests and
  `pytest-xdist` (`make test-parallel`) join the `dev` extra.
- Secret-pattern checker escapes control characters in file names (not a complete secret detector).
  Ruleset readback still lacked `CI gate` in required checks; no settings changed, no release
  published, and no live tenant acceptance or independent human review established. (Oct 2)
- CI scans the built worker image for HIGH/CRITICAL vulnerabilities; release-candidate evidence
  checks `CI gate`/CodeQL. Authored regression evidence, not live tenant acceptance, fresh field
  accuracy or independent human approval. (Oct 2)
- Removed `safe_yaml.bounded_safe_load_all` and `HttpClient.requests_made` **(breaking)**; tests are
  hermetic and fail on outbound connections; coverage floors count branches;
  `.github/rulesets/require-ci-and-review.json` versions the intended `main` ruleset. (Oct 1)
- `docs/connectors/reference.md` is generated from connector classes
  (`python -m tools.connector_reference`) so keys cannot drift from `config_keys`; mypy covers every
  tool package; ruff flags broad exception handlers (`BLE`). (Oct 2)
- DCO accepts Dependabot's app-authored commits only with GitHub's fixed `support@github.com`
  sign-off; CodeQL, Scorecard and the example workflow use `github/codeql-action` 4.38.2 with
  grouped Dependabot updates; ruff moves to 0.16.9. (Sep 28)
- One `CI gate` covers docs, supported Pythons, containers and DCO, but the repository ruleset must
  still require it. The distribution is now `project-nexus-shadowscan` (command, namespace and
  report schemas unchanged; nothing published); release evidence refuses dirty checkouts; SBOM is
  Python-only. (Sep 27)
- Every documentation page (ADRs, tenant canary guide, 2026-09-24 assurance results) is now
  reachable from the site nav, enforced by a consistency test; ruff enforces six more rules (`B007`,
  `B008`, `B034`, `C416`, `E741`, `SIM113`).
- `mypy` runs with `warn_return_any` and `warn_unreachable`, and ruff `B904`/`UP028` are enabled;
  reported sites were fixed at the source (untrusted API rows typed, AWS manual pagination moved out
  of an exception handler).
- The release evidence gate accepts GitHub's actual workflow-run path and requires successful
  exact-commit CI and CodeQL before building a candidate.
- New `tests/test_repository_consistency.py` (run by `make policy`) fails CI on broken links, stale
  counts and metadata or CI/hook drift; the docs toolchain is hash-locked, and the audit found the
  pre-commit secret hook never ran (AND-filtered `types`; now `types_or`).
- The release candidate workflow binds a successful exact-commit main CI run to a wheel, hash-locked
  dependencies, SBOM and retained provenance, with pinned container base and consumer CI example; it
  does not publish a package or authorize deployment. (Sep 25)
- Adds deployment evidence validation and a manually invoked release-evidence workflow; neither
  creates human review, live tenant results, a published release or a production acceptance claim
  from offline tests. (Sep 25)
- Reconciliation after PR #33 keeps the newer webhook, HTTP header, imported-finding, CSP, SARIF,
  GCP and Azure safeguards; version 0.1.1 implies no release tag or published artifact, and tenant
  canaries and container runtime acceptance are still required. (Sep 24)
- Core and cloud runtime dependencies are version- and hash-locked for the documented Linux/Python
  deployment targets, and the Docker build context admits only source and packaging inputs.
- Consolidates further verified fixes from PR #31 onto the PR #30 candidate, preserving #30's
  credential isolation, default deadlines and release gates; the development Ruff requirement rises
  to 0.16.8 and wheel installs are validated against the runtime lock.

### Documentation

- README links are now absolute (it doubles as the PyPI description) with tests for relative and
  broken links; fixed the `pip wheel. --no-deps` typo; new runbook `docs/operations/publishing.md`.
  (Oct 7)
- Fixed a README edit on `main` that broke two copy-paste commands (`pip wheel.` and
  `shadowscan code.` lacked a space), misquoted the `Development Status` classifier and indented the
  `Project status` heading into a bullet.
- A repository test now checks that every `shadowscan` and `pip` command in a Markdown shell block
  names a real subcommand and that the README's classifier is declared in `pyproject.toml`;
  `CITATION.cff` now names all nine surfaces.
- The package summary, `shadowscan --help`, HTML report subtitle and connector docstring named only
  six of nine surfaces, and the README understated which surfaces group repeated matches; a test
  checks each description names every `Surface`.
- The testing guide documents exact synthetic-secret approvals instead of the removed directory
  exclusions and placeholder-word exemptions. (Oct 3)
- mkdocstrings API reference pages for the core modules are part of the documentation site.
- Docs now say Linux x86_64 is the only validated target, Windows is unsupported by design, and
  `main` ruleset enforcement changed in 2026-09 and must be checked live; two hardening logs no
  longer call same-author passes independent reviews.
- CONTRIBUTING.md describes the actual single-maintainer self-merge process and requires independent
  human review before any tagged release; the 2026-09-24 reviews are relabelled internal AI-assisted
  logs, the classifier drops to Alpha and SECURITY.md says no versions are released. (Sep 24)
- Docs cover verifying the final reviewed full commit SHA, required checks, the independent-review
  merge gate and soft-deadline limits; confidence is heuristic, static signals need runtime
  corroboration, and field precision/recall need a held-out local corpus before risk-gate
  enforcement.

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
