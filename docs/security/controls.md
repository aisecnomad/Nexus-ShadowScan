# Security controls and limits

Every implemented security control, with the limits it does not cover. This
detail used to make up most of
[SECURITY.md](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/SECURITY.md),
which now keeps the reporting policy and a
[threat model at a glance](../security.md). The
[threat model](threat-model.md) maps each threat to its control, and
[redaction](redaction.md) lists what reports withhold and what can remain.

## Trust boundary in detail

The operator workstation or CI runner, scanner configuration and installed Python
packages are trusted. Third-party connector execution requires an exact-name
allowlist in `options.plugins` or repeatable `--allow-plugin`. Listing connectors
does not import plugin code. The allowlist is not a sandbox: an approved plugin
runs with scanner privileges. A spawned plugin worker is started without the
credential-shaped environment variables exported for the built-in connectors
(`*_TOKEN`, `*_SECRET`, `*_KEY`, `*_PASSWORD`, `*_PAT`, connection strings,
webhook URLs and URLs that carry a password, the CI, cloud SDK and package
tooling credential variables; the
[plugin contract](../connectors.md#third-party-plugin-execution)
lists them)
unless `options.plugin_env` names them, so they are neither in its
environment (`os.environ`, on Linux `/proc/self/environ`) nor in that of the
programs it starts; a thread-mode plugin shares the scanner's environment. This
keeps credentials from a plugin that does not look for them, not from one that
does. Process mode is lifecycle isolation, not a sandbox: the worker runs as the
scanner's user, so a plugin can still read its parent's environment, every
withheld variable and `SHADOWSCAN_IDENTITY_KEY` included, from
`/proc/<ppid>/environ` on Linux (other systems have equivalents), and every file
that user can read. Pass the built-in connectors' credentials through files
(such as the cloud SDKs' credential files) or a secrets manager rather than
exported variables, which keeps them out of the environment the scanner and
every program it starts carry; a plugin running as the scanner's user can
still read a file the scanner can. To keep a credential from an untrusted
plugin, run that plugin under a separate user or in a separate container, in a
scan job that does not hold the credential. Built-in connector names cannot be
replaced.

Remote responses, scanned repositories and offline exports are untrusted inputs.
Review signature packs before installation. Built-in signature IDs are reserved
unless `options.allow_signature_override` / `--allow-signature-override` explicitly
permits replacement. Directory walks do not follow signature/inventory symlinks.

Use dedicated read-only audit credentials and narrowly scoped inventory approvals.

CSV inventory approval identities preserve embedded line separators in quoted
fields. Imported finding evidence is type-checked before postprocessing, and
malformed cache entries are discarded in favor of a fresh scan. Provider error
envelopes and malformed collection flags must not establish complete empty
coverage, even when a response includes an empty collection field.

Built-in collectors inspect provider resources using read operations. Scope the
audit identity to the documented read permissions and review any enabled
third-party plugin separately.

## Implemented controls and limits

* Gateway inventory reconciliation requires authenticated caller-field
  assurance before an exact card binding grants registration or ownership.
  Operator-asserted and unverified names remain review candidates, without
  registration risk credit. Provider-field assurance still depends on the log
  producer's integrity and the supplied export's provenance; the scanner does
  not authenticate an offline export merely by parsing it.
* Make blueprint and Zapier pagination metadata are validated before collection
  can be considered complete. CODEOWNERS reads remain anchored to the source
  scan's directory descriptor. A root replacement detected before ownership
  lookup makes the scan incomplete; later replacements cannot redirect reads.
* Optional filesystem model/artifact inspection uses confined regular-file
  access, file identity checks and bounded metadata reads. It never executes
  packaged code, unpickles objects, loads tensor data or follows ONNX external
  data references. A recognized format is inventory evidence, not a working
  model or an agent. Lockfile parsing never runs a package manager.
* Optional Linux runtime inspection reads bounded maps and descriptor-link
  metadata and, separately, allowlisted environment key names. It never opens
  descriptor targets or `/proc/<pid>/mem`, and environment values and mapped
  paths are not retained. PID namespace/start identity checks reject changed
  observations; denied or truncated selected inspection remains incomplete.
  These observations cannot establish arbitrary memory-only Python execution.
* MCP/skill instruction review is static and bounded. It emits fixed heuristic
  explanations and locations, not a safety verdict, and never launches a
  discovered server, invokes a described tool or follows a supplied URL.
  Zeek JA4 ingestion and temporal DNS attribution likewise operate solely on
  supplied records; neither introduces live capture or DNS queries.
* Source and manifest inputs are decoded from UTF-8, from UTF-16 or UTF-32
  with a byte-order mark, and for Python from the declared PEP 263 codec. An
  analyzed file with binary or undecodable content (dense NUL bytes, mostly invalid
  UTF-8; in other text, invalid bytes are replaced and noted while no 8 KiB window
  has more than four replaced characters and more than 10% of the window, and a
  few stray NUL bytes in large valid UTF-8 text are noted; names are matched
  without them, and a source file whose lexing differs with and without them
  is incomplete), or whose declared codec
  does not read ASCII as ASCII (UTF-16 or UTF-32 without a byte-order mark,
  UTF-7, EBCDIC), leaves coverage incomplete;
  ordinary binary assets are not text evidence. IAM wildcard and
  agent-definition front-matter matching shares the bounded matcher budget;
  keep an external worker/job deadline for hard isolation.
* Shared `HttpClient` requests require HTTPS without embedded credentials, and
  a URL containing a backslash is refused (it reads as one host to the URL
  parser and another to the transport). A credentialed endpoint taken from a
  remote response is also matched against an exact host, not a hostname suffix.
  Redirects and pagination stay on the configured origin. By default, private,
  loopback, link-local, metadata and other non-global addresses are rejected.
  The HTTPS adapter checks the addresses at connection time and connects directly
  to the checked address, retaining hostname TLS verification. A trusted private
  API requires `allow_private_origin: true` on its connector,
  `options.allow_private_origin: true` (every connector) or
  `--allow-private-origin`; `--deny-private-origin` refuses that grant for
  every connector, connector-level grants included. It does not revoke
  `options.allow_instance_credentials`: under that opt-in cloud connectors
  still contact the instance metadata service, and the `cloud.gcp` credential
  transport accepts a private token endpoint. Pass `--deny-instance-credentials`
  as well to keep cloud connectors off both.
  This exception does not relax origin or TLS checks. HTTP proxies, including
  environment proxy settings, are unsupported by this transport.
* The shared HTTPS adapter bounds response acquisition, including status/header
  delivery, separately from body reads. Cancellation interrupts the active socket
  before it can be pooled for another request. System DNS resolution runs in a
  bounded worker: the resolver call itself cannot be cancelled, but each wait
  fails closed at its budget, at most 20 seconds, and a late result is
  discarded before any connection. At connection the client timeout and the
  acquisition deadline tighten the budget. The `validate_url` preflight is
  tightened by the connector deadline and, for `HttpClient` requests, by the
  client timeout and the client's deadline; its other callers (Git clone
  checks, SDK, MCP registry and JWKS preflights) and the clone pin lookup get
  only the connector deadline. A spent budget refuses without starting a
  lookup, and at most 32 lookups wait on the resolver at once; further ones
  fail closed once their budget passes without a free slot. A stalled resolver
  therefore holds a worker for a bounded time and cannot pile up threads. A
  process/job supervisor remains necessary for a hard execution limit,
  including external SDK transports.
* Default shared HTTP responses and JSON/pagination helpers are limited to 16 MiB
  of decoded bytes, and each body must arrive within twice the client timeout
  (60 seconds by default). Oversized, slow and malformed collection responses
  fail collection, which marks the scan incomplete; a partial body is never
  analyzed.
  Explicit raw streaming callers are responsible for bounded reads and closure.
  Injected Requests sessions have their adapters replaced by destination policy.
  GitLab source-file downloads have a stricter 512 KB (512,000 bytes) per-file cap.
* Configured header values are validated before any request is built; a value
  with control characters (typically a secret file's trailing newline) fails
  without being echoed. The Okta `SSWS` scheme is redacted like `Bearer` and
  `Basic`, and known configuration values are also redacted in their
  `repr()`-escaped spelling, which library errors use.
* Connector warning/error log events contain fixed summaries, never diagnostic
  payloads or exception arguments. Bounded, sanitized diagnostic details remain
  in the scan report; treat reports as sensitive operational artifacts because
  arbitrary upstream text can contain data beyond recognized secret formats.
  An unexpected connector or repository failure raised inside third-party code
  (an SDK or a plugin) is reported by exception type only.
  Shared HTTP retry warnings and HTTP errors retain only a validated HTTPS
  origin and status. Paths, userinfo, queries and fragments are omitted;
  malformed URL diagnostics use fixed messages rather than parser exception text.
  Opaque `api_token`, `foundry_token`, and `github_token` values, including the
  `GH_TOKEN` fallback, are sensitive.
  Diagnostic sanitization preserves credential context across errors, warnings
  and skip reasons; JSON publication also checks connector statistics together.
* Live collectors assign record classification and collection scope after
  copying provider fields. Provider data cannot replace these local provenance
  fields. Offline exports remain untrusted operator-supplied records and do not
  authenticate the declared collection scope.
* Code/cloud credential evidence uses domain-separated HMAC pseudonyms under
  one private key per Engine scan. `SHADOWSCAN_IDENTITY_KEY` supplies an optional
  stable key (at least 32 random bytes, hex/base64); it is never exported or
  cached. Direct library calls use an ephemeral process key. Without a stable
  key, credential-bearing results are rescanned rather than replaying cached
  pseudonyms. Key rotation invalidates cache reuse and collection comparability.
  Resource finding IDs remain stable. Old public credential digests and private
  legacy gateway binding mappings remain sensitive; see the
  [credential evidence migration](../production-migrations.md#credential-evidence-identity-migration).
* `options.connector_timeout_seconds` / `--connector-timeout-seconds` defaults
  to a 120-second cooperative completion deadline. Late connector results are
  discarded and coverage is incomplete. Legacy `connector_timeout` /
  `--connector-timeout` remain compatibility aliases; legacy YAML null uses the
  default. Python cannot forcibly interrupt blocked threads: calls may outlive
  `Engine.run()`. The CLI writes an incomplete report and exits without joining
  an abandoned worker once timeout handling returns. A filesystem replacement
  already in progress can finish after the timeout report; a cache or record
  file from a timed-out connector is unaccepted even if it exists. Record export
  manifests mark these entries `exported: false`. Embedded callers still need a
  process supervisor; worker concurrency remains bounded. Enforce an external
  process or job deadline when a hard runtime limit is needed.
* Azure App Service settings and OCI Function configuration are exported under
  `environment`, so record dumps redact every value; Salesforce token
  values are never requested.
* Cloud SDKs and Git use separate transports. A clone is pinned to the addresses
  ShadowScan resolved and checked (`http.curloptResolve`, proxy variables
  ignored), so Git does not resolve the clone host again; the cloud SDKs get no
  such pin. Network egress rules remain needed for those paths.
  Custom non-Requests transport doubles remain trusted extension/test mechanisms.
* JWT classification remains unverified by default. Optional `jwks_url` signature
  verification uses the shared transport with a bounded JWKS body and key count.
  Only allowlisted asymmetric algorithms and unambiguous eligible public keys
  are accepted. Symmetric and private keys are rejected. `allowed_algorithms`
  can narrow the supported set; `expected_issuer` validates an operator-supplied
  exact issuer. An unverified issuer does not select a JWKS source. Expiry and
  audience are not authorization checks: historical tokens are valid analysis
  inputs. `metadata.verified` never grants permission to act.
* Offline exports use bounded reads without following symlinks, including
  intermediate path components. YAML construction bounds nodes, aliases, depth,
  merge expansion and expanded content before Python objects are constructed.
  Sanitization bounds expanded structure and total replacement work. Ownership
  patterns use bounded matching instead of backtracking regexes, and the code
  scanner's IaC and agent front-matter patterns run on the bounded engine under
  the per-input matching budget. Symbolic links count toward `max_files` and
  their checks stop at the connector deadline. Limit hits and
  malformed inputs make coverage incomplete while retaining valid neighboring
  findings. These are resource safeguards, not process isolation or a universal
  deadline across every external SDK call.
* Record dumps enforce replay's encoded-byte line and file limits and reject
  non-finite JSON numbers. Omitted valid export records remain available to
  live analysis, but the scan and export manifest are incomplete and the new
  dump is not published. Sanitizer safety-limit rejections skip the record and
  also abort dump publication. Preserve the manifest when replaying;
  a direct partial JSONL replay cannot establish collection completeness.
* Git history enrichment is disabled by default. Explicit `use_git: true`
  uses metadata-only commands with lazy fetching and every transport disabled;
  stdout and stderr share a 16 KiB limit, identity fields are capped, and
  cancellation or deadlines terminate the metadata process group. Unsupported
  Git behavior, malformed metadata or exceeded limits makes coverage incomplete.
  Metadata preflight rejects common-directory and alternate-object indirections,
  local `include`/`includeIf` configuration sections, internal links and special
  files. Local `config` and `config.worktree` are read through confined
  descriptors within a 1 MiB limit; unsupported section syntax, encodings,
  continuations and multiline values fail closed. Inputs must remain immutable while Git runs;
  preflight is not a filesystem snapshot or process sandbox.
  Clone calls have a separate HTTPS-only policy: credentials stay scoped to the
  approved origin and redirects are disabled. Hooks and inherited Git overrides
  are suppressed, and clones verify the objects they receive. A termination signal
  or the job deadline stops in-flight clones and removes their checkouts. Unsafe
  branch values are dropped with incomplete diagnostics.
  Remote repository data cannot select an internal offline filesystem path.
  Keep Git patched and use disposable workers for untrusted inputs.
* Reports and generated inventory stubs are written atomically with mode 0600,
  never to a symbolic link and never through a directory link that another user
  owns, a link inside another link's target included; the file is created and
  renamed relative to the opened real directory. `..` in the output path is
  resolved before any link is followed: `-o mylink/../r.json` writes `r.json`
  beside `mylink`, not in the parent of the link's target.
  An existing character device given as the output path (such as `/dev/null`)
  is written in place, and an existing named pipe only when the current user
  owns it with mode 0600; other non-regular paths are refused.
  Dump directories must be private (0700); record files use 0600 and unique
  per-instance filenames. An export manifest records provenance/completion without
  raw connector configuration. JWT records are never exported. No `--dump-raw`
  option exists.

## Other implemented controls

* Generated inventory resource bindings escape literal glob characters. Manual
  wildcard approvals remain possible and require operator review. Surface,
  provider and account restrictions still apply; ambiguous matches do not approve.
  Atlassian app keys require a concrete configured HTTPS site and an explicit
  account constraint on the approval. Unknown site identity leaves the scan
  incomplete and generated cards unbound; site fields in untrusted exports
  cannot supply or override that trusted scope.
* Configuration rejects missing or empty required environment substitutions,
  duplicate YAML keys, unknown top-level/options fields and invalid gate levels.
  Explicit `${VAR:-default}` fallbacks remain an operator policy decision.
* Incomplete scans exit 3 and set SARIF executionSuccessful=false. Only complete
  results qualify for incremental reuse. Comparisons infer resolution only for
  complete scans with matching collection, detection and finding-identity schemas,
  and never for a finding in content the current scan declared (`--profile ci`,
  `declared_omissions`) or tolerated (coverage budget, `stats[].coverage`) as
  unread. A gap the default profile discounts in test code (a warning ending
  "test code is discounted evidence") is counted in neither and does not hold a
  missing finding back.
  Explicit unmatched connector selections and unsupported/error exports fail
  visibly. Incremental input roots and ancestor symlinks are ineligible for reuse;
  pre/post hashing is not an atomic filesystem snapshot. Keep inputs immutable
  while scanning. Runtime telemetry attribution does not prove that a particular
  dependency executed.

See [deployment and migration](../production.md),
[scan semantics](../scanning.md),
and [connector permissions](../connectors.md).
