# Production deployment and migration

This is the rollout guide for version 0.1.2. It covers reviewed
revisions, installation, validation, rollout, operation and migration.

Automated validation establishes implementation behavior. Production rollout
also requires the tenant canaries and container/operational checks below; a
passing unit suite does not establish complete coverage of a particular estate.


## Migration notes and change history

Per-change migration and behavior notes for unreleased changes live in
[pending migration notes](production-migrations.md), and the dated log of
every candidate change lives in the
[candidate change history](history/production-change-history.md), so this
page stays the rollout guide.

## Review before deployment

The model-identifier pass leaves coverage incomplete (exit 3) when a file
exceeds its 400-literal analysis limit. Only literals that carry a vendor stem
(model-id candidates) count; ordinary strings never reach the limit. Findings
from the analyzed prefix remain available; review the unread content
separately before using an incomplete result for an assurance decision.
Catalog assignment and data-file reference limits likewise mark coverage
incomplete when unread content could change the configuration classification.
A truncated reference list is reported only when the project discounts a data
file as a catalog that an unread reference could have named; otherwise the
unread references change nothing and the scan stays complete.

Text decoding examines every bounded window before accepting replacement
characters. A plain-text prefix does not exempt a binary body from incomplete
coverage. Python and notebook inputs remain strict UTF-8 inputs when they
carry a UTF-8 byte-order mark; invalid bytes leave a coverage gap (exit 3).

Before selecting a revision, verify its final-head review record and the live
merge rules. A versioned policy, merged pull request or passing CI does not
establish independent human review. The [merge gate and review status](#merge-gate-and-review-status)
section records the available evidence and commands for checking current
enforcement. Independent human review is required before any tagged release.

Release tags are annotated; personal tag signatures are optional. Verify the
downloaded wheel's digest and GitHub provenance as described in the
[publishing runbook](operations/publishing.md#per-release). Workflow
attestations identify the artifact's origin and do not replace the review
record or deployment acceptance evidence.

## Contents

1. [Review before deployment](#review-before-deployment)
2. [Pin and install a reviewed revision](#install-from-a-reviewed-revision)
3. [Validate security policy, Git metadata and resource limits](#explicit-security-policy)
4. [Roll out with tenant acceptance evidence](#rollout-acceptance)
5. [Operate within collection and resource limits](#resource-limits-and-incomplete-scans)
6. [Upgrade and migrate identities](production-migrations.md)
7. [Candidate change history](history/production-change-history.md)

## Install from a reviewed revision

The scheduled dependency and governance audit checks both live merge rulesets
against the versioned desired policy. Its GitHub token is read-only: a green
job establishes that the visible managed fields match, but its retained
observation can still report partial assurance because GitHub withholds bypass
settings. Read `complete_readback_verified` and `unknown_fields` in each
observation; never interpret an omitted bypass list as empty. A failed or
unavailable read does not establish protection. Repository administrators must apply the
[reviewed ruleset updates](operations/merge-policy.md) and verify fresh API
readback. The audit neither changes settings nor substitutes for independent
human review or tenant acceptance.

Check out an audited full commit SHA before installation. README and example
workflow instructions require a full reviewed commit; a fixed example SHA would
fall behind new fixes. Record the exact revision with deployment evidence and
verify the checkout matches it before building. Do not use a floating branch or
a tag that has not been published.

```bash
SHADOWSCAN_REVISION="REPLACE_WITH_REVIEWED_40_CHARACTER_SHA"
git clone https://github.com/aisecnomad/Nexus-ShadowScan.git
cd Nexus-ShadowScan
git checkout --detach "$SHADOWSCAN_REVISION"
test "$(git rev-parse HEAD)" = "$SHADOWSCAN_REVISION"
```

The install commands below use the files in this checked out tree. Check that
`git status --porcelain` is empty and retain the commit SHA, CI links, dependency
lock and built wheel hash for each worker deployment.

The runtime lock covers the core scanner and all cloud SDK extras on CPython
3.11, 3.12 and 3.13, Linux x86_64. It contains exact versions and permitted
SHA-256 hashes; Linux CI checks installation and dependency consistency on all
three interpreters. Linux x86_64 is the only validated deployment target for
this full runtime/cloud lock. The macOS 3.11 and 3.13 CI jobs install
`requirements-ci.lock` and this runtime lock from the same published wheel
hashes and run the full test suite, which validates development use there;
the coverage floors are enforced on Linux Python 3.11. Use CPython 3.12.4 or
later rather than 3.12.0 to 3.12.3: their `tokenize` is quadratic on a long
line, so redaction there charges each token's line copy to its work budget and
a file with a very long line can leave a scan incomplete (exit 3). Ubuntu 24.04
ships 3.12.3. A macOS deployment still
needs its own wheel,
container and acceptance evidence. Windows is not
supported at all, because the confined file reader
(`O_NOFOLLOW`, `O_DIRECTORY`, `dir_fd`) is unavailable there and the scanner
refuses to read any input rather than weaken that policy. The lock is not
universal for ARM or every future Python release either. Resolve and validate a
separate lock before deploying on another platform.

From the reviewed checkout, in a clean virtual environment:

```bash
python -m pip install --require-hashes --only-binary=:all: -r requirements.lock
python -m pip install --require-hashes --only-binary=:all: -r requirements-build.lock
python -m pip wheel . --no-deps --no-build-isolation --wheel-dir dist
python -m pip install --no-deps dist/nexusshadowscan-0.1.2-*.whl
python -m pip check
python -m shadowscan.signatures.validate
python -m shadowscan.mappings.validate
shadowscan --help
```

The runtime lock deliberately includes all cloud extras, even for a code-only
worker. Development tools are not part of it; CI and `make install-dev` use
`requirements-ci.lock`, which hash-locks the core and development environment.
`requirements-ci-constraints.txt` is a reviewed version input for regenerating
that lock and is never installed by CI. The build backend is locked separately:
`requirements-build.lock` carries the exact `[build-system]` requirements from
`pyproject.toml` (setuptools and wheel) with the SHA-256 hash of every artifact
PyPI publishes for those releases. Install it under `--require-hashes` and build
with `--no-build-isolation`, as above; an isolated build would let pip resolve
the backend from the live index on a version pin alone. CI fails when the two
files disagree, so refresh them together. Build the
wheel in a controlled builder, retain its SHA-256, and install that reviewed
artifact into workers. Capture the builder image digest, Python/pip/build-backend
versions and wheel hash: matching runtime dependencies alone does not ensure
identical wheel bytes. Dependency hashes
prevent silent runtime artifact substitution; they do not establish that a
dependency is safe.

Regenerate intentionally in a clean Linux environment with Python 3.12 and
`pip-tools==7.5.3`, review the dependency diff and advisory results, and let every
CI matrix job verify the result:

```bash
pip-compile --extra cloud --generate-hashes --strip-extras \
  --no-emit-index-url --no-emit-trusted-host --no-annotate \
  --output-file requirements.lock pyproject.toml

uv pip compile pyproject.toml --extra dev --universal --generate-hashes \
  --no-emit-index-url --no-annotate --no-header \
  --constraint requirements-ci-constraints.txt \
  --constraint requirements.lock --constraint requirements-build.lock \
  --output-file requirements-ci.lock
```

The current CI lock records the reviewed `uv` version in its header. Use a
different resolver version only as an intentional toolchain change. Use
`--upgrade` only for an intentional dependency refresh. Preserve each lock's
supported-platform comment when regenerating. Do not bypass failed hash checks.

The Dockerfile installs both locks under `--require-hashes`: the runtime lock
into the virtual environment the runtime stage copies, and the build lock into
a separate build environment. That environment builds the package wheel with
`--no-build-isolation` and is not copied. The image runs as UID/GID 65532. Both
stages pin the same multi-arch `chainguard/wolfi-base:latest` image index by
its literal digest; Python 3.12 and Git are Wolfi packages, and pip stays in
the build stage. Both stages also pin Wolfi's `python-3.12` to one package
revision for now; see
[October 2 integration of #134](history/production-change-history.md#october-2-integration-of-134-and-hygiene-review).
Because apk reads the live Wolfi repository, this image is not byte-for-byte
reproducible. Retain the built image by immutable digest for repeatable
deployment. Reproducible rebuilds additionally require an immutable package
repository snapshot and a validated reproducible build process; a rebuild
cadence alone does not supply either. Keep both `FROM` digests and Python package
pins identical across the build and runtime stages.
The image build checks that Git is 2.45 or newer for history enrichment.
Review that exact digest and any Dependabot refresh before deployment:

```bash
docker build --tag shadowscan:reviewed .
```

Retain the reviewed base and built image digests. The build context is an
allowlist (`.dockerignore`) of package sources, signature and mapping data,
packaging inputs and the runtime/build locks. Distribution packages from `apk`
and image metadata remain mutable, so the Dockerfile does not promise byte-for-byte
reproducible images. There is no claim of a hermetic package snapshot. CI
smoke-tests a non-root, read-only and network-isolated image; build and test the
deployment image, generate its container/OS SBOM, and validate resource limits
and output-directory permissions before rollout.

Docker Hub rate-limits anonymous pulls by source address, and hosted CI runners
share their egress addresses. CI's container job therefore adds Google's Docker
Hub pull-through cache, `https://mirror.gcr.io`, to the runner's Docker daemon
`registry-mirrors` setting, fails unless the restarted daemon reports it, and
pulls the base image by the digest in the Dockerfile's `FROM` lines before the
build. A digest pull is content-verified, so the mirror cannot change the base
image, and the daemon falls back to Docker Hub when the mirror fails. A builder
elsewhere that hits the limit can set the same daemon mirror or authenticate to
Docker Hub; the digest pin keeps the base image identical either way.

The [Kubernetes offline Job example](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/examples/k8s-job.yaml) has a 20-minute
active deadline, a placeholder for a reviewed image digest, and a matching
NetworkPolicy that denies egress when enforced by the cluster CNI. Supply a
reviewed `/input` volume before running it. For live API collection, use a
separate Job and enforce a network path through an approved transparent egress
gateway or firewall that filters by name; a standard Kubernetes NetworkPolicy
cannot filter destinations by DNS name, and ShadowScan's HTTP client and its Git
clones ignore proxy environment variables (the client also rejects an explicit
proxy). See [operational controls](operations/operational-controls.md).

Opt-in Git history enrichment requires Git 2.45+;
verify the distribution Git version if that feature is needed. Cloning also requires
Git 2.45 or newer, because the clone's revision and gitlink inventory are read with
`--no-lazy-fetch`; with an older or unidentifiable Git (Ubuntu 24.04 ships 2.43) the
scan uses sampled API mode and is incomplete. Keep runtime secrets out of the build context.

For record replay, read `exports/manifest.json` and use the `filename` for the
intended connector instance; export names are not a fixed `cloud_aws.jsonl`.

## Explicit security policy

Plugin connectors default to `plugin_execution: process` workers, so a
plugin that exceeds its deadline can be stopped and never sees the raw
operator identity key; `options.plugin_execution: thread` keeps the old
in-process behavior and gives both guarantees up.

```yaml
options:
  plugins: []
  plugin_execution: process
  allow_signature_override: false
  allow_private_origin: false
  allow_credential_mixing: false
  allow_instance_credentials: false
  connector_timeout_seconds: 120
connectors:
  - name: identity.jwt
    input: ./tokens.json
    jwks_url: https://identity.example.com/keys
    expected_issuer: https://identity.example.com/
    allowed_algorithms: [RS256]
```

`plugins` contains exact connector names, not module paths or wildcard patterns.
Approved plugins still run trusted Python code. `shadowscan connectors` lists
installed plugin metadata without importing it. A plugin must be explicitly
allowed on each scan, even if a prior scan imported it.

Approved third-party connectors run in dedicated spawned workers by default
(`options.plugin_execution: process`, `--plugin-execution process`); built-in
connectors always run on threads. `options.plugin_execution: thread` or
`--plugin-execution thread` runs plugins in the scanner process (the previous
default), where a blocked plugin cannot be stopped at its deadline.
In process mode, plugin import and execution happen in the child. The original
connector deadline includes worker startup and result transfer, and the worker
exits as soon as its result is sent (plugin `atexit` handlers do not run); expired results
are discarded, and termination escalates from TERM to KILL with bounded cleanup.
A parent supervision guard allows up to two additional seconds for cleanup.
Workers also exit by themselves two seconds after the deadline, or as soon as
the scanner process exits (job-deadline watchdog, signals), and a
`KeyboardInterrupt` during collection kills them at once. Worker crashes, invalid result schemas and output above the 16 MiB JSON
transport limit make the scan incomplete. There is no automatic thread fallback.

Process mode is lifecycle isolation, not a security sandbox. Workers inherit the
scanner's privileges and environment, and killing one does not undo remote
changes, completed cache/export writes, or terminate its independently spawned
descendants. Continue to use an external job deadline and disposable workers
with appropriately restricted credentials and filesystem/network access.
Embedded Python entry points must use the usual `if __name__ == "__main__"`
guard for spawning. Plugin workers are daemonic and cannot themselves start
`multiprocessing.Process` children. A worker discards the plugin's standard
output, standard error and logging. See [connectors](connectors.md) for the
plugin execution contract.

Keep scans of repository content separate from jobs holding live cloud, identity,
SaaS or low-code credentials. By default, configuration rejects a selected code
connector alongside a selected live credentialed collector. A single remote code
connector can use its repository token; code plus offline exports is allowed.
`allow_credential_mixing: true` permits a reviewed exception, but does not isolate
the repository from credentials available in the worker. Use separate disposable
workers for untrusted repositories.

`allow_instance_credentials: false` disables implicit cloud instance-metadata
credential acquisition. Enabling it is a global opt-in; a connector-level value
cannot silently override that policy. The engine replaces the key in any
connector entry with the scan-wide value, and passes that value to every
`cloud.*` connector, plugins included, and to any plugin that declares the
cloud surface or documents the key in its `config_keys`. Before this release
only `cloud.*` entries were replaced, so review plugin entries that set their
own `allow_instance_credentials: true`: it no longer takes effect. Use
explicit audit credentials or approved workload credentials and inspect
account/tenant attribution before rollout.
These settings are credential-use policy, not a process or network sandbox.

Custom packs can add signatures by default. Replacing a built-in signature
requires explicit `allow_signature_override` approval. Enable private origins
only when the selected scan requires a trusted private HTTPS endpoint; keep
network-layer restrictions appropriate for that scan. Separate private-endpoint
scans from public collection when they need different trust policy.
Configuration rejects duplicate authored YAML keys and unknown top-level or
`options` fields. `${VAR}` must resolve to a nonempty value; use
`${VAR:-fallback}` only where an explicit fallback is appropriate. Invalid
`fail_on` thresholds or `parallel` values stop the scan before collection.
Environment references are validated in disabled connector declarations too;
remove unused placeholders or give intentionally optional values a fallback.
Relative inventory globs and `options.workdir`, like other configured paths
(including `identity.jwt` `ca_bundle`), resolve beside the configuration file,
independent of the process directory.

The new policies also expose `--connector-timeout-seconds`,
`--allow-credential-mixing/--deny-credential-mixing` and
`--allow-instance-credentials/--deny-instance-credentials`.
All scan commands also expose `--allow-plugin`,
`--allow-signature-override/--deny-signature-override` and
`--allow-private-origin/--deny-private-origin`. Configured values are retained
unless explicitly overridden; `--deny-private-origin` also overrides every
connector-level `allow_private_origin`. Signature inspection commands expose the same
signature override opt-in. JWT CLI verification additionally accepts
`--expected-issuer` and repeatable `--jwt-algorithm`.

The shared HTTP transport enforces destination policy at connection time and
retains TLS hostname checks. A well-known NAT64 address (`64:ff9b::/96`, what
a DNS64 resolver returns on an IPv6-only runner) is judged by the IPv4 address
it embeds; the local-use prefix `64:ff9b:1::/48` is always refused. HTTP proxies are unsupported; environment proxies
are ignored. Cloud SDK and Git transport behavior remains separate. Do not assume
that the shared client's policy controls every network connection in the process.
Inject only trusted `requests.Session` implementations. Calls to the shared
client that explicitly request `stream=True` must read within a size limit and
close the response; the default buffered response path enforces a 16 MiB limit
and a whole-body [read deadline](#resource-limits-and-incomplete-scans).

JWT verification is for analysis. The default scope is signature evidence;
configuring `expected_issuer` also binds the issuer. Neither mode authorizes a
request or substitutes for audience, expiry and application-policy validation in
an actual relying service.

## Git metadata policy

All code connectors default to `use_git: false`. Source inspection and
`CODEOWNERS` still work without invoking Git for history enrichment. For reviewed
local metadata, set the connector's `use_git: true` explicitly (a YAML boolean).
History enrichment requires Git 2.45 or later and a self-contained `.git`
directory; external gitfiles and symlinks are not accepted for enrichment.
Metadata preflight also rejects common-directory and alternate-object
indirections, local `include`/`includeIf` configuration sections, internal links
and special files. Local `config` and `config.worktree` use confined reads with
a 1 MiB limit and a conservative UTF-8, single-line configuration grammar.
Ordinary sections, quoted or deprecated dotted subsections, comments and
single-line values work; unsupported section syntax, continuations and multiline
values make coverage incomplete before Git starts. Inputs must remain immutable
while Git runs; preflight is not a filesystem snapshot or process sandbox.
Unsupported versions and failed metadata reads, including unavailable history
objects, make the scan incomplete while preserving code findings.

Incremental scans with `use_git: true` run the same bounded preflight before
Git fingerprinting and cache reuse, within the connector deadline. Unsafe
metadata disables reuse; the full scan retains source findings and reports
incomplete coverage. Updating the scanner invalidates previous cache entries
through its source digest.

Metadata commands disable hooks, lazy fetching and every transport. Authenticated
cloning uses a separate HTTPS-only policy. Remote JSON fields such as
`_local_path` cannot select local scan roots or substitute for a verified offline
record. Use fresh disposable workers and immutable inputs; these controls do not
turn Git or the scanner into a process sandbox.

## Resource limits and incomplete scans

Record dumps are JSONL and obey offline replay's 4 MiB encoded-byte line limit,
including the newline. Each connector export also obeys the smaller of its
`max_input_file_bytes` and `max_input_bytes` limits: 32 MiB by default. The hard
file ceiling stays 64 MiB. Export-size and strict-JSON serialization rejections
make the scan incomplete while preserving valid original records for analysis.
Sanitizer safety-limit rejections skip the unsafe record and make the scan
incomplete. Any of these rejections aborts dump publication and preserves a
prior file; the manifest marks the new export `exported: false`.
A partial dump is not complete evidence. Use smaller collection scopes or raise the
configured file/total limits within their hard ceilings when appropriate.
The line limit is fixed, so a single oversize record requires an upstream
export with bounded records rather than a larger file limit.

Shared HTTP JSON responses are streamed and limited to 16 MiB of decoded
content by default. Each network attempt has a response-acquisition budget of
twice the client timeout (60 seconds by default), covering connection, request
transmission, status line and headers. TCP candidates and TLS handshakes share
the remaining acquisition time. The active socket is interrupted on expiry;
the watchdog is cancelled and joined before the response can leave its checked-out
connection. System DNS runs in a bounded worker: the resolver call itself
cannot be cancelled, but each wait fails closed at its budget, at most 20
seconds. The connection-time lookup is tightened by the client timeout and the
acquisition deadline, and a late resolution is discarded before connection.
The `validate_url` preflight that precedes it is tightened by the connector
deadline and, for `HttpClient`, by the client timeout and deadline, so one
request can wait on DNS twice. A spent budget refuses without starting a
lookup, and at most 32 lookups wait on the resolver at once; when a stalled
resolver holds them all, further lookups fail closed at their budget. A
process/job supervisor is still needed for a hard time limit.

Each response body has a separate budget of twice the client timeout.
The 30-second client timeout also bounds individual socket reads, so without
these budgets a server sending a byte just inside every timeout could hold a
worker until the connector deadline abandoned it. A body still being read at the deadline is
aborted (`HTTP response exceeds the read deadline`) and the connector's
collection is incomplete (exit 3); a partial body is never analyzed. The
budgets follow the client's timeout, not a `timeout` passed with one
request. Retries and redirects each get a fresh acquisition budget:
`connector_timeout_seconds` still bounds a connector's whole collection.
Pagination rejects missing or malformed collection arrays and records an
incomplete scan when a response exceeds its limit. Review unusually large
provider pages against their API contract before raising a per-client or
per-request limit. GitLab file downloads remain capped at 512 KB (512,000
bytes) per file.

YAML parsing checks input size, composed nodes, alias count, nesting, expanded
nodes/content and merge work before object construction. Sanitization has a
separate expanded-structure and total-work budget, so valid YAML aliases cannot
cause unbounded report serialization. CODEOWNERS patterns use bounded iterative
matching with a per-lookup work budget.

`code.filesystem` reserves incomplete coverage (exit 3) for content it would
have read. Since the model-identifier and corroboration changes of the next
release, the remaining lockfile names and generated files (`*.log`, `*.har`,
`*.snap`) joined the default `oversize_skip_globs`, so such a file over
`max_file_size` is skipped with a warning and leaves the scan complete. Change
logs are deliberately not on that list: a name glob such as `CHANGELOG*` would
also match source files (`history_store.py`, `changes.ts`) that a scanned
repository names freely. With `scan_secrets: false`, an oversize documentation
file (`.md`, `.txt`, a `CHANGELOG.md` included) and, without `include_tests`,
an oversize file under a test or fixture path (a recorded cassette) are skipped
with a warning; with credential detection on (the default) they are read for
credentials below the limit and stay a coverage gap above it, so no planted key
is lost to an exit 0. A repository with a change log over `max_file_size`
therefore still exits 3 under the default settings; raise `max_file_size`, or
review the file and list its path in `oversize_skip_globs` (the setting
replaces the default list, so keep the defaults beside it). `strict_coverage`
keeps every skip outside the globs a gap. See the [coverage policy](scanning.md#large-and-generated-files).

The code scanner's IaC wildcard-action and agent front-matter patterns run on
the bounded regex engine under the same per-input matching budget as the
signature patterns, so a planted file costs at most that budget and is
reported as an incomplete file rather than holding the connector. The crawler
user-agent discount tokenizes only lines naming `mozilla/`, in linear time, so
a planted file of escaped quotes cannot hold the connector either. Symbolic
links count toward `max_files` together with regular files. A checkout with
more links than the remaining `max_files` budget needs a larger `max_files` or
an `exclude` entry for the link directories. The walk lists a root's entries
before it scans them in priority order; listing, including the checks of file
and directory links, stops after half of the time in which a file can still
start, with the error `connector deadline: listing stopped after N entries`,
so the listed files are still scanned and their findings kept. The link-check
error `connector deadline reached while checking symbolic links` remains as a
backstop at the deadline margin. The scan is incomplete (exit 3). A root that
starts when no file can start any more, such as a late repository of an
organization scan, lists nothing (`after 0 entries`), so it cannot run the
connector past its deadline and discard the findings of the roots scanned
before it. A tree whose listing alone takes more than that half is reported
incomplete even when the former interleaved walk would have finished in time;
raise `connector_timeout_seconds` for such a tree.

YAML manifest artifact matching uses a shared one-second deadline and gives
each bounded line chunk no more than the remaining manifest pattern budget.
Concurrent collection can take over the signature matcher’s separate 100 ms
ceiling while still remaining inside that manifest deadline and any active
per-input scan deadline. Exhausting either deadline marks the code scan
incomplete (exit 3).

A limit hit is a diagnostic and incomplete coverage, not proof of absence. Exit 3
must remain a failed gate in CI. Exit 2 means a complete scan exceeded the chosen
risk threshold. `connector_timeout_seconds` defaults to 120 seconds and must be a strictly positive
finite number. It starts when the connector worker begins, and split filesystem
roots share that connector's deadline. The engine stops accepting a connector's
results after the deadline and records incomplete coverage. Python
worker threads (built-in connectors, and plugins under `plugin_execution: thread`)
cannot safely be killed: a blocked SDK call can continue after
that soft deadline. The CLI normally exits after emitting an incomplete report,
but a filesystem replacement already in progress can finish after the timeout
report. Such cache or record artifacts are unaccepted even if present; timed-out
record exports are `exported: false` in the manifest. Use a fresh state and
export directory after a timeout to avoid reusing a late cache or orphan export.
Embedded callers must supervise their process and
cannot reuse an Engine with an active abandoned worker. Also enforce a host/job
wall-clock deadline and terminate the disposable worker when it expires.
SDK connect/read limits and bounded retries reduce blocking; none guarantees a
universal hard deadline for the whole scan.

For CLI scans, `--job-deadline-seconds 600` or
`options.job_deadline_seconds: 600` also arms a process watchdog covering plugin
discovery, engine setup, collection and report output. The explicit CLI option
starts during option processing, before command preparation, including connector
metadata discovery for `run` and stdin reads for `jwt`. A YAML-only deadline starts
after the configuration has been read and validated. Use an external supervisor
to bound process startup, Click argument parsing and YAML preflight. The value
must be positive and finite; omission or YAML `null` leaves it disabled. Expiry
terminates the scanner with exit `3`, without guaranteeing a final report. It first
stops in-flight `git clone` process groups and deletes their temporary checkouts (best
effort, bounded to a few seconds); SIGTERM, SIGINT and SIGHUP do the same before the
scanner exits. SIGKILL and OOM kills cannot, so keep the external job deadline and
process-group or container cleanup. A blocked output stream cannot delay that exit. Completed CLI
invocations disarm their watchdog. `Engine` embedding does not arm it: the host
application owns process supervision. Keep the external job deadline and process
group/container cleanup to reap child processes and bound native code that holds
the interpreter lock indefinitely.

Without a job deadline, a CLI scan that abandoned a timed-out connector worker
still cannot hang while it writes the report: the CLI allows 30 seconds for
report output and clone cleanup, then exits `3` with a message that coverage is
incomplete. When that exit fires, the report may be missing or truncated
(standard output can stop mid-document), an existing `-o` file may still hold
the previous report, and a private temporary file may remain beside it; treat
none of them as this scan's result. With a job deadline set, that deadline bounds
report output instead and the 30-second limit is not armed. Ctrl-C (SIGINT)
during report output also disarms the job deadline, so the 30-second limit is
armed then, and the CLI does not wait for the abandoned worker. A completed
invocation disarms it.

Code scans follow a documented coverage policy. Links whose own names are never
read, source-file links whose real targets are analyzed in the same project
with the same test classification, coding-agent instruction-document links
to another instruction document under the same condition, and (with
`inspect_model_artifacts`) model-artifact links to a scanned artifact with the
same suffix under the same condition, are skipped because
nothing at the alias path is lost (see [scan semantics](scanning.md) for the
exact rule). Directory
links, configuration aliases, links into excluded or unread content, links
leaving the root, oversized files the scanner would
inspect and files it analyzes by name but cannot read as text (binary content
with dense NUL bytes, mostly invalid UTF-8, or UTF-16 or UTF-32 without a byte-order mark; a few stray NUL
bytes or invalid bytes in otherwise valid text do not count) make the scan
incomplete (exit 3) by default, with a warning naming the omission.
`strict_coverage: true` (`--strict-coverage`) records those
conditions as errors; explicit `oversize_skip_globs` remain declared omissions
in both modes. Raise `max_file_size` or add `exclude` patterns for known data files.
A non-empty `bin`, `build`, `dist`, `out`, `target`, `obj`, `coverage`, `vendor`,
`third_party`, `thirdparty` or `external` directory that the walk skips by default
is listed in one warning per scan root (the scan stays complete); set
`default_excludes: false` (`--no-default-excludes`) to scan them. Evidence found
only in test or fixture paths has half weight and cannot promote a project to an
agent unless `include_tests: true` (`--include-tests`) is set, and a project
finding whose evidence is already reported by an MCP configuration, agent
manifest, exported workflow, IaC or credential finding is not emitted again.
Recognisable placeholder credentials (repeated characters, marker words such as
`EXAMPLE`, very low character diversity) are no longer reported. A
real-format credential in a test, fixture or `cassettes/` path is still a
`secret` finding, at half weight and tagged `test-code-only` unless
`include_tests: true` is set. Risk factors
always sum to the reported score; `risk.danger_score` excludes the governance
factors and `options.risk_basis: danger` bases `level` and `--fail-on` on it.
Review [scan state and runtime correlation](scanning.md) and the changelog
before raising an enforcement gate on a scanner upgrade.

A ServiceNow agent remains a native finding if optional display-name or OAuth
signature matching times out before the agents are emitted. The connector marks
coverage incomplete and skips repeated matching; exit 3 remains mandatory.
OAuth findings whose classification could not finish are omitted, and native
findings must not be interpreted as fully enriched.

Saved provider errors and unsupported/malformed export records also make scans
incomplete. Valid neighbors remain available. Explicit empty inventories such
as `[]` remain valid; an authorization-error document is not an empty inventory.
Identity and low-code collectors retain available records when enrichment or a
later page fails. Auth0 offset pagination has a finite page budget and detects
repeated pages. Okta grants and optional tokens both follow pagination.
Zoom's Marketplace listing enumerates approved public and account-created apps;
its results do not prove a per-user installation. A denied or incomplete
Marketplace category marks the scan incomplete.
Google Workspace accepts omitted empty arrays only in identified native users
and token-list envelopes; an arbitrary empty object is incomplete coverage.
Every `--only` value must match an enabled connector name or label, including
when another selector matches successfully.

Use disposable, resource-limited workers for untrusted repository scans. Keep
scanner state and output outside the repository under review. Avoid handing
production credentials to a job that executes repository-controlled build steps.
For GitHub/GitLab remote repository scans, preflight estimates and process-group
cancellation reduce ordinary runaway clone cost. `clone_max_bytes` also stops a
clone when observed checkout use, including `.git`, exceeds the configured cap.
It checks during the clone and after Git exits; a failed measurement or excessive
entry count also stops Git, removes the partial checkout and makes collection
incomplete while retaining the sampled API fallback. Periodic checks can
overshoot the threshold, and the cap does not limit network transfer bytes or
guarantee a hard writable disk ceiling. Give each disposable worker an
operating-system/container writable disk quota, memory and process limits, a
separate job wall-clock deadline and a cleanup policy for abandoned workspaces.
A worker's soft connector timeout is not a hard kill for every child process.
A local checkout example, such as
`examples/github-action-code-scan.yml`, does not exercise the remote clone path.

## Release verification

### Merge gate and review status

The [versioned policy and activation procedure](operations/merge-policy.md)
retain the existing required checks and add `CI gate`, bind them to GitHub
Actions, and require fresh non-author approval with no bypass actors. Use
`python -m tools.governance_check RULESET_JSON` on a fresh API snapshot before
relying on enforcement. Neither the policy file nor this checker updates live
repository administration settings.

Ruleset
[23913372, Require CI and CodeQL](https://github.com/aisecnomad/Nexus-ShadowScan/rules/23913372)
is configured to require `test (3.11)`, `test (3.12)` and `analyze`, an
up-to-date branch, and one approving review from a reviewer with write access,
alongside `Protect main`. The 2026-10-10 readback below shows the aggregate
`CI gate` added to that required-check list with the existing checks and
approval rule retained. Its enforcement
state has changed more than once during 2026-09: the 2026-09-24 review recorded
it disabled; on 2026-09-25 (13:10 UTC) a merge attempted without an approving
review was refused with "Repository rule violations found", so it was enforced
at that moment; on 2026-09-27 (10:40 UTC), and again on 2026-10-01 during the
discovery review, both rulesets were read back with `enforcement: disabled`.
The October 1 branch response also reported `protected: false`. During the
October 2 hygiene review, both rulesets were read back as `enforcement: active`
and the branch response reported `protected: true`. `Require CI and CodeQL`
retained one required approval, stale-review dismissal, strict checks and no
bypass actors; its required checks still omitted `CI gate`. `Protect main`
separately retained administrator and integration bypass actors. Treat no
observation as permanent; only the live commands below describe the current
state. Keep the CodeQL job's displayed name `analyze` consistent with the
required check.

Both rulesets were read back active on 2026-10-01 (updated 17:30 UTC).
`Require CI and CodeQL` requires one approving review of the final revision
with stale reviews dismissed, the strict required checks `test (3.11)`,
`test (3.12)` and `analyze`, CodeQL alert gating and signed commits, and lists
no bypass actors; `CI gate` is not yet among its required checks. `Protect
main` adds linear history and deletion protection and still names bypass
actors. At 08:05 UTC on 2026-10-02 both rulesets read back as
`enforcement: disabled` again (last updated 04:28 UTC), and
`GET /repos/aisecnomad/Project-Nexus/rules/branches/main` (the former name)
returned no active rules, so nothing enforced review, CI or linear history on
`main` at that time.
At 19:08 UTC on 2026-10-02 both again read back as `enforcement: disabled`
(last updated 18:39 UTC) with no active rules on `main`. The committed
snapshots in
[`.github/rulesets/observed/`](https://github.com/aisecnomad/Nexus-ShadowScan/tree/main/.github/rulesets/observed)
recorded that 04:28 UTC state until they were refreshed from the 2026-10-10
readback described below.
On 2026-10-03 (19:06 UTC), both rulesets read back active again. The review/CI
ruleset still omitted `CI gate` and application bindings on its three required
checks, and still had `require_last_push_approval` and
`required_review_thread_resolution` disabled. `Protect main` retained four
bypass actors. These observations do not meet the versioned desired policy;
the weekly read-only audit will fail until matching administrator updates are
applied and verified with a complete API response. If GitHub withholds bypass
actors from the read-only workflow token, it will remain failed with unknown
assurance and an administrator must obtain the full readback.
On 2026-10-04, both rulesets read back as `enforcement: disabled` again,
and the `main` branch response reported `protected: false`. The available
GitHub connector exposes no administration-write operation; restoring the
reviewed policy and verifying exact readback requires an administrator.
On 2026-10-06 (23:50 UTC; both last updated at 20:16 UTC), both rulesets
read back `enforcement: active` in complete responses that included
`bypass_actors`, the `main` branch response reported `protected: true`, and
the classic branch-protection endpoint answered HTTP 404 `Branch not
protected`. `Require CI and CodeQL` requires one approving review with stale
reviews dismissed, the strict checks `test (3.11)`, `test (3.12)` and
`analyze`, CodeQL and code-quality gating and signed commits, and lists no
bypass actors; it still omits `CI gate`, the checks' application binding,
last-push approval and review-thread resolution. `Protect main` requires no
approval, adds linear history and deletion protection, and still lists the
administrator role and three integrations as `always` bypass actors. The
weekly audit keeps failing until the reviewed payloads are applied.

On 2026-10-10 (administrator readback; `Protect main` updated 15:53:38 UTC,
`Require CI and CodeQL` updated 15:53:51 UTC), both rulesets read back
`enforcement: active` in complete responses that included `bypass_actors`.
`Require CI and CodeQL` now requires `test (3.11)`, `test (3.12)`, `analyze`
and `CI gate`, each bound to the GitHub Actions application (15368) under the
strict up-to-date policy; one approving review with stale reviews dismissed,
last-push approval, review-thread resolution and extra approval for
unattributed changes; CodeQL and code-quality gating; Copilot code review;
signed commits; and deletion and force-push protection. `Protect main` now
requires one approving review with stale dismissal, last-push approval and
thread resolution, and keeps linear history, deletion and force-push
protection, CodeQL gating and signed commits. Both rulesets list the same
four `always` bypass actors: the repository administrator role
(`RepositoryRole` 5) and integrations 1144995, 1236702 and 2875373. The
integrations were not resolved to application names during the readback.
`python -m tools.governance_check` on the review/CI readback fails with
`bypass_actors_not_empty`; on the `Protect main` readback it reports
`bypass_actors_not_empty, status_checks_required`, the second code because
that ruleset carries no status-check rule and the committed payload does not
add one. `python -m tools.governance.rulesets verify` against each committed
`.update.json` reports `readback differs from reviewed payload:
bypass_actors` and nothing else. The merge gate is therefore not yet enforced
against a repository administrator, who can merge without the non-author
approval. Removing the bypass actors and a readback showing
`bypass_actors: []` remain outstanding. The committed observed snapshots
record this readback.

Classic branch protection is not readable through the app
integration. Read and retain the current configuration before changing it,
and compare it against the [versioned merge policy](operations/merge-policy.md):
`python -m tools.governance_check <snapshot.json>` reports every difference
with a fixed diagnostic code. The policy file is not applied automatically and
does not describe the live state; a repository administrator applies it under
**Settings → Rules → Rulesets**.

Do not claim that the full merge gate is enforced until a readback shows
`CI gate` required and `bypass_actors: []`. The 2026-10-10 readback meets the
first condition and not the second. If the API connection lacks
administration access, use an authorized administrator session rather than
weakening the rules.

Whatever the ruleset's state, the history is unchanged: the repository has a
single maintainer, and no change merged to `main` through 2026-10-02
(including #42, #62, #65 and #123 to #133) carries an approving review from a
second person; the only approvals on merged pull requests are the maintainer's
own, on two Dependabot updates. A repository administrator can bypass or
reconfigure rules, so a merged pull request, the
version string and the internal AI-assisted hardening logs are not evidence of
independent review. The review and merge policy is in
[CONTRIBUTING.md](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CONTRIBUTING.md#review-and-merge-policy).

Rulesets, branch protection and pull request approvals are repository settings
that can change at any time, so an
operator who needs an independently reviewed revision must inspect the live
state when selecting the commit and retain the output with the deployment
evidence:

```bash
# Rules currently enforced on main; an empty list means nothing is enforced
gh api repos/aisecnomad/Nexus-ShadowScan/rules/branches/main
# The ruleset itself, including its enforcement state
gh api repos/aisecnomad/Nexus-ShadowScan/rulesets/23913372 --jq '{name, enforcement, rules: [.rules[].type]}'
# Classic branch protection; HTTP 404 means none is configured
gh api repos/aisecnomad/Nexus-ShadowScan/branches/main/protection
# Who authored, reviewed and merged the pull request that introduced a change
gh pr view <number> --repo aisecnomad/Nexus-ShadowScan --json author,mergedBy,reviews
```

The offline rules helper can prepare a reviewed PUT body from a fresh full
ruleset response. Use an administrator identity able to see `bypass_actors`;
GitHub can omit that field for identities without ruleset write access. Read
the default branch first and confirm it is `main`:

```bash
gh api repos/aisecnomad/Nexus-ShadowScan --jq .default_branch
gh api repos/aisecnomad/Nexus-ShadowScan/rulesets/23913372 > /secure/main-rules-before.json
python -m tools.release.rules prepare --input /secure/main-rules-before.json \
  --output /secure/main-rules-update.json --repository aisecnomad/Nexus-ShadowScan \
  --default-branch main
# Review the generated body before this administrator operation.
gh api --method PUT repos/aisecnomad/Nexus-ShadowScan/rulesets/23913372 \
  --input /secure/main-rules-update.json
gh api repos/aisecnomad/Nexus-ShadowScan/rulesets/23913372 > /secure/main-rules-after.json
python -m tools.release.rules verify --input /secure/main-rules-after.json \
  --output /secure/merge-rule-verification.json --repository aisecnomad/Nexus-ShadowScan \
  --default-branch main
```

Preparation activates the same ruleset and tightens it to the versioned minimum
policy: all four required checks are bound to the GitHub Actions app, final-push
approval and review-thread resolution are required, deletion is blocked and
CodeQL errors remain blocking. It retains additional checks and stronger rules,
pins an unbound required check and refuses a conflicting nonempty app binding.
It also refuses missing independent approval or stale-review dismissal,
ambiguous branch scopes, nonempty or unavailable bypass lists and malformed
settings. Generate the body from current settings rather than from an older
snapshot, so that later administrator changes are not overwritten, and compare
it with the [versioned merge policy](operations/merge-policy.md). The verifier
checks a supplied settings snapshot against the same minimum policy as the
governance checker. The release workflow obtains its snapshot
directly from GitHub; an offline receipt cannot authenticate its own API origin,
establish historical enforcement or prove an actual human approved the final PR.

The [two-ruleset payload helper](https://github.com/aisecnomad/Nexus-ShadowScan/tree/main/tools/governance)
additionally prepares `Protect main` and `Require CI and CodeQL` together,
removing bypass actors from both. The observed snapshots and proposed PUT
bodies are in [.github/rulesets](https://github.com/aisecnomad/Nexus-ShadowScan/tree/main/.github/rulesets).
The committed observed snapshots capture the 2026-10-10 readback: active
rulesets that still list four `always` bypass actors. Refresh
those observations and regenerate the bodies before applying them; the files
are preparation, not evidence of active enforcement. After administrator PUTs,
compare each fresh full API response against its exact approved body:

```bash
python -m tools.governance.rulesets plan --ruleset-id 23892853 \
  --input /secure/protect-main-before.json --output /secure/protect-main-update.json
python -m tools.governance.rulesets plan --ruleset-id 23913372 \
  --input /secure/main-rules-before.json --output /secure/main-rules-update.json
# Apply each reviewed body to its matching ruleset through an administrator.
python -m tools.governance.rulesets verify --ruleset-id 23892853 \
  --input /secure/protect-main-after.json --expected /secure/protect-main-update.json
python -m tools.governance.rulesets verify --ruleset-id 23913372 \
  --input /secure/main-rules-after.json --expected /secure/main-rules-update.json
```

An approving review counts only when it comes from a person with write access,
other than the author, and covers the final revision of the pull request. A
successful workflow run or Copilot review does not supply that approval. A
single maintainer cannot approve their own PR: recruit a second eligible human
reviewer rather than weakening the rules to self-merge. Recheck the live ruleset
and pull request status at release time.

The CI workflow installs hash-locked runtime, build and core/development
dependency sets and validates signatures, lint, typing, dependency advisories
(including the documentation lock), tests, wheel creation, installed-wheel
validation outside the source checkout and offline SARIF output. The Linux
Python 3.11 job traces coverage and enforces a minimum of 80% overall and 75%
for each module under `shadowscan/connectors/`, both counting statements and
branches, so a well-tested engine cannot conceal an untested provider; the
other jobs run the same tests untraced. Coverage proves execution of code paths in tests; it does not prove
provider compatibility or complete tenant inventory. The aggregate `CI gate`
requires every Linux and macOS matrix job, documentation and container security to succeed; it also
requires DCO on every pull-request commit, including merge commits that can
introduce authored conflict resolutions. It fails if a required prerequisite fails, is
cancelled or is unexpectedly skipped. Verify that the live ruleset requires
`CI gate` before treating the full matrix as an enforced merge gate. The dedicated
container job builds one Docker image and checks its non-root UID, signature assets
and network-isolated scan with a read-only root filesystem and resource limits.
It also requires the expat that the image's Python uses to parse every XML file
read from a repository to be 2.8.5 or newer, and the build fails if any file
keeps a setuid or setgid bit.
It inventories that exact local image with a CycloneDX SBOM and blocks HIGH or
CRITICAL OS and Python vulnerabilities, including unfixed findings, and lists each
blocking finding in the job log. It records
the image ID, source revision, pinned scanner and fresh vulnerability database
identities; scanner errors also block the gate.
Focused regressions cover the review findings, private-address enforcement,
public-key verification, plugin policy, artifact permissions and replay integrity.
Dependabot checks Python, GitHub Actions and Docker base-image dependencies weekly.

Automated and mocked provider-contract checks do not validate a tenant's actual
permissions, enabled services, data retention or export trust chain. Before an
operational rollout, run a read-only canary in each target tenant, inspect complete
coverage and account identity, verify expected known resources, and compare live
results with the retained export. These environment-specific checks require
access to those tenants and are not performed by offline CI.

The [synthetic evaluation](evaluation.md) guards against known classification
regressions. It does not measure field precision, recall or the calibration of
the heuristic confidence score. Before turning on `--fail-on` for an estate,
label a representative held-out set from that estate, include inactive configs,
commented/string-only source, disabled integrations and genuinely executing
agents, and review errors by connector and severity. For code-filesystem cases,
run the acceptance command with a separately reviewed, SHA-256-frozen policy:

```bash
python -m tools.evaluation.accept \
  --corpus /restricted/holdout.json \
  --policy /restricted/acceptance-policy.json \
  --annotations /restricted/holdout-annotations.json \
  --output /restricted/acceptance-result.json
```

The gate rejects synthetic/public samples and requires a frozen, SHA-256-bound
two-reviewer ledger plus predeclared sample floors and Wilson lower bounds per
family. Both acceptance paths reject repeated nonblank source contents or pinned
locations across holdout cases, including renamed and partially overlapping
multi-file samples. Repeated files inside one case are one sampling unit; blank
package scaffolding alone does not duplicate an otherwise distinct case, but
repeated all-blank cases are rejected. Previously evaluated source exclusion
remains strict for every file. Ledger declarations do not authenticate reviewer independence or prove
tenant completeness. Set a documented acceptable false-alert
and miss rate for each high-impact workflow; keep human triage while those
acceptance metrics are measured.

## Rollout acceptance

Before broad deployment, retain evidence for each intended connector instance.
The [canary proof packet](evaluation.md#read-only-tenant-canary-procedure) lists
the concrete status, denominator, control and reviewer artifacts:

1. Run a read-only canary with the actual audit identity. Record the expected
   tenant/account, regions and collection scope, then verify known agents and
   at least one known permission/configuration signal appear.
2. Verify denied access, malformed exports and partially invalid selections
   cannot pass the gate. Require `summary.complete=true` and inspect all connector
   statistics for successful collection; do not infer coverage from finding
   count or an empty report alone.
3. Check sanitized artifacts with synthetic credentials and enforce private
   file/directory modes. Keep configuration, state and outputs outside scanned
   repositories and restrict access to retained reports. Regenerate retained
   reports after an upgrade that withholds more, such as the
   [2026-09-28 redaction changes](history/production-change-history.md#completeness-report-and-credential-changes).
4. Replay each exported instance using its manifest filename, checking account,
   resource identity and detection consistency. Sanitized exports are not
   lossless raw API backups; credential findings may differ after redaction.
5. Run a representative large scan in a resource-limited disposable worker.
   Set a job deadline, monitor incomplete/failed runs and provider throttling,
   and document how to restore access or rerun after a partial collection.
6. Pin the reviewed scanner commit, wheel/image digest and approved dependency lock for rollout.
   Establish a fresh comparison baseline, retain the prior pinned version for
   rollback, and keep rollback reports separate from the new identity schema.
7. Measure precision and recall on a held-out, representative set of your own
   code and tenant records. Record the labeled corpus, per-connector confusion
   matrix, severity thresholds, reviewer decisions and accepted failure budget
   before treating findings as an automated policy decision.

These checks require operator-specific tenant access and operational decisions.
Until completed, describe deployment status as pending tenant and container acceptance.
