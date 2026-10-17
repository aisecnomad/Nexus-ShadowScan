# Contributing to ShadowScan

Thank you for your interest in making ShadowScan better. This guide covers
everything from setting up your environment to getting a PR merged.

## Code of conduct

Participation is governed by the [Code of conduct](CODE_OF_CONDUCT.md), including
its reporting and enforcement process. For usage questions, start with the
[Support guide](SUPPORT.md). Report vulnerabilities through the
[security policy](SECURITY.md#reporting), never through a public issue.

## Choose a contribution

- **Documentation:** fix a confusing step, add a synthetic example, or improve
  an explanation. No live tenant or cloud credentials are needed. Use the
  [documentation form](https://github.com/aisecnomad/Nexus-ShadowScan/issues/new?template=documentation.yml)
  or submit a focused pull request.
- **Detection quality:** provide a minimal positive or negative fixture with the
  expected outcome and why it is correct. A dependency name alone does not prove
  an agent is running. File it with the
  [detection quality report form](https://github.com/aisecnomad/Nexus-ShadowScan/issues/new?template=detection_report.yml);
  accepted reports become labeled regression cases under `tools/evaluation/`.
- **Bugs:** use the [bug report form](https://github.com/aisecnomad/Nexus-ShadowScan/issues/new?template=bug_report.yml)
  and include the full scanner commit, command, expected result and a sanitized
  reproducer. Search existing issues first; add evidence to an existing report
  where possible.
- **Connectors or architecture:** open a proposal before implementing a large
  change so maintainers can agree on scope, permissions and offline fixtures.
- **Review:** explain what you inspected and verified, including limits. Review
  from someone who did not author the change is especially valuable.

Browse [open issues](https://github.com/aisecnomad/Nexus-ShadowScan/issues) or propose
a small improvement if no suitable issue exists. You can ask for scope guidance
on the issue before starting; there is no expectation to build a large feature
as your first contribution.

## Getting started

Use Python 3.11, 3.12, 3.13, or 3.14 and Git on a POSIX system. Linux and macOS are
CI-validated development and test targets; Linux x86_64 is the only validated
deployment target for the production runtime lock. On Windows use WSL,
because the scanner's confined file reader needs `O_NOFOLLOW`/`dir_fd` and the
Makefile needs `/bin/bash`, `mktemp` under `$TMPDIR` (default `/tmp`) and the
POSIX `venv/bin` layout. Linux and macOS CI install the hash-locked runtime,
cloud and development toolchain. Fork the repository on GitHub if you need a
branch you can push; clone your fork in that case. In a local checkout:

```bash
git clone https://github.com/aisecnomad/Nexus-ShadowScan.git
cd Nexus-ShadowScan
python -m venv .venv
source .venv/bin/activate
git switch -c fix/short-description
make install                         # hash-locked dev + cloud + docs environment
pre-commit install                   # recommended local hooks
```

Cloud SDKs are optional for users, but the Linux test suite is gated with the
hash-locked runtime set that includes them. Offline fixtures cover the cloud
connectors; do not commit live tenant exports.

Run `make help` for a quick reference of all development commands.

## Find your way around

| Path | What lives there |
|---|---|
| [`shadowscan/`](shadowscan/) | The scanner package: CLI (`cli/`), engine, finding model, risk and autonomy scoring, inventory reconciliation, reporters and redaction. [docs/architecture.md](docs/architecture.md#package-layout) describes each module's responsibility. |
| [`shadowscan/connectors/`](shadowscan/connectors/) | One subpackage per discovery surface (`code`, `identity`, `gateway`, `lowcode`, `saas`, `cloud`, `endpoint`, `network`, `runtime`); each connector implements `collect()` and `analyze()`. |
| [`shadowscan/signatures/data/`](shadowscan/signatures/data/), [`shadowscan/mappings/data/`](shadowscan/mappings/data/) | YAML signature packs and the threat and control mapping catalogs. |
| [`tests/`](tests/) | The pytest suite. Unit tests sit in [`tests/unit/`](tests/unit/), named after the module they exercise; offline, sanitized fixtures sit under [`tests/fixtures/`](tests/fixtures/); `tests/test_repository_policy.py` and `tests/test_repository_consistency.py` are the `make policy` gates. Other top-level `tests/test_*.py` modules test repository tooling: release, governance, evaluation, canaries and benchmark entry points. Find a module's tests with `git grep -l shadowscan.connectors.identity.okta tests`. |
| [`docs/`](docs/) | The MkDocs site (`mkdocs.yml` holds the navigation): getting-started guides, connector guides under [`docs/connectors/`](docs/connectors/), concepts, operations runbooks, ADRs and the API reference. |
| [`examples/`](examples/) | The offline demo configuration (`shadowscan.offline.yaml`), sample inventories, canary and eBPF fixtures, and consumer CI examples (GitHub Actions workflows and Kubernetes manifests). |
| [`tools/`](tools/README.md) | Repository tooling that never ships: the secrets and per-connector coverage gates, the regression corpora, benchmark harnesses, the acceptance verifier, release, governance and container checks, and the AI review gate internals. |
| [`benchmarks/`](benchmarks/README.md) | Benchmark corpora and recorded results, with each benchmark's harness and what it can and cannot show. |
| [`archive/reviews/`](archive/reviews/README.md) | Dated, AI-assisted review records; per [AGENTS.md](AGENTS.md), not independent human review. |
| [`.github/`](.github/) | Workflows ([inventory](.github/workflows/README.md)), issue forms, the pull request template, the label taxonomy (`labels.yml`), Dependabot configuration and the committed `main` ruleset. |

Files at the repository root stay there because the build, the container image,
Dependabot and the tests read them from there:

| File | Purpose |
|---|---|
| `pyproject.toml` | Package metadata, extras, and the ruff, mypy, pytest and coverage settings |
| `Makefile` | Every development command; `make help` lists them by section |
| `requirements.lock` | Hash-locked runtime and cloud SDK set for deployments, CI and the image |
| `requirements-build.lock` | Hash-locked build backend for `--no-build-isolation` builds |
| `requirements-ci.lock` | Hash-locked development and test toolchain (CPython 3.11 to 3.14) |
| `requirements-ci-constraints.txt` | Reviewed inputs that `requirements-ci.lock` is generated from; never installed directly |
| `requirements-docs.lock` | Hash-locked MkDocs toolchain for `make docs` and the Docs workflow |
| `requirements-fuzz.lock` | Hash-locked Atheris fuzzing engine for `make fuzz` and the Fuzz workflow (Linux x86_64) |
| `mkdocs.yml` | Documentation site configuration and navigation |
| `Dockerfile`, `.dockerignore` | The worker image and its build-context allow-list |
| `agent-card.yaml` | Sample Agent Capability Card used by the offline demo, the quick start and the image |
| `CHANGELOG.md`, `docs/engineering-log.md`, `RELEASE_NOTES.md` | One line per change, the detailed engineering log, and the operator summary of what changes on upgrade |
| `AGENTS.md` | Rules for coding agents working in this repository |
| `CITATION.cff`, `NOTICE`, `LICENSE`, `CODEOWNERS` | Citation metadata, attribution, licence and review ownership |

## Run one test

After the development setup above, run one offline test from the repository root:

```bash
python -m pytest -q tests/unit/test_signatures.py::test_all_signatures_load_and_validate
```

This validates that the bundled signatures load successfully. It needs no cloud
credentials. When iterating on a change, replace the path and test name with the
relevant test; a single-test pass does not establish full-suite coverage.

Unit tests live in `tests/unit/`, in files named after the module or feature
they exercise (`test_http_security.py`, `test_gitlab_connector.py`,
`test_csv_injection.py`). Add a regression test to the file for the code it
covers rather than a new file per change. A test that replaces a redaction
rule must patch it through `shadowscan.utils.redaction`, which rebinds the
name in every `redaction_*` module; patching a `redaction_*` module directly
changes only that module.

Existing Make targets provide the next steps:

```bash
make check-fast      # lint, format, types, validators, OCSF, complexity, secrets and policy; no tests
make test-fast       # full test suite without coverage, stop at first failure
make test            # full suite with line and branch coverage and the overall floor
make coverage-gate   # connector coverage; run after make test
make check           # all local quality gates
```

On CI runners the full suite takes about 15 minutes untraced and about 20 with
coverage; `make check-fast` takes a minute or two. `make audit`, and therefore
`make check`, needs network access for pip-audit.

For detailed testing guidance, environment setup troubleshooting, and advanced patterns,
see [Testing Guide](docs/testing.md).

To run the connector coverage check directly after the full coverage test run,
export a report and pass its filename explicitly:

```bash
python -m coverage json -o /tmp/shadowscan-coverage.json
python -m tools.coverage_gate /tmp/shadowscan-coverage.json
```

The gate requires the JSON report argument and branch data; running one test is
not enough to measure every connector. See [quality gates](#quality-gates) for
CI requirements, and the [testing guide](docs/testing.md#the-full-suite) for the
isolation every test runs under.

## Trust model

The operator workstation or CI runner, the scan configuration, and installed
Python packages are trusted. Remote API responses, scanned repositories, and
offline exports are untrusted. Third-party connectors are not a sandbox: an
approved plugin runs with scanner privileges.

## Quality gates

Run `make check` for the main local quality gates. CI is the authoritative
merge check and additionally builds and validates the installed wheel, exercises
SARIF output and the container, and runs CodeQL. The CI workflow defines the
exact supported Python matrix and dependency pins.

| Gate | Command | Requirement |
|------|---------|-------------|
| Lint | `ruff check shadowscan tests tools benchmarks` | No errors |
| Format | `ruff format --check shadowscan tests tools benchmarks` | No changes |
| Types | `mypy shadowscan tools benchmarks` | No errors |
| Tests | `pytest --cov --cov-fail-under=80` | ≥ 80% aggregate, statements and branches |
| Connectors | `make coverage-gate` (after tests) | ≥ 75% for every module under `shadowscan/connectors/`, statements and branches |
| Signatures | `python -m shadowscan.signatures.validate` | All valid |
| Mappings | `python -m shadowscan.mappings.validate` | All valid |
| OCSF schema | `python -m tools.ocsf_schema --check` | The vendored OCSF requirements match the version the reporter emits |
| Complexity | `python -m tools.complexity_gate` | No function above ruff's `C901` limit of 15 and no `shadowscan` module above 2,000 lines grows past `tools/complexity_baseline.json`, and the baseline allows no more than the code has |
| Secrets | `make secrets` | Every tracked file is scanned; only exact reviewed synthetic-value approvals are accepted |
| Audit | `make audit` | No known vulnerabilities in the environment or any hash lock |
| Repository policy | `make policy` | Action pins, permissions, links, anchors, Makefile and hook parity with CI |
| Docs | `make docs` | `mkdocs build --strict` with no warnings |
| Evaluation | `make evaluate` | All bundled corpora pass |

CI measures coverage on one Linux job (Python 3.11) and runs the same full
suite untraced on the others; `pyproject.toml` enables branch coverage.

Ruff enforces a 110-column line length outside `tests/`,
`tools/benchmark/*_cases.py` and `benchmarks/*/corpus.py`, flags loop
variables captured by closures (B023), flags a broad `except` that does not
re-raise (BLE), and rejects `noqa` directives that suppress nothing (RUF100)
or name no codes (PGH004). Suppress an intentional broad `except` with
`# noqa: BLE001 - <reason>`; a repository test requires the reason. Mypy requires annotated definitions
(`disallow_untyped_defs`) and reports unused `type: ignore` comments.
`pyproject.toml` holds the complete rule sets.

`make complexity` runs `python -m tools.complexity_gate`, which holds two measures to
`tools/complexity_baseline.json`: every function above ruff's `C901` limit of 15 in
`shadowscan/`, `tools/` and `benchmarks/`, and every `shadowscan` module above 2,000 lines.
Each entry is keyed by file and qualified name (`path::Class.method`, a nested function as
`outer.<locals>.inner`), so a function never inherits another's room. The gate keeps the
functions and modules that are already too large from growing and stops a new one from
joining them. When it fails because your change made a function more complex or a module
longer, split it; do not raise the number. When it fails because you improved one, run
`python -m tools.complexity_gate --update` and commit the lower baseline, so the room cannot
be spent again. A rise that is unavoidable is recorded with
`python -m tools.complexity_gate --rebaseline` and explained in the pull request.
[Testing](docs/testing.md#function-and-module-size) has the details.

The same gates as individual commands:

```bash
make install
python -m shadowscan.signatures.validate
python -m shadowscan.mappings.validate
python -m tools.ocsf_schema --check
python -m tools.complexity_gate
make secrets
ruff check shadowscan tests tools benchmarks
ruff format --check shadowscan tests tools benchmarks
mypy shadowscan tools benchmarks
make audit
python -m pytest -q --cov=shadowscan --cov-fail-under=80
make coverage-gate
make evaluate
```

The cloud SDKs (`boto3`, `google-auth`, `azure-identity`, `oci`) are optional
extras for users, but the test suite is gated with them installed. `make
install` installs the hash-locked `requirements.lock`, which contains every
cloud SDK, together with the CI and build locks, as CI does. The
release-evidence tests record the version of the `build` frontend, which only
`requirements-build.lock` provides. Offline fixtures cover the
cloud connectors; do not commit live tenant exports.

Dependabot updates the version ranges in `pyproject.toml` and the reviewed
inputs in `requirements-ci-constraints.txt`, not the hash locks. Refresh the locks by hand as described in
[docs/production.md](docs/production.md); the weekly `audit.yml` workflow
re-audits every lock between commits.

Do not commit private adjudicated evaluation corpora.

The secret-pattern gate runs in CI, in `make check` and in the pre-commit hook.
It names the file, line and credential family of each match, never the value,
and fails on a file it cannot read. Tests, signature packs and evaluation
corpora are checked too. `tools/secret_allowlist.json` contains only the exact
repository path, credential family, SHA-256 of the matched text and review
reason for approved synthetic fixtures or documentation placeholders. There
are no directory exemptions or automatic placeholder-word exemptions.

Review each new credential-shaped example before adding its digest to the
manifest. Never approve an actual service credential. Changing a placeholder
in documentation also requires an explicit approval. Private-key detections
match a BEGIN marker, so their entries must additionally bind the SHA-256 of
the whole file's bytes; a marker approval cannot cover a replacement key body.
The script validates every entry, including during partial pre-commit runs,
and fails on malformed, duplicate or stale approvals. Remove entries when their
fixture is removed. The bounded pattern check does not establish that the
repository contains no secrets.

## Pull requests

1. Make one focused change on your branch. For a documentation-only change,
   check the affected links and run `mkdocs build --strict` if the site changes.
2. Run the checks relevant to your change, then the full gates before requesting
   review for code changes. Explain any check you could not run and why.
3. Push your branch to your fork and open a pull request against `main`. Link the
   related issue with `Fixes #123` only when the PR resolves it completely.
4. Explain the problem, the resulting behavior and the validation performed.
   Draft PRs are welcome when you want feedback before the implementation is done.
5. Address review feedback and rerun affected checks after updating the branch.
   If the PR received independent approval, request renewed review after
   changing the approved commit. The requirements below apply to the final commit.

- Target `main`. Do not push reviewed security changes directly.
- Keep findings fail-closed: a malformed export, a denied API, an expired
  deadline or any limit whose remainder the scanner cannot count must mark the
  scan incomplete (exit 3) rather than look empty. A gap it *can* count --
  one unreadable entry, one file over a size cap -- goes through
  `ctx.coverage_gap()`, which charges it to the budget and reports it either
  way; see `shadowscan/coverage.py` for which is which.
- Do not log raw credentials, JWTs, or unsanitized connector configuration.
- Pin GitHub Actions by full commit SHA. Do not leave `persist-credentials`
  enabled on checkouts that do not need to push.
- Add a detailed entry under Unreleased in `docs/engineering-log.md`, name it in
  a line under Unreleased in `CHANGELOG.md`, and update `docs/production.md`
  when a change affects rollout, finding identity, or credential policy.
- Include regression tests for bug fixes.
- Use the PR template checklist; it covers the main gates. `make check` runs
  every local gate; CI also builds the documentation, audits each lock file and
  validates the wheel and container (see [quality gates](#quality-gates)).

Repository policy is tested. When you touch `.github/`, a top-level document or
a docs page, run `make policy`: `tests/test_repository_policy.py` checks action
pins, permissions, manual publishing boundaries and issue-form structure, and
`tests/test_repository_consistency.py` checks that Markdown links and heading
anchors resolve, that the Makefile, pre-commit hooks and docs lock match CI,
that every CodeQL step runs the same release, and that documented counts match
the shipped code.

## Writing a connector

See [docs/architecture.md](docs/architecture.md) for the full connector
contract. In brief:

1. Create a module under `shadowscan/connectors/<surface>/`.
2. Implement `collect()` (live API) and `analyze()` (offline records → findings).
3. Register in `shadowscan/connectors/__init__.py`.
4. Add offline test fixtures under `tests/fixtures/`.
5. Achieve ≥ 75% coverage of statements and branches (the per-connector floor);
   [iterate on one connector](docs/testing.md#iterate-on-one-connector) shows how
   to measure one module while you work.
6. Describe each key in `config_keys` and run `make connector-reference`, which
   regenerates [docs/connectors/reference.md](docs/connectors/reference.md); a
   test fails when it is stale. Document required API scopes and the offline
   export format in the connector guide under `docs/connectors/`, and add the
   connector's summary row to [docs/connectors.md](docs/connectors.md). Run
   `make readme-matrix` too: the README detection matrix lists the identity,
   gateway, low-code, SaaS and network connectors, and a test fails when it is
   stale. Run `make readme-visuals` as well: the connector diagram under
   `docs/assets/` names every built-in connector, and a test fails when it is
   stale.

`BaseConnector.load_offline` already reads `input` exports. Declare an
[engine hook](docs/architecture.md#engine-hooks) only when the engine must
treat the connector differently; the engine never special-cases a name.

## Writing signatures

Signatures are YAML. Add a pack directory with `--signatures` or the
`signatures:` config key. After changes:

```bash
python -m shadowscan.signatures.validate
make evaluate
make readme-matrix   # the README detection matrix is generated from the built-in packs
```

See [docs/signatures.md](docs/signatures.md) for the schema and authoring guide.

## Changing threat and control mappings

Catalogs and rules live under `shadowscan/mappings/data/`. They are evidence
references and author mappings, never compliance determinations. After a
change:

```bash
python -m shadowscan.mappings.validate
make mapping-reference
```

Add a test with a finding the changed rule should match. See
[docs/concepts/mappings.md](docs/concepts/mappings.md) for the format, editions
and licensing limits.

## Review and merge policy

ShadowScan currently has a single maintainer. The maintainer reviews changes,
checks validation and is accountable for merges. CI and CodeQL must pass on the
current PR revision, conflicts must be resolved, and substantive review feedback
must be addressed. The `main` ruleset is configured to require one approving
review from someone with write access for every pull request, including routine
changes. An author cannot approve their own change: a maintainer-authored PR
requires a second eligible human reviewer. Stale approvals are dismissed after
a push; request a new approval for the final revision. That ruleset has been
enabled and disabled several times since 2026-09, so check the live rules
before relying on it. AI-assisted review is advisory and is never an
independent human approval.

Before merging, the maintainer checks:

- The PR targets `main`, is up to date, conflicts are resolved, and current CI
  and CodeQL checks pass, including the aggregate `CI gate` and the strict
  required checks `test (3.11)`, `test (3.12)` and `analyze`. CI also runs signature validation, lint, typing,
  dependency audit, coverage, detection evaluation, and package and smoke checks.
- The change respects the trust model, documents compatibility changes, and
  includes appropriate validation. An AI-assisted change must meet the same
  requirements as any other contribution.
- The approving reviewer has write access, is someone other than the author,
  and approved the final PR revision. The review record describes what was
  checked and any remaining limitation. A new push requires renewed approval.

The historical review status is documented in
[merge gate and review status](docs/production.md#merge-gate-and-review-status).
Do not read a merged pull request, green check, AI review or version number as
evidence that a second person examined the change. Repository settings are
separate from this policy: inspect the
[live rules](https://github.com/aisecnomad/Nexus-ShadowScan/rules) and PR checks
before merging. The versioned policy requires no bypass actors; the 2026-10-10
readback listed four `always` bypass actors on both `main` rulesets, so a
repository administrator can merge without the non-author approval until they
are removed. Every ruleset blocks nothing while disabled. Apply and
verify the [versioned merge policy](docs/operations/merge-policy.md) with repository
administration access. Do not disable checks or review rules to make a
merge possible, and recheck live enforcement before relying on it.

**Independent human review is required before any tagged release.** The
reviewer must not have authored or produced the change. A review is recorded as
a GitHub pull request approval from an account other than the author's. Inspect
the review author, state and `commit_id` with
`gh api repos/aisecnomad/Nexus-ShadowScan/pulls/<number>/reviews`, and compare that
commit to the current PR head. The ruleset on `main` is configured to require
one approving review from a reviewer with write access; its enforcement state
has changed several times since 2026-09 (the dated readbacks are under
[merge gate and review status](docs/production.md#merge-gate-and-review-status)),
so check the [live rules](https://github.com/aisecnomad/Nexus-ShadowScan/rules)
rather than this sentence. While the maintainer is the only account with write access, that rule
cannot be satisfied for the maintainer's own changes until a second eligible
reviewer receives write access and approves. Never manufacture an approval or
treat an AI reviewer as that person.

For deployment, pin the full reviewed commit SHA and retain its review and
acceptance evidence. A version tag does not replace that evidence.
Independent review of a release does not itself establish live tenant acceptance.
See [governance](GOVERNANCE.md) for release and decision responsibilities.

## Security reports

Follow the [security reporting instructions](SECURITY.md#reporting) to submit a
private report. Do not include credentials, private exports, or exploit details
in public issues.

## Developer Certificate of Origin

By contributing to this project, you certify that you have the right to submit
the work under the Apache-2.0 license and that you agree to the
[Developer Certificate of Origin](https://developercertificate.org/) (DCO).

You can sign off your commits with `git commit -s`, which adds a
`Signed-off-by` line. CI calls the reusable [`DCO` workflow](.github/workflows/dco.yml)
to check every commit in a pull request for a matching sign-off. Merge commits
also need sign-off because conflict resolutions can introduce new authored
content; use `git merge --signoff` when updating a branch by merging.
The `CI gate` check requires successful DCO, documentation, and every Python
matrix job, including the container smoke test. Whether that check is configured
to block merges follows the live repository rules (see
[review and merge policy](#review-and-merge-policy)).
Dependabot commits are authored by GitHub's Dependabot app and signed off by
GitHub as `support@github.com`; the workflow accepts exactly that pairing and
no other mismatched sign-off.

The `main` rulesets also require verified commit signatures
(`required_signatures`). A DCO `Signed-off-by` trailer is not a signature.
Either sign your commits (SSH or GPG) or expect the maintainer to
squash-merge, which produces a GitHub-signed commit.

## License

By contributing, you agree that your contributions will be licensed under the
Apache-2.0 license.
