# OpenSSF Best Practices evidence

The [OpenSSF Best Practices badge](https://www.bestpractices.dev/) is a self-certification. The maintainer signs in, answers a questionnaire about the project, and the site records the answers; it fills in some itself, but every answer stays the maintainer's. This page maps the 67 criteria of the **passing** level to what this repository shows, so that an application can cite files instead of memory.

**This repository claims no badge.** The README shows none and nothing in the repository records an application. This page is preparation, not an application and not a claim. It was written from the criteria as the site published them on 2026-10-17; they change, so read them again when you apply.

## What the statuses mean

| Status | Meaning |
|---|---|
| **Met** | The repository shows it. Cite the linked files in the answer. |
| **Confirm** | True of the repository today, but the answer also depends on something outside it that can change: a GitHub setting, the issue tracker, the date, or how you read the criterion. Check it on the day you apply. |
| **Attest** | Only the person answering can say it, because it is about their own knowledge. The links are context, not proof. |
| **N/A** | The criterion does not apply, for the reason given. |
| **Gap** | Not met today. The row says what would meet it. |

Of the 67 criteria (43 MUST, 10 SHOULD, 14 SUGGESTED): 50 Met, 11 Confirm, 2 Attest, 3 N/A, 1 Gap.
The Gap on a MUST criterion (`crypto_keylength`) has to be resolved, or answered with a reasoned reading of the criterion, before the passing level can be reached. An honest *Unmet* on a SHOULD or SUGGESTED criterion does not block it.

## Before you apply

1. Sign in at [bestpractices.dev](https://www.bestpractices.dev/) with the GitHub account that administers the repository and add the project from its repository URL.
2. Answer each criterion from the tables below. The site pre-fills some answers from public data; compare them with the tables.
3. For every **Confirm** row, check the current state that day. For every **Attest** row, answer for yourself; nothing in the repository can.
4. Do not answer Met for a criterion the evidence only partly supports. Say what is missing in the justification field; the form has one for that.

Passing the CI checks, the CodeQL analysis or the OpenSSF Scorecard is not independent human review, and neither is this badge. [Governance](../governance.md) and the [reviewer packet](reviewer-packet.md) say what review is still outstanding.

## Passing level, criterion by criterion

### Basics

#### Basic project website content

| Criterion | Level | Status | Evidence |
|---|---|---|---|
| `description_good` | MUST | **Met** | The [README](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/README.md) opens with what ShadowScan does and for whom, and [the documentation home](../index.md) repeats it. |
| `interact` | MUST | **Met** | Obtain: [README, Install](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/README.md#install). Feedback: [SUPPORT.md](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/SUPPORT.md) sends bug reports, detection reports and proposals to the issue forms. Contribute: [CONTRIBUTING.md](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CONTRIBUTING.md). |
| `contribution` | MUST | **Met** | [CONTRIBUTING.md, Pull requests](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CONTRIBUTING.md#pull-requests): one focused branch, a pull request against `main`, review, and the checks it must pass. |
| `contribution_requirements` | SHOULD | **Met** | [CONTRIBUTING.md, Quality gates](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CONTRIBUTING.md#quality-gates) lists each requirement with its command: lint, format, types, coverage floors, validators, the secret gate and the audit. [Developer Certificate of Origin](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CONTRIBUTING.md#developer-certificate-of-origin) adds the sign-off. |

#### FLOSS license

| Criterion | Level | Status | Evidence |
|---|---|---|---|
| `floss_license` | MUST | **Met** | Apache-2.0: [`LICENSE`](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/LICENSE) and `license = "Apache-2.0"` in [`pyproject.toml`](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/pyproject.toml). |
| `floss_license_osi` | SUGGESTED | **Met** | Apache-2.0 is approved by the Open Source Initiative. |
| `license_location` | MUST | **Met** | [`LICENSE`](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/LICENSE) and [`NOTICE`](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/NOTICE) at the top level of the repository. |

#### Documentation

| Criterion | Level | Status | Evidence |
|---|---|---|---|
| `documentation_basics` | MUST | **Met** | Install and first run: [installation guide](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/getting-started/install.md) and [quick start](../getting-started/quickstart.md). Secure use: [SECURITY.md, Trust boundary](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/SECURITY.md#trust-boundary), [Security](../security.md) and [Production deployment](../production.md). |
| `documentation_interface` | MUST | **Met** | Command line: [README, Command reference](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/docs/reference/cli.md). Python API: [API reference](../api/index.md), generated from the code with mkdocstrings. Connector configuration: [reference](../connectors/reference.md), generated by `make connector-reference` and tested to be current. |

#### Other

| Criterion | Level | Status | Evidence |
|---|---|---|---|
| `sites_https` | MUST | **Met** | The repository, its issues, the PyPI project and the Pages URL are all `https:` addresses ([project URLs](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/pyproject.toml)). |
| `discussion` | MUST | **Met** | GitHub issues and pull-request discussions are public, searchable, addressable by URL and open to anyone with a GitHub account; they need no proprietary client. |
| `english` | SHOULD | **Met** | Documentation, issue forms, commit messages and code comments are in English, and reports in English are accepted. |
| `maintained` | MUST | **Confirm** | The latest commit on `main` was made on 2026-10-16 (observed 2026-10-17), and Dependabot opens update pull requests weekly ([`.github/dependabot.yml`](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/.github/dependabot.yml)). The criterion asks that significant reports get a response; the two response rows below show whether they do. |

### Change Control

#### Public version-controlled source repository

| Criterion | Level | Status | Evidence |
|---|---|---|---|
| `repo_public` | MUST | **Met** | [`aisecnomad/Nexus-ShadowScan`](https://github.com/aisecnomad/Nexus-ShadowScan) is public on GitHub. |
| `repo_track` | MUST | **Met** | The git history records who changed what and when. |
| `repo_interim` | MUST | **Met** | Changes reach `main` through pull requests between releases, and [RELEASE_NOTES.md](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/RELEASE_NOTES.md) lists the ones not yet released under Unreleased. |
| `repo_distributed` | SUGGESTED | **Met** | The repository uses git, a distributed version control system. |

#### Unique version numbering

| Criterion | Level | Status | Evidence |
|---|---|---|---|
| `version_unique` | MUST | **Met** | Each release has its own version in [`pyproject.toml`](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/pyproject.toml). CI checks that `shadowscan/__init__.py` and `CITATION.cff` agree ([publishing a release](publishing.md#per-release), step 1). |
| `version_semver` | SUGGESTED | **Met** | Versions are `MAJOR.MINOR.PATCH` (0.1.2). The repository states no compatibility policy for them, so answer with the format only. |
| `version_tags` | SUGGESTED | **Met** | Annotated tags `v0.1.1` and `v0.1.2` exist (`git ls-remote --tags origin`, 2026-10-17). [Publishing a release](publishing.md#per-release), step 4, has the maintainer tag each reviewed release. |

#### Release notes

| Criterion | Level | Status | Evidence |
|---|---|---|---|
| `release_notes` | MUST | **Met** | [`RELEASE_NOTES.md`](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/RELEASE_NOTES.md) has one written section per release, and [`CHANGELOG.md`](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CHANGELOG.md) records the changes. Neither is a `git log`. |
| `release_notes_vulns` | MUST | **Confirm** | N/A is allowed when no release has fixed a publicly known vulnerability in ShadowScan itself that already had a CVE. Check the repository's [security advisories](https://github.com/aisecnomad/Nexus-ShadowScan/security/advisories) before choosing it. |

### Reporting

#### Bug-reporting process

| Criterion | Level | Status | Evidence |
|---|---|---|---|
| `report_process` | MUST | **Met** | [`SUPPORT.md`](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/SUPPORT.md) and the issue forms in [`.github/ISSUE_TEMPLATE`](https://github.com/aisecnomad/Nexus-ShadowScan/tree/main/.github/ISSUE_TEMPLATE): bug, detection report, connector request, documentation, feature request and usage question. |
| `report_tracker` | SHOULD | **Met** | GitHub issues ([tracker](https://github.com/aisecnomad/Nexus-ShadowScan/issues)). |
| `report_responses` | MUST | **Confirm** | The repository cannot show this. Count the bug reports opened between 2 and 12 months before you apply and check that most have a reply from the maintainer. |
| `enhancement_responses` | SHOULD | **Confirm** | As above for feature requests and connector requests. A reply of "no" counts. |
| `report_archive` | MUST | **Met** | GitHub keeps issues and every response public and searchable. |

#### Vulnerability report process

| Criterion | Level | Status | Evidence |
|---|---|---|---|
| `vulnerability_report_process` | MUST | **Met** | [SECURITY.md, Reporting](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/SECURITY.md#reporting) says what to report privately, what to include and how disclosure is coordinated. |
| `vulnerability_report_private` | MUST | **Confirm** | SECURITY.md and the issue chooser ([`.github/ISSUE_TEMPLATE/config.yml`](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/.github/ISSUE_TEMPLATE/config.yml)) send reporters to the [private advisory form](https://github.com/aisecnomad/Nexus-ShadowScan/security/advisories/new) over HTTPS. The link works only while private vulnerability reporting is enabled in the repository settings, so check that setting. |
| `vulnerability_report_response` | MUST | **Confirm** | The criterion counts what happened: an initial response within 14 days to every report of the last six months, or N/A if there were none. SECURITY.md promises no response time, which does not change the answer. |

### Quality

#### Working build system

| Criterion | Level | Status | Evidence |
|---|---|---|---|
| `build` | MUST | **Met** | `make build` runs `python -m build` with the backend pinned in [`requirements-build.lock`](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/requirements-build.lock); [release.yml](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/.github/workflows/release.yml) builds and attests the same way. |
| `build_common_tools` | SUGGESTED | **Met** | setuptools through `python -m build`, pip and make. |
| `build_floss_tools` | SHOULD | **Met** | Every build tool is free software. |

#### Automated test suite

| Criterion | Level | Status | Evidence |
|---|---|---|---|
| `test` | MUST | **Met** | The pytest suite under [`tests/`](https://github.com/aisecnomad/Nexus-ShadowScan/tree/main/tests) is released with the code under Apache-2.0. [CONTRIBUTING.md, Quality gates](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CONTRIBUTING.md#quality-gates) and [Testing](../testing.md) say how to run it, and [ci.yml](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/.github/workflows/ci.yml) runs it. |
| `test_invocation` | SHOULD | **Met** | `python -m pytest`, or `make test` for the whole gate. |
| `test_most` | SUGGESTED | **Met** | CI requires at least 80% aggregate coverage counting branches and at least 75% for every connector module ([`tools/coverage_gate.py`](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/tools/coverage_gate.py)). Redaction and source lexing also have property tests and [fuzz targets](fuzzing.md). |
| `test_continuous_integration` | SUGGESTED | **Met** | [ci.yml](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/.github/workflows/ci.yml) runs on every pull request, every push to `main` and weekly. |

#### New functionality testing

| Criterion | Level | Status | Evidence |
|---|---|---|---|
| `test_policy` | MUST | **Met** | [CONTRIBUTING.md, Pull requests](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CONTRIBUTING.md#pull-requests) and [`AGENTS.md`](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/AGENTS.md) require regression tests for fixes, offline fixtures for connectors, evaluation cases for signatures and tests for mapping rules. The [pull request template](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/.github/PULL_REQUEST_TEMPLATE.md) turns them into a checklist. |
| `tests_are_added` | MUST | **Confirm** | Cite two or three recent merged pull requests that add tests with a feature or fix. The template and the coverage gates make that the default, but the evidence is in the pull requests, not in this repository's files. |
| `tests_documented_added` | SUGGESTED | **Met** | The same CONTRIBUTING.md and pull request template sections are the instructions for change proposals. |

#### Warning flags

| Criterion | Level | Status | Evidence |
|---|---|---|---|
| `warnings` | MUST | **Met** | ruff (rule sets E, F, W, I, B, UP, SIM, C4, BLE and RUF100) and mypy (`disallow_untyped_defs`, `check_untyped_defs`, `warn_unreachable`, `warn_return_any`, `warn_unused_ignores`), configured in [`pyproject.toml`](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/pyproject.toml) and run in CI and in pre-commit. |
| `warnings_fixed` | MUST | **Met** | CI fails on any ruff or mypy finding. A broad `except` or a `noqa` needs a written reason that a repository test checks, and a suppression that suppresses nothing is itself an error. |
| `warnings_strict` | SUGGESTED | **Met** | The settings above are stricter than the tools' defaults. They are not `mypy --strict`, and ruff runs no security rule set; CodeQL covers that. |

### Security

#### Secure development knowledge

| Criterion | Level | Status | Evidence |
|---|---|---|---|
| `know_secure_design` | MUST | **Attest** | Only a primary developer can say this. For context: the [threat model](../security/threat-model.md), the hard rules in [`AGENTS.md`](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/AGENTS.md) (fail closed, no raw credentials, no weakened HTTPS or origin controls) and the [ADRs](../adrs/index.md). |
| `know_common_errors` | MUST | **Attest** | Only a primary developer can say this. For context: the threat model's sections on untrusted input, egress, output disclosure and supply chain, and the CodeQL results. |

#### Use basic good cryptographic practices

| Criterion | Level | Status | Evidence |
|---|---|---|---|
| `crypto_published` | MUST | **Met** | The package uses SHA-256 and HMAC-SHA-256 from the standard library, JWT signature algorithms RS256, PS256, ES256 and EdDSA through PyJWT with `cryptography`, and TLS through `requests`, `urllib3` and OpenSSL. SHA-1 appears once; see `crypto_weaknesses`. |
| `crypto_call` | SHOULD | **Met** | It calls `hashlib`, `hmac`, `secrets`, PyJWT, `cryptography` and OpenSSL and implements no primitive of its own. |
| `crypto_floss` | MUST | **Met** | Every library above is free software. |
| `crypto_keylength` | MUST | **Gap** | ShadowScan's own keys are 256 bits: `secrets.token_bytes(32)`, or an operator key that [`shadowscan/utils/credential_identity.py`](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/shadowscan/utils/credential_identity.py) rejects below 32 bytes. It generates no asymmetric keys. When it verifies a JWT against an issuer's JWKS it uses the issuer's key and sets no minimum RSA modulus size of its own. Either add one, or answer with that explanation if you read the criterion as covering keys the software generates. |
| `crypto_working` | MUST | **Met** | The package uses no MD4, MD5, DES, RC4 or ECB mode. Its one SHA-1 use is described under `crypto_weaknesses`. |
| `crypto_weaknesses` | SHOULD | **Confirm** | [`shadowscan/connectors/code/remote.py`](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/shadowscan/connectors/code/remote.py) recomputes a git object id with SHA-1 when a remote repository names objects that way (`usedforsecurity=False`). That is git's own format, not a ShadowScan mechanism; everything ShadowScan keys or identifies itself uses SHA-256. This is a SHOULD, so your reading of it decides the answer. |
| `crypto_pfs` | SHOULD | **N/A** | ShadowScan implements no key-agreement protocol. OpenSSL negotiates TLS to providers through `requests` and `urllib3`. |
| `crypto_password_storage` | MUST | **N/A** | ShadowScan stores no passwords to authenticate external users. |
| `crypto_random` | MUST | **Met** | Keys and nonces come from `secrets` (`token_bytes`, `token_hex`). `random.uniform` appears only to add jitter to HTTP retry delays in [`shadowscan/utils/http.py`](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/shadowscan/utils/http.py). |

#### Secured delivery against man-in-the-middle (MITM) attacks

| Criterion | Level | Status | Evidence |
|---|---|---|---|
| `delivery_mitm` | MUST | **Met** | Source, issues and PyPI are served over HTTPS. Releases also carry Sigstore-signed build-provenance and SBOM attestations that `gh attestation verify` checks ([publishing a release](publishing.md#per-release), steps 6 and 7). |
| `delivery_unsigned` | MUST | **Met** | No step fetches a hash over HTTP and trusts it unsigned. `SHA256SUMS` comes from the attested release candidate and is compared with the digests of files downloaded from PyPI over HTTPS, and dependencies install with `--require-hashes` from the hash locks. |

#### Publicly known vulnerabilities fixed

| Criterion | Level | Status | Evidence |
|---|---|---|---|
| `vulnerabilities_fixed_60_days` | MUST | **Confirm** | The evidence is automation: pip-audit in CI and in the weekly [audit.yml](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/.github/workflows/audit.yml), Dependabot and CodeQL. Run `make audit` and read the repository's [security alerts](https://github.com/aisecnomad/Nexus-ShadowScan/security) the day you apply. The criterion says patched and released: SECURITY.md has fixes land on `main` with no backport, so a fix that sits unreleased on `main` while a medium or higher vulnerability stays public past 60 days may not count. Releasing is the maintainer's action. |
| `vulnerabilities_critical_fixed` | SHOULD | **Confirm** | Same sources as above. SECURITY.md says a confirmed fix should include a regression test. |

#### Other security issues

| Criterion | Level | Status | Evidence |
|---|---|---|---|
| `no_leaked_credentials` | MUST | **Met** | [`tools/check_secrets.py`](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/tools/check_secrets.py) scans every tracked file in CI, in pre-commit and under `make secrets`. The only credential-shaped values it accepts are synthetic ones, each bound by SHA-256 in [`tools/secret_allowlist.json`](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/tools/secret_allowlist.json). The fuzz targets assemble theirs at run time, so none is stored. The scan is bounded and proves nothing about what it does not match. |

### Analysis

#### Static code analysis

| Criterion | Level | Status | Evidence |
|---|---|---|---|
| `static_analysis` | MUST | **Met** | CodeQL for Python runs on every pull request, every push to `main` and weekly ([codeql.yml](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/.github/workflows/codeql.yml)), and the release-evidence workflow takes a successful CodeQL run of the exact commit as an input. ruff and mypy run in CI too. |
| `static_analysis_common_vulnerabilities` | SUGGESTED | **Met** | CodeQL's security queries for Python. |
| `static_analysis_fixed` | MUST | **Confirm** | The versioned `main` ruleset has a code-scanning rule that blocks medium and higher security alerts, but [merge policy enforcement](merge-policy.md) is clear that a versioned ruleset is a desired configuration, not proof of enforcement. Check the open code-scanning alerts the day you apply. |
| `static_analysis_often` | SUGGESTED | **Met** | CodeQL runs on every pull request and push, and weekly. |

#### Dynamic code analysis

| Criterion | Level | Status | Evidence |
|---|---|---|---|
| `dynamic_analysis` | SUGGESTED | **Met** | Hypothesis property tests and coverage-guided Atheris fuzzing of the redactor and the source lexer ([fuzzing](fuzzing.md)) both vary their inputs. The release gate requires the whole suite, with the Hypothesis tests in it, to pass on the exact commit; the scheduled fuzz run is not a release gate. |
| `dynamic_analysis_unsafe` | SUGGESTED | **N/A** | The package and its tooling are Python only, with no C, C++, Rust or Cython source; fixtures and benchmark corpora hold other languages as data. Native code comes from third-party wheels. |
| `dynamic_analysis_enable_assertions` | SUGGESTED | **Met** | The suite runs with pytest's assertions, and the fuzz checks raise an explicit `InvariantViolation` that Python's `-O` cannot remove. Neither runs with `-O`. |
| `dynamic_analysis_fixed` | MUST | **Met** | The fuzzers found three weaknesses and one place worth hardening, all fixed with regression tests in the change that added them; [What it has found](fuzzing.md#what-it-has-found) lists them. None exposed a credential; judge their severity yourself. |

## Silver and gold

The higher levels ask for more than one person and for processes this project does not have yet. These are the criteria whose answer is known from the repository today; the rest were not assessed here.

| Level | Criterion | Status | Why |
|---|---|---|---|
| Silver | `access_continuity` (MUST) | **Gap** | [There is one maintainer](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/MAINTAINERS.md), so nobody else can accept changes or release within a week of losing them. |
| Silver | `bus_factor` (SHOULD) | **Gap** | A bus factor of 1. |
| Silver | `assurance_case` (MUST) | **Gap** | The [threat model](../security/threat-model.md) and trust boundaries are written. The argument that secure design principles were applied is not. |
| Silver | `signed_releases` (MUST) | **Confirm** | Releases carry keyless Sigstore attestations, not a project signing key, and [publishing a release](publishing.md#per-release) documents how to verify them. Whether that answers the criterion is your reading. Attach the `.sigstore.json` bundles to each GitHub release, as step 7 describes. |
| Silver | `dco` (SHOULD) | **Met** | [Developer Certificate of Origin](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CONTRIBUTING.md#developer-certificate-of-origin) and the [DCO workflow](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/.github/workflows/dco.yml) check every commit of a pull request. |
| Gold | `bus_factor`, `contributors_unassociated`, `two_person_review` (MUST) | **Gap** | These need at least two unassociated significant contributors and review of at least half of all changes by someone other than the author. [Governance](../governance.md) records that a merged pull request and a green CI run are not a second person's review. |
| Gold | `require_2FA` (MUST) | **Confirm** | A GitHub account and organization setting that the repository cannot show. |
| Gold | `security_review` (MUST) | **Gap** | No independent security review has been done. The files under `archive/reviews/` are not one; the [reviewer packet](reviewer-packet.md) is how one would start. |
| Gold | `build_reproducible` (MUST) | **Gap** | The wheel rebuilds to the same digest from the tagged commit, but the sdist does not ([publishing a release](publishing.md#per-release), step 6). |
| Gold | `test_statement_coverage90` (MUST) | **Gap** | The CI floor is 80% with branches counted; nothing here shows 90% statement coverage. |

## After the badge is awarded

Add the badge to the README only then, with the project number the site assigned, and record the date and level in [the roadmap](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/ROADMAP.md) instead of describing the project as secure:

```markdown
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/PROJECT_ID/badge)](https://www.bestpractices.dev/projects/PROJECT_ID)
```

The OpenSSF Scorecard `CII-Best-Practices` check reads the badge level on its next run: [2 for in progress, 5 for passing, 7 for silver and 10 for gold](https://github.com/ossf/scorecard/blob/main/docs/checks.md#cii-best-practices). Scorecard's `Fuzzing` check is separate and does not recognize this project's fuzzers; [Fuzzing](fuzzing.md#what-it-does-not-show) says why.

## What this page does not claim

* It is a self-assessment by the project's contributors, not an assessment by OpenSSF, and it is not independent review.
* It does not say any criterion is met in the site's records. Only the maintainer's answers do that.
* A **Met** here means the repository shows the practice. It does not show how well the practice works.
* The criteria and the site's automation change. Treat the tables as a checklist for 2026-10-17, not as a standing statement.

Sources: the [passing-level criteria](https://www.bestpractices.dev/en/criteria/0) and the badge project's [criteria data](https://github.com/ossf/best-practices-badge/blob/main/docs/criteria.md); Scorecard's [check documentation](https://github.com/ossf/scorecard/blob/main/docs/checks.md).
