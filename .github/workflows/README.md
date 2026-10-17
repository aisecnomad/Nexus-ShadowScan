# Workflows

Every GitHub Actions workflow in this directory, what starts it and what it
may write. GitHub runs only the `.yml` and `.yaml` files here; this page is
documentation. The rules every workflow follows are tested by
[`tests/test_repository_policy.py`](../../tests/test_repository_policy.py)
(`make policy`): actions pinned by full commit SHA, `persist-credentials: false`
on checkouts, a `timeout-minutes` on every job, write scopes granted per job
and listed in `WRITE_SCOPES`, and no cancellation of a `main` push run.

## Required for merging

The `Require CI and CodeQL` ruleset
([committed payload](../rulesets/require-ci-and-review.json),
[merge policy](../../docs/operations/merge-policy.md)) requires these checks on
pull requests to `main`: `test (3.11)`, `test (3.12)` and `CI gate` from
[CI](ci.yml), and `analyze` from [CodeQL](codeql.yml). Renaming one of those
jobs needs a ruleset change in the same pull request.

## Inventory

| Workflow | Starts on | What it does | Writes |
|---|---|---|---|
| [CI](ci.yml) | push to `main`, every pull request, Monday 05:17 UTC | DCO check (calls [DCO](dco.yml)), docs build, tests on Linux and macOS, coverage gates, evaluation corpora, wheel and container checks; `CI gate` summarizes them | nothing |
| [CodeQL](codeql.yml) | push to `main`, every pull request, Monday 05:29 UTC | Python code scanning | `security-events` |
| [Docs](docs.yml) | push and pull request touching docs or the package; manual | Builds the MkDocs site; a manual run with `publish` from `main` deploys GitHub Pages, and with the repository variable `DOCS_PUBLISH` set to `true` every docs push to `main` republishes it | `pages`, `id-token` (deploy job only) |
| [DCO](dco.yml) | called by CI | Checks every commit's `Signed-off-by` trailer | nothing |
| [Scorecard](scorecard.yml) | push to `main`, ruleset changes, Monday 05:20 UTC, manual | OpenSSF Scorecard; publishes the result | `security-events`, `id-token` |
| [Dependency and governance audit](audit.yml) | Tuesday 04:41 UTC, manual | `pip-audit` of every hash lock; read-only check of the visible `main` rules | nothing |
| [Discovery benchmark](benchmark.yml) | Wednesday 06:23 UTC, manual | Regression gate on the pinned public corpus in [`benchmarks/shadow-ai-discovery`](../../benchmarks/shadow-ai-discovery/) | nothing |
| [AI review](ai-review-gate.yml) | pull requests that change `.github/ai-review/**` | Validates and publishes AI review evidence ([gate design](../../docs/security/ai-review-gate.md)); never an approval | `pull-requests`, `checks` (publication job only) |
| [Release candidate evidence](release.yml) | manual only | Builds and attests a review bundle; uploads to an index only after review, from a protected environment | `attestations`, `id-token` |
| [Labels](labels.yml) | push to `main` changing [`labels.yml`](../labels.yml), manual | Creates or updates every label in the taxonomy; never deletes one | `issues` |
| [Stale issues](stale.yml) | Monday 06:00 UTC, manual | Marks inactive issues and pull requests `stale`; never closes them | `issues`, `pull-requests` |

## Optional third-party scanners

These run only after the maintainer configures the vendor service; until then
every run is skipped, which is expected. Pull requests from forks and from
Dependabot receive no repository secrets, so they are skipped too.

| Workflow | Enabled by | Starts on | Writes |
|---|---|---|---|
| [Black Duck](black-duck-security-scan-ci.yml) | variable `BLACKDUCKSCA_URL`, `COVERITY_URL`, `POLARIS_SERVER_URL` or `SRM_URL`, with its secret; the job then fails unless variable `BRIDGECLI_DOWNLOAD_VERSION` holds an `x.y.z` version | push to `main`, pull requests, Wednesday 06:25 UTC | nothing |
| [Checkmarx One](checkmarx-one.yml) | variable `CX_BASE_URI` and the `CX_*` secrets | pull requests | `security-events` |
| [Semgrep](semgrep.yml) | variable `SEMGREP_ENABLED=true` and secret `SEMGREP_APP_TOKEN` | push to `main`, pull requests, Friday 08:24 UTC | `security-events` |

The Black Duck action downloads the Bridge CLI at run time, so once a service
is configured the job also requires the repository variable
`BRIDGECLI_DOWNLOAD_VERSION`, set to a reviewed Bridge CLI version (`x.y.z`)
and passed as `bridgecli_download_version`. Without it the job fails at its
first step instead of skipping, because a skipped job reports success and
would look like an unconfigured integration. The variable pins the Bridge CLI
by version, not by content: the action fetches that version's bundle from
`repo.blackduck.com` over HTTPS without a checksum check, and the pin does not
cover tools the Bridge CLI fetches for a scan.

## Changing a workflow

Run `make policy` before pushing. A new write scope must be added to
`WRITE_SCOPES` in the policy test with the job that needs it; a new label used
by automation must exist in [`labels.yml`](../labels.yml). Dependabot keeps the
action pins here and in [`examples/`](../../examples/) moving together
([`dependabot.yml`](../dependabot.yml)).
