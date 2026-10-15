# Repository tooling

Everything under `tools/` is development and assurance tooling for this
repository. None of it ships in the `nexusshadowscan` wheel, and none of it
publishes a package, a release or a tag. Run each entry point from the
repository root with the development install (`make install`), so the
`python -m` entry points below resolve.

## Quality gates

These run in CI and in `make check`; see
[CONTRIBUTING.md](../CONTRIBUTING.md#quality-gates) for the full list.

| Module | What it does | Run it with |
|---|---|---|
| [`check_secrets.py`](check_secrets.py) | Fails on credential-shaped values in tracked files; narrow exceptions live in [`secret_allowlist.json`](secret_allowlist.json), each bound to a path and a value digest | `make secrets` |
| [`coverage_gate.py`](coverage_gate.py) | Fails when aggregate coverage hides a built-in connector module below its own floor | `make coverage-gate` |
| [`connector_reference.py`](connector_reference.py) | Renders [`docs/connectors/reference.md`](../docs/connectors/reference.md) from the connector classes | `make connector-reference` |
| [`readme_visuals.py`](readme_visuals.py) | Renders the README banner and the architecture diagrams under [`docs/assets/`](../docs/assets/) as SVG from the surfaces, connectors and report formats | `make readme-visuals` |
| [`mapping_reference.py`](mapping_reference.py) | Renders [`docs/concepts/mappings-reference.md`](../docs/concepts/mappings-reference.md) from the mapping catalogs | `make mapping-reference` |
| [`evaluation/`](evaluation/) | The labeled detection regression corpora and their scorer | `make evaluate`; see [docs/evaluation.md](../docs/evaluation.md) |

## Benchmarks

Comparative and real-world benchmarks. Each one answers a different question;
[benchmarks/README.md](../benchmarks/README.md) compares them and states what
none of them can show.

| Package | Question it answers | Entry point |
|---|---|---|
| [`shadowbench/`](shadowbench/README.md) | All nine surfaces: generated per-surface cases with decoys, and one authored organization scored entity by entity | `python -m tools.shadowbench` |
| [`discovery_benchmark/`](discovery_benchmark/README.md) | Code surface: which facts do discovery tools find in 87 pinned public repositories; `benchmark.yml` reruns ShadowScan on it weekly as a regression gate | `python -m tools.discovery_benchmark` |
| [`benchmark/`](benchmark/README.md) | Seeded, generated head-to-head cases on repository, endpoint and network inputs, plus the sampled real-world cohort under [`benchmark/realworld/`](benchmark/realworld/README.md) | `python -m tools.benchmark.run` |
| [`benchmark_realworld/`](benchmark_realworld/README.md) | Public repositories read as a working tree and as `$HOME`, labeled under a written protocol | `python -m tools.benchmark_realworld.run` |

## Release, governance and acceptance

Maintainer-run checks. They read evidence and settings; they change nothing on
GitHub or in a tenant.

| Package | What it does | Documented in |
|---|---|---|
| [`release/`](release/) | Binds a release candidate to successful CI with verifiable file hashes and checks the merge rules it was built under; never publishes | [docs/operations/publishing.md](../docs/operations/publishing.md) |
| [`governance/`](governance/), [`governance_check.py`](governance_check.py) | Prepares and audits the `main` rulesets against the committed merge policy | [docs/operations/merge-policy.md](../docs/operations/merge-policy.md) |
| [`acceptance/`](acceptance/README.md) | Checks a deployment evidence packet against a policy chosen before evaluation | [its README](acceptance/README.md) |
| [`canaries/`](canaries/) | Read-only, explicitly scoped tenant acceptance canaries | [docs/canaries.md](../docs/canaries.md) |
| [`container/`](container/) | Verifies exact-image container scan evidence in CI | [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) |
| [`ai_review/`](ai_review/) | The advisory AI review gate: validates and synthesizes model findings; it is not a review | [docs/security/ai-review-gate.md](../docs/security/ai-review-gate.md) |
