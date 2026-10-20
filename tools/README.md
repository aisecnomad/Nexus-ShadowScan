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
| [`complexity_gate.py`](complexity_gate.py) | Fails when a function above ruff's `C901` limit of 20 or a `shadowscan` module above 2,000 lines grows past [`complexity_baseline.json`](complexity_baseline.json), or when that baseline allows more than the code has; `--update` lowers it, `--rebaseline` records a reviewed rise | `make complexity` |
| [`coverage_gate.py`](coverage_gate.py) | Fails when aggregate coverage hides a built-in connector module below its own floor | `make coverage-gate` |
| [`complexity_gate.py`](complexity_gate.py) | Fails when a function is new above cyclomatic complexity 15 or above its allowance in [`complexity_baseline.json`](complexity_baseline.json), keyed by file and qualified name; `--update` records only decreases unless `--allow-increase` is passed too | `make complexity` |
| [`test_annotations.py`](test_annotations.py) | Run by CI after a failed test step: turns the pytest JUnit reports into one error annotation per failing test (node id, file, line, exception type and the redacted first line of the message), so the checks API names each failing test | `python -m tools.test_annotations "$RUNNER_TEMP"/junit-*.xml` |
| [`ocsf_schema.py`](ocsf_schema.py) | `--check` fails when the vendored OCSF Detection Finding requirements do not match the version the reporter emits; `--refresh` rewrites them from the live definition (needs network) | `make ocsf-schema` |
| [`connector_reference.py`](connector_reference.py) | Renders [`docs/connectors/reference.md`](../docs/connectors/reference.md) from the connector classes | `make connector-reference` |
| [`readme_visuals.py`](readme_visuals.py) | Renders the README banner and the architecture diagrams under [`docs/assets/`](../docs/assets/) as SVG from the surfaces, connectors and report formats | `make readme-visuals` |
| [`mapping_reference.py`](mapping_reference.py) | Renders [`docs/concepts/mappings-reference.md`](../docs/concepts/mappings-reference.md) from the mapping catalogs | `make mapping-reference` |
| [`evaluation/`](evaluation/) | The labeled detection regression corpora and their scorer | `make evaluate`; see [docs/evaluation.md](../docs/evaluation.md) |

## Fuzzing

Assurance tooling that runs on a schedule and on demand, not as a merge gate. It looks for inputs that
break a stated guarantee; a clean run does not show that none exist. See
[docs/operations/fuzzing.md](../docs/operations/fuzzing.md) for what each target checks and what it
leaves out.

| Package | What it does | Run it with |
|---|---|---|
| [`fuzz/`](fuzz/) | Atheris targets for the redaction and source-lexing code, the seed corpora they start from (built in code, so no credential-shaped file is stored) and the checks that Hypothesis tests in the ordinary suite share | `make fuzz`, or `python -m tools.fuzz TARGET`; needs [`requirements-fuzz.lock`](../requirements-fuzz.lock) |

## Benchmarks

Comparative and real-world benchmark harnesses moved to the optional, pinned
[Nexus ShadowBench companion](../benchmarks/README.md). Run its commands from
the companion checkout; the main scanner's regression corpora remain local.

| Package | Question it answers | Entry point |
|---|---|---|
| [ShadowBench](https://github.com/aisecnomad/Nexus-ShadowBench/tree/main/tools/shadowbench) | All nine surfaces: generated cases and one authored organization | Companion README |
| [Discovery](https://github.com/aisecnomad/Nexus-ShadowBench/tree/main/tools/discovery_benchmark) | Facts found in 87 pinned public repositories; the weekly workflow uses the companion pin | Companion README |
| [Synthetic and sampled](https://github.com/aisecnomad/Nexus-ShadowBench/tree/main/tools/benchmark) | Generated repository, endpoint and network inputs, plus sampled real-world repositories | Historical source-checkout instructions |
| [Repository and home views](https://github.com/aisecnomad/Nexus-ShadowBench/tree/main/tools/benchmark_realworld) | Public repositories read as a working tree and as `$HOME` | Historical source-checkout instructions |

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
