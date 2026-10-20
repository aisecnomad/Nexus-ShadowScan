# Stability and compatibility

ShadowScan is at version 0.1.2 with the package classifier
`Development Status :: 3 - Alpha`. This page defines the contract that 1.0.0
will freeze: what callers may rely on, what may change in any release, and how
a stable feature is retired. Until 1.0.0 the same contract is already recorded
and checked in CI, so every change to it is visible in review, but a 0.x minor
release may still break it with a changelog entry.

Bumping the version, changing the classifier and tagging are maintainer
release actions under the [release process](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/GOVERNANCE.md#release-process).
Nothing on this page changes the version or publishes anything.

## Versioning after 1.0

From 1.0.0, releases follow [Semantic Versioning](https://semver.org/) for the
stable surface listed below:

- **Major** (2.0.0): removes or renames a stable command, option, alias,
  configuration key, connector name, Python name or report field; changes the
  meaning of an exit code; narrows an accepted value; or changes a versioned
  schema without a new schema identifier.
- **Minor** (1.1.0): adds a command, option, choice, connector, configuration
  key, Python name, report field or incomplete-reason category; deprecates a
  stable feature.
- **Patch** (1.0.1): fixes behavior without changing the stable surface.

Detection content is not versioned this way. A minor or patch release may add,
retune or retire signatures, change confidence and risk scores, and find more
or fewer agents in the same input; [evaluation](../evaluation.md) records how
detection changes are measured.

## What is stable

| Surface | Where it is recorded | Checked by |
|---|---|---|
| Command line: commands, subcommands, options, their aliases and secondary (`--deny-…`) spellings, value types and choices, plain defaults | [`cli-surface.json`](cli-surface.json) | `make cli-surface`; `tests/test_stability_contract.py` |
| Exit codes 0, 1, 2 and 3 as the [exit code table](cli.md#exit-codes) defines them | the `exit_codes` of [`cli-surface.json`](cli-surface.json), read from that table | the same test, which also requires every exit literal in `shadowscan/cli/` to be documented |
| Python API: the names in `__all__` of every public module, with their signatures, bases and public members | [`python-api.json`](python-api.json) | `make python-api`; `tests/test_stability_contract.py` |
| Connector plugin API: the `shadowscan.connectors` entry-point group, `BaseConnector` and `ConnectorContext`, the class attributes the registry verifies, `PluginDiagnostic.rule` identifiers and the `options.plugins` approval syntax | [`python-api.json`](python-api.json) (`shadowscan.connectors`, `shadowscan.connectors.base`) and [plugin identity rules](../architecture.md#plugin-identity-rules) | the Python API snapshot |
| Built-in connector names (`surface.provider`), their configuration keys and offline export formats | [connector configuration reference](../connectors/reference.md) | `make connector-reference` |
| Scan configuration file keys (`shadowscan.yaml`, `options.*`) | [configuration](../getting-started/configuration.md) | parsing rejects an unknown top-level, `options` or built-in connector key |
| JSON report: top-level fields, `finding_identity_schema`, finding fields and `summary.incomplete_reasons` categories | [models](../api/models.md); the categories are `INCOMPLETE_REASONS` in `shadowscan.coverage` | the `ScanResult` and `Finding` signatures in the Python API snapshot; field-level changes are reviewed by hand |
| SARIF 2.1.0, OCSF 1.1.0 Detection Finding (`class_uid` 2004) and CycloneDX 1.6 output, with the version each declares | [reporters](../api/reporters.md), [OCSF events](../operations/ocsf.md), [AI bill of materials](../operations/ai-bom.md) | `tests/unit/test_sarif_validity.py` against the vendored SARIF schema, `tests/unit/test_ocsf_validity.py` and `python -m tools.ocsf_schema --check`, `tests/unit/test_cyclonedx.py` |
| Finding identity: a finding's `id` for the same input under the same identity schema | [finding identity](../architecture.md#finding-identity-and-merging) | `tests/unit/test_finding_continuity.py` |
| Versioned documents, each named by a `shadowscan.<document>/v<N>` identifier: `finding-identity/v2`, `collection-scope/v1`, `live-scope/v1`, `credential-identity/v1`, `inventory/v1`, `control-evidence/v1`, `fleet-merge/v2`, `autonomy/v1`, `registry-record/v1`, `mcp-registry-snapshot/v1`, `record-exports/v1` | the module that writes each | review: an incompatible change needs a new identifier |
| Signature pack YAML schema | [signatures](../signatures.md) | `python -m shadowscan.signatures.validate` |

A versioned document changes incompatibly only under a new identifier (`v2`
after `v1`). Changing how finding IDs are derived is a new
`shadowscan.finding-identity` version: earlier baselines stop being comparable,
so it ships with a [migration note](../production-migrations.md) and, after
1.0, in a major release.

The public Python modules are `shadowscan`, `shadowscan.connectors` and every
module an [API reference](../api/index.md) page renders. Each declares
`__all__`; a name outside it is internal even when it has no underscore, and a
test fails when a public module defines a public-looking name it does not list.

## What is internal

These may change in any release, without deprecation:

- Every module or name whose own name, or any parent package's, starts with an
  underscore, such as `shadowscan/cli/_scan.py` and the other command modules,
  and `shadowscan.reporters._publication`.
- The `shadowscan.cli` Python module, its Click objects and `ScanOptions`: the
  `shadowscan` command is the contract, not the objects that implement it.
- `shadowscan.utils` other than `shadowscan.utils.http` and
  `shadowscan.utils.redaction`; `shadowscan.coverage`, `shadowscan.errors`,
  `shadowscan.endpoint` and `shadowscan.plugin_process`; submodules of
  `shadowscan.signatures`, `shadowscan.mappings` and `shadowscan.reporters`
  beyond what each package's `__all__` exports.
- The concrete connector modules (`shadowscan.connectors.identity.okta` and the
  rest). Use a connector by its registered name through the configuration or
  `get_connector_class()`; its Python class, helpers and record shapes are
  implementation.
- Human-readable output: the table, Markdown, HTML and CSV layouts, help text,
  log lines, diagnostics, finding titles and descriptions, and evidence text.
- Default limits, budgets and timeouts, which a release may retune with a
  changelog entry.
- Everything under `tools/`, `benchmarks/` and `tests/`, which never ships.

The [connector maintenance inventory](../operations/connector-inventory.md)
describes the built-in connectors for review; it is documentation, not part of
the versioned contract.

## Deprecation policy

A stable feature is deprecated before it is removed:

1. The change that deprecates it documents the replacement, records the
   deprecation in `CHANGELOG.md`, and, where the code can tell, makes using it
   log a warning.
2. The deprecated feature keeps working for at least one minor release after
   the release that deprecates it.
3. It is removed only in a major release, with a migration note.

Current deprecations:

| Deprecated | Replacement | Warns when used |
|---|---|---|
| `--connector-timeout` (alias on every scanning command) | `--connector-timeout-seconds` | no; the option help names it |
| `options.connector_timeout` in a configuration file | `options.connector_timeout_seconds` | yes, once per process |
| `ScanConfig(connector_timeout=...)` | `ScanConfig(connector_timeout_seconds=...)` | yes, once per process |

## When a contract test fails

`tests/test_stability_contract.py` compares the committed snapshots with what
the code produces now and lists what was removed, changed or added. It fails
on any drift, additions included, so that every change to the surface is
reviewed:

1. Run `make cli-surface` or `make python-api` (or `python -m tools.cli_surface`
   and `python -m tools.public_api`) and commit the regenerated JSON with the
   change.
2. Say in the pull request whether the change is **additive** (a new command,
   option, choice, name or optional parameter) or **breaking** (anything
   removed, renamed or narrowed, a parameter made required, a changed default,
   type or exit-code meaning).
3. For a breaking change, deprecate first as above. Before 1.0 a breaking
   change still needs a changelog entry that says so and a migration note when
   operators must act.

An internal helper in a public module takes an underscore prefix instead of a
place in `__all__`.

## 1.0.0 readiness checklist

The maintainer decides when 1.0.0 is ready. Items marked done are recorded in
the repository; the others are open.

- [x] CLI surface frozen as a snapshot with a drift test
  ([`cli-surface.json`](cli-surface.json)).
- [x] Every public module declares `__all__`; the public Python API is frozen
  as a snapshot with a drift test ([`python-api.json`](python-api.json)).
- [x] Connector permissions and failure modes inventoried with a drift test
  and a weekly check ([connector maintenance inventory](../operations/connector-inventory.md)).
- [ ] Review the frozen surface itself. The Python snapshot declares every
  name the API reference pages render public, several hundred across the
  public modules. Trim what should not be supported through 1.x (an underscore
  prefix, or a module dropped from the API reference) before tagging 1.0.0;
  afterwards each removal is a major release.
- [ ] Decide the `--connector-timeout` alias: remove it before 1.0.0, or keep it
  through 1.x and make it warn like the configuration key does.
- [ ] Independent human review of the exact release candidate commit by
  someone who did not author it, recorded as a pull request approval, as the
  [release process](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/GOVERNANCE.md#release-process)
  and [review policy](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/CONTRIBUTING.md#review-and-merge-policy)
  require. CI, CodeQL, Scorecard and AI-assisted review do not count.
- [ ] Retained acceptance evidence for the deployment scope 1.0.0 claims,
  including authorized live tenant checks where they apply; offline tests do
  not establish it.
- [ ] A fresh live readback of the `main` rulesets showing the
  [versioned merge policy](../operations/merge-policy.md) in force.
- [ ] Migration notes for every breaking change since 0.1.2 in
  [pending migration notes](../production-migrations.md).
- [ ] Release actions, by the maintainer only: version 1.0.0, classifier
  `Development Status :: 5 - Production/Stable`, release notes, the
  [publishing runbook](../operations/publishing.md).
