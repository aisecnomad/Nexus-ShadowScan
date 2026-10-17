## Summary

<!-- What does this PR do? Link any related issues with "Closes #NNN". -->

## Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New connector or signature
- [ ] Enhancement (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that changes existing behavior)
- [ ] Documentation
- [ ] CI / tooling

## Checklist

### Required for all changes

Shortcut: `make check` runs the lint, format, type, complexity, test, coverage, evaluation,
audit, validator and secrets gates below in one command.

- [ ] `make lint` and `make format-check` pass
- [ ] `make typecheck` passes
- [ ] `make complexity` passes (split a function or module that grew; commit a lower baseline with `--update` after an improvement; explain any `--rebaseline`)
- [ ] `make test` passes (full suite, 80% aggregate coverage)
- [ ] `make coverage-gate` passes after that coverage run (per-connector floor)
- [ ] `make evaluate` passes (all bundled corpora; explain any intended corpus change)
- [ ] `make audit` (`pip-audit`) reports no known vulnerabilities
- [ ] `python -m shadowscan.signatures.validate` passes
- [ ] `python -m shadowscan.mappings.validate` passes
- [ ] `make secrets` finds no hardcoded credentials
- [ ] `make policy` passes (when `.github/`, a top-level document or a docs page changed)
- [ ] `make docs` passes (when `docs/`, `mkdocs.yml` or a document the site includes changed)
- [ ] Every commit carries a `Signed-off-by` trailer (`git commit -s`; see the DCO in `CONTRIBUTING.md`)
- [ ] No raw credentials, JWTs, or unsanitized configuration in logs or reports
- [ ] `docs/engineering-log.md` entry and `CHANGELOG.md` line added under Unreleased (if user-facing)

### Required for connector changes

- [ ] Per-connector coverage ≥ 75% for the changed connector (`make coverage-gate` output)
- [ ] Offline fixtures added (no live credentials in tests)
- [ ] Connector handles API failures and marks coverage incomplete (exit 3)
- [ ] New connector registered in `shadowscan/connectors/__init__.py`
- [ ] `docs/connectors/reference.md` and the README detection matrix regenerated (`make connector-reference`, `make readme-matrix`) and least-privilege scopes documented in the connector guide
- [ ] `shadowscan connectors` listing verified

### Required for signature changes

- [ ] Evaluation corpus updated for the new or changed signature
- [ ] No false positives introduced on existing negative corpus entries

### Required for mapping changes

- [ ] `docs/concepts/mappings-reference.md` regenerated (`make mapping-reference`)
- [ ] Each changed rule has a test in `tests/unit/test_mappings.py`

### Required for security-sensitive changes

- [ ] `docs/production.md` updated if rollout, finding identity, or credential policy changed
- [ ] `SECURITY.md` updated if trust boundary or controls changed
- [ ] Redaction tested with known credential formats
- [ ] No credential-bearing values in application log events (only fixed summaries)

## Verification

<!-- How did you verify this change? Paste CI link, test output, or scan results. -->

<!-- State the tested commit, targeted regressions, and any checks not run.
For detection changes include both positive and negative examples. Distinguish
synthetic regression evidence from an independent human-labeled holdout.
For live connector validation name the authorized scope and coverage gaps;
never include tenant identifiers, tokens, or private exports. -->

## Breaking changes

<!-- If this is a breaking change, describe the migration path. -->
