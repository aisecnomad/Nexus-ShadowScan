.DEFAULT_GOAL := help
SHELL := /bin/bash

# --- Development -----------------------------------------------------------

.PHONY: install
install: ## Install in editable mode with dev + cloud + docs extras and the build frontend
	python -m pip install --require-hashes --only-binary=:all: \
		-r requirements-ci.lock -r requirements-build.lock -r requirements.lock -r requirements-docs.lock
	python -m pip install --no-deps --no-build-isolation -e .

.PHONY: install-dev
install-dev: ## Install with dev extras and the build frontend only (no cloud SDKs)
	python -m pip install --require-hashes --only-binary=:all: -r requirements-ci.lock -r requirements-build.lock
	python -m pip install --no-deps --no-build-isolation -e .

.PHONY: install-hooks
install-hooks: install-dev ## Install pinned pre-commit hooks
	pre-commit install

# Fail fast on an interpreter pyproject.toml does not support, before the
# hash-locked installs run (a consistency test keeps these bounds equal to
# requires-python).
.PHONY: ensure-python
ensure-python:
	@python -c 'import sys; sys.exit(None if (3, 11) <= sys.version_info[:2] < (3, 14) else "ShadowScan development needs CPython 3.11 to 3.13; this python is " + sys.version.split()[0] + ". Create a virtual environment with a supported interpreter, for example: python3.12 -m venv .venv")'
install install-dev: ensure-python

# --- Quality ---------------------------------------------------------------

.PHONY: lint
lint: ## Run ruff linter
	ruff check shadowscan tests tools benchmarks

.PHONY: format
format: ## Run ruff formatter
	ruff format shadowscan tests tools benchmarks

.PHONY: format-check
format-check: ## Check ruff formatting without changes
	ruff format --check shadowscan tests tools benchmarks

.PHONY: typecheck
typecheck: ## Run mypy type checker
	mypy shadowscan tools benchmarks

.PHONY: test
test: ## Run test suite with coverage
	python -m pytest -q --cov=shadowscan --cov-report=term-missing --cov-fail-under=80

.PHONY: test-fast
test-fast: ## Run tests without coverage (faster iteration)
	python -m pytest -q -x

.PHONY: test-parallel
test-parallel: ## Run tests in parallel with pytest-xdist
	python -m pytest -q -n auto --cov=shadowscan --cov-report=term-missing --cov-fail-under=80

.PHONY: coverage-gate
coverage-gate: ## Enforce per-connector coverage floor
	@set -euo pipefail; \
	coverage_file="$$(mktemp "$${TMPDIR:-/tmp}/shadowscan-coverage.XXXXXX")"; \
	trap 'rm -f "$$coverage_file"' EXIT; \
	python -m coverage json -o "$$coverage_file"; \
	python -m tools.coverage_gate "$$coverage_file"

.PHONY: signatures
signatures: ## Validate all signature schemas and regexes
	python -m shadowscan.signatures.validate

.PHONY: mappings
mappings: ## Validate the threat and control mapping catalogs
	python -m shadowscan.mappings.validate

.PHONY: secrets
secrets: ## Fail on hardcoded credentials in tracked files, as CI does
	set -o pipefail; git ls-files -z | xargs -0 python tools/check_secrets.py

.PHONY: audit
audit: ## Audit the environment and every hash-locked dependency set, as CI does
	pip-audit --skip-editable --progress-spinner off
	set -e; for lock in requirements.lock requirements-build.lock requirements-ci.lock requirements-docs.lock; do \
		pip-audit --require-hashes --strict --progress-spinner off \
			--disable-pip -r "$$lock"; \
	done

.PHONY: evaluate
evaluate: ## Run the bundled detection regression corpora (reports go to a temporary directory)
	@set -euo pipefail; \
	out="$$(mktemp -d "$${TMPDIR:-/tmp}/shadowscan-evaluation.XXXXXX")"; \
	python -m tools.evaluation.evaluate --output "$$out/synthetic.json"; \
	python -m tools.evaluation.evaluate --corpus tools/evaluation/public_corpus.json --output "$$out/public.json"; \
	python -m tools.evaluation.evaluate --corpus tools/evaluation/realistic_corpus.json --output "$$out/realistic.json"; \
	python -m tools.evaluation.evaluate --corpus tools/evaluation/review_corpus.json --output "$$out/review.json"; \
	python -m tools.evaluation.evaluate --corpus tools/evaluation/field_review_corpus.json --output "$$out/field-review.json"; \
	python -m tools.evaluation.evaluate --corpus tools/evaluation/attribution_corpus.json --output "$$out/attribution.json"; \
	python -m tools.evaluation.evaluate --corpus tools/evaluation/current_idioms_corpus.json --output "$$out/current-idioms.json"; \
	python -m tools.evaluation.evaluate --corpus tools/evaluation/benchmark_followup_corpus.json --output "$$out/benchmark-followup.json"; \
	python -m tools.evaluation.evaluate --corpus tools/evaluation/independent_corpus.json \
		--annotations tools/evaluation/independent_annotations.json --output "$$out/independent.json"; \
	echo "Evaluation reports: $$out"

.PHONY: check
.NOTPARALLEL: check
check: lint format-check typecheck signatures mappings secrets audit test coverage-gate evaluate ## Run local quality gates (CI also validates packaging and containers)
	@echo "All checks passed."

.PHONY: policy
policy: ## Check repository policy: action pins, permissions, links, anchors, Makefile/CI parity
	python -m pytest -q tests/test_repository_policy.py tests/test_repository_consistency.py

.PHONY: check-fast
check-fast: lint format-check typecheck signatures mappings secrets policy ## Offline subset of check for a quick pre-push run (no tests, audit or evaluation)

# --- Build -----------------------------------------------------------------

.PHONY: build
build: ## Build the sdist and the wheel from it, stamped with the HEAD commit time as release.yml does
	python -m pip install --require-hashes --only-binary=:all: -r requirements-build.lock
	SOURCE_DATE_EPOCH="$$(git show -s --format=%ct HEAD)" python -m build --no-isolation --outdir dist .
	python -m tools.release.distributions --directory dist

.PHONY: wheel-validate
wheel-validate: build ## Validate the wheel installs and works outside checkout
	@set -euo pipefail; \
		set -- dist/nexusshadowscan-*.whl; \
		if [ "$$#" -ne 1 ] || [ ! -f "$$1" ]; then \
			echo "wheel-validate requires exactly one scanner wheel in dist; remove stale build artifacts" >&2; \
			exit 1; \
		fi; \
		wheel="$$1"; \
		wheel_test_root="$$(cd "$${TMPDIR:-/tmp}" && pwd -P)"; \
		wheel_test_dir="$$(mktemp -d "$$wheel_test_root/shadowscan-wheel-test.XXXXXXXX")"; \
		trap 'rm -rf -- "$$wheel_test_dir"' EXIT; \
		python -m venv "$$wheel_test_dir/venv"; \
		"$$wheel_test_dir/venv/bin/python" -m pip install --require-hashes --only-binary=:all: -r requirements.lock; \
		"$$wheel_test_dir/venv/bin/python" -m pip install --no-deps "$$wheel"; \
		"$$wheel_test_dir/venv/bin/python" -m pip check; \
		cd "$$wheel_test_dir"; \
		"$$wheel_test_dir/venv/bin/python" -m shadowscan.signatures.validate; \
		"$$wheel_test_dir/venv/bin/python" -m shadowscan.mappings.validate; \
		"$$wheel_test_dir/venv/bin/shadowscan" --help

.PHONY: docker
docker: ## Build worker from the reviewed Dockerfile base digest
	docker build --tag shadowscan:local .

.PHONY: docker-test
docker-test: docker ## Run container smoke test
	docker run --rm --network none --read-only --cap-drop ALL \
		--security-opt no-new-privileges --entrypoint python shadowscan:local \
		-c 'import os; assert os.geteuid() == 65532; print("Non-root: OK")'
	docker run --rm --network none --read-only --cap-drop ALL \
		--security-opt no-new-privileges --entrypoint python shadowscan:local \
		-m shadowscan.signatures.validate
	docker run --rm --network none --read-only --cap-drop ALL \
		--security-opt no-new-privileges --entrypoint python shadowscan:local \
		-m shadowscan.mappings.validate

# --- Demo ------------------------------------------------------------------

.PHONY: demo
demo: ## Run the bundled offline demo scan
	shadowscan scan -c examples/shadowscan.offline.yaml --format table

.PHONY: demo-sarif
demo-sarif: ## Run offline demo with SARIF output
	shadowscan scan -c examples/shadowscan.offline.yaml --format sarif -o shadowscan.sarif
	@echo "SARIF written to shadowscan.sarif"

# --- Docs ------------------------------------------------------------------

.PHONY: docs
docs: ## Build documentation site locally with the locked toolchain
	python -m pip install -q --require-hashes --only-binary=:all: -r requirements-docs.lock
	mkdocs build --strict

.PHONY: docs-serve
docs-serve: ## Serve documentation site with live reload
	python -m pip install -q --require-hashes --only-binary=:all: -r requirements-docs.lock
	mkdocs serve

.PHONY: connector-reference
connector-reference: ## Regenerate docs/connectors/reference.md from the connector classes
	python -m tools.connector_reference

.PHONY: readme-matrix
readme-matrix: ## Regenerate the README detection matrix from the signature packs and connector classes
	python -m tools.readme_matrix

.PHONY: readme-visuals
readme-visuals: ## Regenerate the README banner and architecture diagrams (docs/assets/*.svg) from the code
	python -m tools.readme_visuals

.PHONY: mapping-reference
mapping-reference: ## Regenerate docs/concepts/mappings-reference.md from the mapping catalogs
	python -m tools.mapping_reference

# --- Cleanup ---------------------------------------------------------------

.PHONY: clean
clean: ## Remove build artifacts and caches
	rm -rf dist build site *.egg-info .mypy_cache .pytest_cache .ruff_cache .hypothesis .coverage coverage.xml htmlcov
	rm -f shadowscan.sarif
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

# --- Help ------------------------------------------------------------------

.PHONY: help
help: ## Show this help
	@awk 'BEGIN { FS = ":.*## "; if (system("test -t 1") == 0) { b = "\033[1m"; c = "\033[36m"; r = "\033[0m" } } /^# --- / { t = $$0; gsub(/^# --- | -+$$/, "", t); printf "\n%s%s%s\n", b, t, r; next } /^[a-zA-Z_-]+:.*## / { printf "  %s%-20s%s %s\n", c, $$1, r, $$2 }' $(MAKEFILE_LIST)
