# Sampled real-world repositories benchmark (326)

Runs open-source Shadow-AI / agent-discovery tools on **real public repositories** (GitHub and GitLab)
and measures how often they notice LLM, agent, MCP and coding-agent integrations, and how often they raise
a false alarm. It complements the synthetic head-to-head in [`../README.md`](../README.md), whose cases
were written in this repository and which cannot say anything about code in the wild.

> **Read [PROTOCOL.md](PROTOCOL.md) first.** It states the sampling, ground truth, tool rules, metrics, the
> changes made after a separate-agent design review (not human, not independent), and what the benchmark
> does *not* show. This benchmark is
> **not independent**: ShadowScan, one of the tools scored, is developed in the same repository. The ground
> truth is a deterministic oracle plus language-model adjudication of disagreements; neither is human review.
> Results are for offline runs of pinned tool versions on one dated sample, not field precision or recall,
> and nothing here ranks the tools. Nothing was committed while the benchmark ran (the files were an uncommitted working tree);
> they were committed afterwards, in the pull request that added this directory, and `results/freeze.json`
> records the hashes the scored run was checked against.

| File | Purpose |
|---|---|
| [PROTOCOL.md](PROTOCOL.md) | the protocol, its limits and its change log |
| [CORPUS.md](CORPUS.md) | generated description of the scored sample |
| [REPORT.md](REPORT.md) | generated results, with a written findings section |
| `manifest.jsonl`, `calibration.jsonl` | the sample: URL, pinned commit, tree hash, size, frame, metadata |
| `labels.jsonl`, `labels-calibration.jsonl` | oracle output (version 2) for each repository |
| `exclusions.json` | scored repositories that the ShadowScan repository names (`contamination.py`) |
| `rejects.jsonl`, `sampling-summary.json` | why candidates were not used; pool sizes; seed |
| `registry/ai_registry.json` | the oracle's knowledge (packages, imports, paths, markers) and its revision log |
| `registry/vocab-overlap.json` | which tools' own source mentions each registry technology (`vocab_overlap.py`) |
| `oracle.py` | tool-independent labeller (standard library only; run with `python -I`) |
| `frames.py`, `sample.py`, `fetch.py`, `fetch_corpus.py`, `purposive.json` | where repositories come from; the hardened snapshot fetcher; corpus re-creation |
| `adapters.py`, `baseline_grep.py` | one run command and one fixed "detected" rule per tool; keyword baselines |
| `sandbox.py`, `run.py`, `freeze.py` | network-less, unprivileged, file-system-restricted runs; the parallel resumable runner; the hash freeze |
| `score.py`, `adjudicate.py`, `report.py`, `corpus_summary.py` | statistics, blinded adjudication, rendering |
| `rerun_errors.py`, `record_environment.py` | re-run timeouts alone (declared sensitivity); hash the stored corpus and tool packages |
| `diagnose_shadowscan.py` | a diagnostic, not a score: repeats the ShadowScan scans that were partial or incomplete and counts the causes into `results/shadowscan-incomplete-causes.json` (labels and counts only) |
| `install_tools.sh` | pinned installation of the third-party tools (ShadowScan from this checkout) |
| `install_cdxgen.py`, `cdxgen/package.json`, `cdxgen/package-lock.json` | frozen npm installation, disabled lifecycle scripts, and a receipt for each new cdxgen installation |
| [SHADOWSCAN-FIXES.md](SHADOWSCAN-FIXES.md) | what was changed in ShadowScan after reading its failures in REPORT.md, and what was measured afterwards; not a second person's audit |
| `results/` | normalised per-repository outcomes, scored summary, run manifest, freeze record (no raw tool output) |
| `results-rerun/` | the timeout, kill and adapter-exception pairs re-run alone with two workers (`rerun_errors.py --out`); a declared deviation that REPORT.md describes and PROTOCOL.md does not |
| `results-merged/` | a copy of `results/` in which each re-run pair replaces its first row (`rerun_errors.py --merged`); the input to the re-run sensitivity table, never the headline |
| `results/summary-rerun.json` | `score.py` output for `results-merged/`, read by `report.py --rerun-summary` |

## Reproduce

Needs root (namespaces, cgroups, `pivot_root`), a user named `rwb` (`useradd -r -M rwb`), Python 3.13, Node 22 with npm 10,
Go and `uv`. Use a disposable machine: the scripts download and run third-party code and clone untrusted
repositories (nothing from a repository is ever executed outside the sandbox).

```bash
bash tools/benchmark/realworld/install_tools.sh /opt/rwb/toolroot
python -m tools.benchmark.realworld.fetch_corpus --manifest tools/benchmark/realworld/manifest.jsonl --corpus WORK/corpus
python -I tools/benchmark/realworld/oracle.py --registry tools/benchmark/realworld/registry/ai_registry.json \
    --manifest tools/benchmark/realworld/manifest.jsonl --corpus WORK/corpus --out labels.jsonl
python -m tools.benchmark.realworld.freeze --write results/freeze.json
python -m tools.benchmark.realworld.run --manifest tools/benchmark/realworld/manifest.jsonl \
    --corpus WORK/corpus --tool-root /opt/rwb/toolroot --results results --workers 8 --timeout 600 \
    --freeze results/freeze.json
python -m tools.benchmark.realworld.score --manifest tools/benchmark/realworld/manifest.jsonl \
    --labels tools/benchmark/realworld/labels.jsonl --results results --output results/summary.json
python -m tools.benchmark.realworld.report --summary results/summary.json --run-manifest results/run-manifest.json \
    --manifest tools/benchmark/realworld/manifest.jsonl --labels tools/benchmark/realworld/labels.jsonl \
    --results results --freeze results/freeze.json --output REPORT.md
```

Unit tests: `python -m pytest tests/test_benchmark_realworld_sampled.py`.

### cdxgen dependency installation

New installations copy the committed `cdxgen/package.json` and `package-lock.json`
into `TOOL_ROOT/cdxgen`, then use `npm ci --ignore-scripts --engine-strict`.
The lock pins the transitive registry tarballs and their integrity hashes; npm
fails if the manifest and lock disagree. No npm lifecycle script runs. Python
and Go tool installation still executes third-party build code, so the disposable
machine requirement applies.

The tool version remains cdxgen 12.8.5. Its exact Undici 7.28.0 dependency has
known vulnerabilities, and cdxgen 12.8.6 still uses that pin. The committed
manifest narrowly overrides it to
[Undici 7.29.1](https://github.com/nodejs/undici/releases/tag/v7.29.1), which
contains the security fixes. This creates a new dependency graph; it does **not**
reconstruct or validate the dependencies used for the historical benchmark.
Existing results, run manifests and freeze records are preserved.

After a successful installation, `TOOL_ROOT/cdxgen/install-receipt.json` records
the manifest and lock SHA-256 hashes, tool and runtime versions, override and
lifecycle policy. Once replacement begins, a failed install leaves no success
receipt; a preflight failure leaves the intact prior installation's receipt alone. Save
that receipt with any new run's evidence. Before updating the lock, review the
dependency changes, run `npm audit --package-lock-only` in the committed `cdxgen`
directory, and verify the installed CLI on a small synthetic input. Do not run
benchmark repositories or their scripts while reviewing installation.

## Safety notes

* Repositories are cloned with hooks, LFS and submodules disabled, `.git` removed, and every symlink that is
  absolute, dangling, cyclic or physically resolves outside the snapshot replaced by a text file. The oracle
  and the keyword baseline run with `python -I`; the baseline runs inside the sandbox.
* Tools run as an unprivileged user with no capabilities, no network, an empty `HOME`, a memory cap, a
  wall-clock kill and a minimal root file system (no home directory, corpus, labels or other session). The
  privileged process reads tool output only through `Session.read`, which refuses symlinks anywhere in the
  path; a database a tool writes is opened by an unprivileged process inside the sandbox.
* Raw tool output is discarded: public repositories can contain other people's credentials, and AGENTS.md
  forbids persisting them. Rows keep fixed-vocabulary notes, exception class names and filtered names.
