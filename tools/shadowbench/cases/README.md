# ShadowBench harness

The harness for ShadowBench, the nine-surface shadow AI agent discovery benchmark: a seeded
corpus generator, an isolated runner, one adapter per tool, a scorer and a
report renderer. The benchmark's design, rubrics, corpus and committed results
live in [`benchmarks/shadowbench/cases/README.md`](../../../benchmarks/shadowbench/cases/README.md);
read that first. Nothing here is a release artifact, and the results are not
independent: the same maintainer wrote ShadowScan, the harness, the rubrics
and every other tool's adapter.

Third-party tools run as uid and gid 65534 with `no_new_privs`, inside fresh
network, PID and mount namespaces, with an environment built from scratch and
`/root` and `/home` hidden under empty tmpfs mounts (see Isolation below).
That is still not a sandbox: a tool can read any world-readable file elsewhere
on the host. Run the benchmark only on a disposable, externally isolated
machine with no credentials.

## Entry points

Every command is a subcommand of `python -m tools.shadowbench.cases`:

| Command | Module | What it does |
|---|---|---|
| `generate` | `generate.py` | Build the corpus at a seed (`--seed`, `--per-surface`, `--output`). Each surface and modality draws from its own random stream, seeded from a SHA-256 of the seed, surface and modality; the header records this as `"stream_scheme": "sha256"`. `--stream-scheme legacy` only rebuilds the committed 2026-10-11 cases: under it the seed has no effect and four pairs of modalities share a stream (see the benchmark README's Random streams). Export, runtime and active-network cases compose entity drafts into one platform-native input; endpoint and passive-network cases reuse the pre-registered families of `tools/benchmark`; code cases pin repositories from `benchmarks/shadow-ai-discovery/corpus.json`, and generation refuses to run without that file. |
| `verify` | `verify.py` | Load and validate a corpus, print its recorded generator digest beside the current sources' digest, and always rebuild the cases at the recorded seed, per-surface count and stream scheme (`legacy`, with the modalities it makes share a stream, when the header names none) and compare the parsed case lists (header and `created` stamp ignored); a matching digest alone never passes a corpus. Identical cases exit 0 even when the digest differs, and verify says so; any difference exits 1 and names the first differing case or, when one list is a prefix of the other, the two case counts. `--regenerate` is accepted and changes nothing. The committed corpus's digest predates both the move to `cases/` and the digest's inclusion of the code corpus, so verify reports changed sources that build the same cases. |
| `run` | `runner.py` | Materialize each case, execute every adapter's invocations through `stage.py` in isolation, write one JSONL row per (tool, case) and `manifest.json` (with the harness commit), and keep each run's raw output locally under `<out>/raw/<tool>/`. Needs root and a `gcc` that can link a static binary. |
| `score` | `score.py` | Entity-level and case-level metrics per tool, surface and modality; estate recall; agent tier; paired McNemar against a reference tool. Leaves the decoys an adapter declares it withholds from its tool (`withheld_decoys`) out of that tool's specificity, unless the tool reports one anyway. Refuses results the run manifest does not vouch for (another corpus digest, a results file for a tool the manifest does not record as run, row statuses that differ from its counts) or an adapter module that does not load unless `--force`, which records each override; refuses malformed rows and malformed `withheld_decoys` even with `--force`. |
| `report` | `report.py` | Render `metrics.json` as Markdown, with any `--force` override listed at the top and, when the manifest has the harness fields, the harness commit and its state beside the corpus and platform. |

`contract.py` defines the surfaces, modalities, case layout, entity keys and
the adapter protocol. `corpus.py` is the case model and validates case inputs
on load. `families/` holds the entity families and their rubrics.
`mockserv.py` serves the loopback services of active-network cases.
`stage.py` is what runs inside the namespaces. `adapters/` holds one module
per tool, `adapters/registry.py` loads them, and `adapters/_probe.py` runs the
version probes. `fetch_code.py` fetches the pinned code-surface repositories;
it is not a subcommand but a module of its own, run from the repository root
as `python -m tools.shadowbench.cases.fetch_code DEST`. `install_tools.sh`
installs the third-party tools.

## Isolation

For each (tool, case) the runner creates `<scratch>/<tool>-<case>-XXXX/`
(mode 0711) with two directories: `work/`, which holds the materialized case
and the tool's output and is handed to uid 65534 for the run, and `control/`,
which only root can enter and which holds the stage's spec and result. It then
starts `stage.py` as root under `unshare --net --pid --fork --kill-child
--mount --propagation private --mount-proc`, from `/` and with a fixed
`PATH`.

Before anything from the case runs, the stage checks that it is the init of a
fresh PID namespace and not in the runner's mount namespace, sets
`no_new_privs`, brings loopback up, mounts an empty tmpfs over `/root` and
`/home`, and moves to `/`, so no process it starts inherits a working directory
under a hidden path. It then serves the case's mock services on `127.0.0.1`,
starts the case's inert processes as uid 65534 with `work/` as their working
directory, and runs the adapter's invocations as uid 65534 with no
supplementary groups and exactly the environment each invocation declares.
After each invocation, and on a timeout, it stops every process in the
namespace, kills and reaps all but its own inert processes, and records the
case as an error if any process survives. When the stage itself overruns, the
runner kills its process group, which ends every process in the namespace.

Before any tool runs, the runner refuses to start, with exit 2 and the reason,
unless:

* it runs as root and `unshare` (util-linux) is on the fixed `PATH`;
* every case and checkout id in the corpus matches `[A-Za-z0-9._-]+`, since
  the ids name directories;
* the scratch directory (`--scratch`, or a new temporary directory) belongs to
  the runner and gives group and other nothing but search (mode 0711, as the
  runner creates it), because every run's `work/` belongs to the same uid and
  a listable scratch directory would let one tool reach a concurrent run's
  tree;
* the scratch directory, `tool_root` (by default the directory holding
  `tools.json`) and every absolute path in `tools.json` lie outside `/root`
  and `/home`, which the stage hides, and uid 65534 can traverse to the
  scratch directory;
* `gcc` can compile and statically link the inert process binary, which needs
  gcc and the C library's static archive (`glibc-static` or `libc6-dev`,
  depending on the distribution). A missing compiler or a failed link is
  reported with gcc's exit code and the end of its output.

The tools must also be readable and executable by uid 65534. After a tool
exits, any symlink it left that leads out of `work/`, and any FIFO, socket or
device node, is removed before the adapter reads the output as root.

The manifest records a version for each tool that ran. When the tool's entry
in `tools.json` has a `version` string (see Tool configuration), the runner
records that string as given, without a probe. Otherwise it calls the
adapter's `version()` once, after the tool's cases, outside the stage and as
the runner's user. An adapter that runs the tool's binary for it does so only
through `adapters/_probe.py`: the probe gets a fixed `PATH`, a throwaway
`HOME` that is also its working directory, no other inherited environment, an
empty stdin and a timeout. A probe started as root (the runner always is)
never runs the binary as root: it gets an empty network namespace and a
private mount namespace with `/root` and `/home` hidden, and drops to uid/gid
65534 with no supplementary groups and `no_new_privs`, the identity the stage
gives the tool, with its home under `/tmp`. Without `unshare`, `setpriv`,
`mount` and `sh` a root probe does not run. A probe that cannot start, cannot
drop privileges or times out records `unknown`. Otherwise the adapter reads the version from what the probe
printed, whatever its exit code; only the installed-package lookup (Snyk,
Cisco, `agent-discovery`) requires exit 0. Fleet records the printed text as
it is, ShadowScan its last word plus the checkout's commit, and Numbat the
printed text when its version pattern does not match; the other adapters
record `unknown` when theirs does not.

## Tool configuration

`run --tools tools.json` names each installed tool:

```json
{
  "tool_root": "/opt/nsb/tools",
  "tools": {
    "shadowscan": {"bin": "/opt/nsb/venv/bin/python", "repo": "/opt/nsb/Project-Nexus"},
    "snyk-agent-scan": {"bin": "/opt/nsb/tools/venvs/snyk-agent-scan/bin/snyk-agent-scan"},
    "cisco-mcp-scanner": {"bin": "/opt/nsb/tools/venvs/mcp-scanner/bin/mcp-scanner"},
    "agentmesh-discovery": {"bin": "/opt/nsb/tools/venvs/agentmesh-discovery/bin/agent-discovery"},
    "agentdiscover": {"bin": "/opt/nsb/tools/venvs/agentdiscover/bin/agentdiscover"},
    "numbat": {"bin": "/opt/nsb/tools/bin/numbat"},
    "vet": {"bin": "/opt/nsb/tools/bin/vet"},
    "ai-infra-guard": {"bin": "/opt/nsb/tools/bin/ai-infra-guard",
                       "fingerprints": "/opt/nsb/tools/share/ai-infra-guard/fingerprints",
                       "vuln": "/opt/nsb/tools/share/ai-infra-guard/vuln_en"},
    "fleet-ai-tools": {"bin": "/opt/nsb/tools/bin/fleet-ai-tools"}
  }
}
```

ShadowScan's `bin` is a Python interpreter with ShadowScan's dependencies and
its `repo` is the checkout put on `PYTHONPATH`; like every other path here, it
must lie outside `/root` and `/home`. AI-Infra-Guard's `fingerprints` and
`vuln` default to `<tool_root>/share/ai-infra-guard/`. Any entry may also
carry a `version` string. The runner records it in the manifest as given,
for every tool alike, without probing the tool or checking the string against
it; an entry without one gets the version its adapter probes.

Each adapter's module docstring states the exact command line and the mapping
from the tool's output to entity keys. [`install_tools.sh`](install_tools.sh)
builds or installs every tool at the pinned commit or version into a tool root
in this layout and writes `<tool root>/tools.json` for them, without the
ShadowScan entry. Each entry it writes carries the pinned version or commit as
`version`, in the form the committed 2026-10-11 manifest records; remove the
field to record what the installed tool reports instead. Installs are
version-pinned, not hash-locked: each PyPI tool is pinned to one version, but
its transitive dependencies resolve at install time, and the Fleet wrapper's
indirect Go modules are resolved by `go mod tidy`. Record `uv pip freeze` for
each venv and the wrapper's `go.sum` next to any results. The script
downloads third-party code; review it and run it on a disposable machine.

## Reproduce

```bash
git clone . /opt/nsb/Project-Nexus    # from your checkout: a copy outside /root and /home
cd /opt/nsb/Project-Nexus
python -m tools.shadowbench.cases verify --corpus benchmarks/shadowbench/cases/corpus.json
bash tools/shadowbench/cases/install_tools.sh /opt/nsb/tools    # writes /opt/nsb/tools/tools.json
python -m venv /opt/nsb/venv && /opt/nsb/venv/bin/pip install --require-hashes --only-binary=:all: -r requirements.lock
# add to "tools" in /opt/nsb/tools/tools.json:
#   "shadowscan": {"bin": "/opt/nsb/venv/bin/python", "repo": "/opt/nsb/Project-Nexus"}
python -m tools.shadowbench.cases.fetch_code /opt/nsb/checkouts
sudo python -m tools.shadowbench.cases run --corpus benchmarks/shadowbench/cases/corpus.json \
    --tools /opt/nsb/tools/tools.json --checkouts /opt/nsb/checkouts --out /opt/nsb/results --workers 3
python -m tools.shadowbench.cases score --corpus benchmarks/shadowbench/cases/corpus.json \
    --results /opt/nsb/results --out /opt/nsb/results/metrics.json
python -m tools.shadowbench.cases report --corpus benchmarks/shadowbench/cases/corpus.json \
    --metrics /opt/nsb/results/metrics.json --out /opt/nsb/results/REPORT.md
```

`fetch_code` fetches the 26 pinned code-surface repositories with its own
hardened `git` calls: `https` remotes only, hooks off, submodules never
fetched, the caller's `GIT_*` variables dropped except the TLS CA settings,
TLS verification on, no symlinked destination, and `rev-parse HEAD` checked
against the pinned commit. The runner checks each checkout's HEAD again before
copying it into a case.

`run` records in `manifest.json` the corpus path and SHA-256, the generator
digest, the platform, each tool's version and row-status counts, and the
harness the run came from: `harness_commit` is the checkout's `HEAD` (null
when git cannot name it, for example when it refuses a checkout that another
user owns), and `harness_dirty` says whether anything under `tools/`,
untracked files included, differed from it (null when unknown). Untracked
files count because the registry imports every module in `adapters/`. Git
runs without the caller's `GIT_*` variables. `score` copies these fields into
`metrics.json`, and the report names the corpus, the tool versions and, for a
manifest that has the harness fields, the harness commit and its state. The
scorer's own commit is not recorded, so the code that produced `metrics.json`
must still be identified from the repository history. The committed
2026-10-11 manifest predates the harness fields; its report names no harness
commit, and the code that produced its rows can only be inferred from that
history.

## Adding a tool

Write `adapters/<tool>.py` with a class that has `name`, `display`,
`surfaces` (surface to the set of modalities it handles), and the methods
`unavailable_reason`, `version`, `invocations` and `normalize` from
`contract.Adapter`; export it as `ADAPTER`. The runner executes the
invocations; `normalize` maps the tool's own output onto entity keys and never
interprets beyond it. Follow the rules in `adapters/__init__.py`: fail closed
(a crash, timeout, missing report, empty or unparsable output is an `error`,
never an empty `ok`), set `raw["incomplete"]` when the tool says it did not
read everything, emit only taxonomy facts on the code surface, and run the
tool's binary in `version()` only through `_probe.run_probe`. When the
adapter converts a case's input and drops records a decoy comes from, declare
those decoys' key prefixes per (surface, modality) in a `withheld_decoys`
attribute, as the ShadowScan adapter does for AWS IAM roles, so the scorer
does not credit the tool with true negatives for records it never saw. Put
the exact command line and the mapping rule in the docstring, pin the
version, and commit the adapter before running it on the scored corpus.
Calibrate on a different seed (`generate --seed 1 --per-surface 4 --output
smoke.json`) with the default stream scheme; check that `verify --corpus
smoke.json` prints `stream scheme sha256` and no shared streams. Before the
stream fix the seed had no effect, so the committed adapters were calibrated
on a smoke corpus drawn from the scored corpus's own streams.
