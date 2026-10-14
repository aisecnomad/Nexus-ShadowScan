# ShadowBench harness

The harness for ShadowBench, the nine-surface shadow AI agent discovery benchmark: a seeded
corpus generator, an isolated runner, one adapter per tool, a scorer and a
report renderer. The benchmark's design, rubrics, corpus and committed results
live in [`benchmarks/shadowbench/synthetic/README.md`](../../../benchmarks/shadowbench/synthetic/README.md);
read that first. Nothing here is a release artifact, and the results are not
independent: the same maintainer wrote ShadowScan, the harness and the rubrics.

Third-party tools run as root inside fresh network and PID namespaces with a
minimal environment. That is not a filesystem sandbox: a tool can read the host
(Fleet's table enumerates every home directory, for example). Run the benchmark
only on a disposable, externally isolated machine with no credentials.

## Entry points

Every command is a subcommand of `python -m tools.shadowbench.synthetic`:

| Command | Module | What it does |
|---|---|---|
| `generate` | `generate.py` | Build the corpus at a seed. Export, runtime and active-network cases compose entity drafts into one platform-native input; endpoint and passive-network cases reuse the pre-registered families of `tools/benchmark`; code cases pin repositories from `benchmarks/shadow-ai-discovery/corpus.json`. |
| `verify` | `verify.py` | Check a committed corpus loads, validates, and matches the generator sources (`--regenerate` rebuilds and compares). |
| `run` | `runner.py` | Materialize each case, execute every adapter's invocations through `stage.py` in isolation, store one JSONL row per (tool, case) and the verbatim output. |
| `score` | `score.py` | Entity-level and case-level metrics per tool, surface and modality; estate recall; agent tier; paired McNemar against a reference tool. |
| `report` | `report.py` | Render `metrics.json` as Markdown. |

`contract.py` defines the surfaces, modalities, case layout, entity keys and
the adapter protocol. `corpus.py` is the case model. `families/` holds the
entity families and their rubrics. `mockserv.py` serves the loopback services
of active-network cases. `stage.py` is what runs inside the namespaces.
`adapters/` holds one module per tool; `adapters/registry.py` loads them.

## Tool configuration

`run --tools tools.json` names each installed tool:

```json
{
  "tool_root": "/opt/nsb/tools",
  "tools": {
    "shadowscan": {"bin": "/opt/nsb/venv/bin/python", "repo": "/path/to/Nexus-ShadowScan"},
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

Each adapter's module docstring states the exact command line and the mapping
from the tool's output to entity keys. [`install_tools.sh`](install_tools.sh)
builds or installs every tool at the pinned commit or version into a tool root
in this layout. It downloads third-party code; review it and run it on a
disposable machine.

## Reproduce

```bash
python -m tools.shadowbench.synthetic verify --corpus benchmarks/shadowbench/synthetic/corpus.json --regenerate
bash tools/shadowbench/synthetic/install_tools.sh /opt/nsb/tools
python -m venv /opt/nsb/venv && /opt/nsb/venv/bin/pip install --require-hashes -r requirements.lock
python tools/shadowbench/synthetic/fetch_code.py /opt/nsb/checkouts
sudo python -m tools.shadowbench.synthetic run --corpus benchmarks/shadowbench/synthetic/corpus.json \
    --tools /opt/nsb/tools.json --checkouts /opt/nsb/checkouts --out /opt/nsb/results --workers 3
python -m tools.shadowbench.synthetic score --corpus benchmarks/shadowbench/synthetic/corpus.json \
    --results /opt/nsb/results --out /opt/nsb/results/metrics.json
python -m tools.shadowbench.synthetic report --corpus benchmarks/shadowbench/synthetic/corpus.json \
    --metrics /opt/nsb/results/metrics.json --out /opt/nsb/results/REPORT.md
```

`fetch_code.py` fetches the 26 pinned code-surface repositories with the
discovery benchmark's fetcher (detached checkouts at the pinned commits; only
`git` runs). `run` records the corpus SHA-256, the generator digest, the
platform and each tool's version in `manifest.json`; `score` copies them into
`metrics.json`, so a report always names the exact inputs and code it describes.

## Adding a tool

Write `adapters/<tool>.py` with a class that has `name`, `display`,
`surfaces` (surface to the set of modalities it handles), and the methods
`unavailable_reason`, `version`, `invocations` and `normalize` from
`contract.Adapter`; export it as `ADAPTER`. The runner executes the
invocations; `normalize` maps the tool's own output onto entity keys and never
interprets beyond it. Put the exact command line and the mapping rule in the
docstring, pin the version, and commit the adapter before running it on the
scored corpus. Calibrate on a different seed (`generate --seed 1 --per-surface 4`).
