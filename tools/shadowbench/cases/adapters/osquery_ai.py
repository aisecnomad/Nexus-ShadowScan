"""osquery (Meta/Kolide) interactive shell for AI process discovery on runtime/snapshot.

Binary: ``osqueryi`` (the interactive osquery shell, distributed as part of the
osquery package from github.com/osquery/osquery or via
``apt install osquery`` / ``brew install osquery``).

Invocation (a single SQL query against the ``processes`` table; ``--json``
emits one JSON array of row objects to stdout)::

    osqueryi --json "SELECT pid,name,path,cmdline FROM processes
        WHERE name LIKE '%ollama%' OR name LIKE '%vllm%'
        OR cmdline LIKE '%langchain%' OR cmdline LIKE '%autogen%'
        OR cmdline LIKE '%crewai%' OR cmdline LIKE '%litellm%'
        OR cmdline LIKE '%langserve%' OR cmdline LIKE '%llama_cpp%'
        OR cmdline LIKE '%triton%' OR cmdline LIKE '%mlflow%'
        OR cmdline LIKE '%langflow%' OR cmdline LIKE '%dify%'
        OR cmdline LIKE '%openwebui%' OR cmdline LIKE '%text-generation%'
        OR cmdline LIKE '%koboldcpp%' OR cmdline LIKE '%localai%'
        OR cmdline LIKE '%lmdeploy%' OR cmdline LIKE '%sglang%'
        OR name LIKE '%mcp%' OR cmdline LIKE '%mcp-server%'
        OR cmdline LIKE '%modelcontextprotocol%'"

On the runtime/snapshot surface the runner provides
``osquery_processes.json`` (a pre-captured ``osqueryi --json`` result) and
``osqueryd_results.jsonl`` (result-log lines) under ``inputs/``.  This
adapter does not read those files: it runs osqueryi directly against the
live process table in the tool's PID namespace, where the runner has
spawned the case's processes.  The ``WHERE`` clause covers common AI model
servers, agent frameworks, MCP processes and LLM gateways.

Output: a JSON array of row objects, each with string-valued ``pid``,
``name``, ``path`` and ``cmdline`` columns::

    [{"pid": "42", "name": "ollama", "path": "/usr/bin/ollama",
      "cmdline": "ollama serve"}, ...]

``[]`` and exit 0 when no process matches.

Fail closed: empty stdout or output that is not a JSON array of objects is
an error, never an empty inventory.  A working query against a PID
namespace that has processes always returns at least ``[]``.

Mapping: each row with a non-zero ``pid`` maps to ``process:<pid>``.
The label is determined by the process name and command line:

* ``agent``: name or cmdline contains ``crewai``, ``autogen``, ``langchain``,
  ``langserve``, ``langflow``, ``dify``, ``mcp``, ``modelcontextprotocol``.
* ``llm``: name or cmdline contains ``ollama``, ``vllm``, ``litellm``,
  ``llama_cpp``, ``triton``, ``text-generation``, ``koboldcpp``, ``localai``,
  ``lmdeploy``, ``sglang``, ``openwebui``.
* ``ai``: name or cmdline contains ``mlflow`` or other AI tooling not
  classified above.

The strongest label wins when a process matches multiple patterns
(``agent`` > ``llm`` > ``ai``).

``version()`` runs ``osqueryi --version`` through ``_probe`` (scrubbed
environment, throwaway home, timeout).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from tools.shadowbench.cases.adapters._probe import cli_version
from tools.shadowbench.cases.contract import (
    AdapterResult,
    Entity,
    Invocation,
    MaterializedCase,
    RunResult,
    ToolEnv,
    base_env,
    tail,
)

TOOL = "osquery-ai"
BIN = "osqueryi"

AGENT_PATTERNS = frozenset(
    {
        "crewai",
        "autogen",
        "langchain",
        "langgraph",
        "langserve",
        "langflow",
        "dify",
        "flowise",
        "mcp-server",
        "mcp_server",
        "modelcontextprotocol",
        "n8n",
        "superagi",
        "autogpt",
        "pipecat",
        "hayhooks",
        "langroid",
        "praisonai",
    }
)
LLM_PATTERNS = frozenset(
    {
        "ollama",
        "vllm",
        "litellm",
        "llama_cpp",
        "llama-cpp",
        "llama.cpp",
        "triton",
        "text-generation",
        "koboldcpp",
        "localai",
        "lmdeploy",
        "sglang",
        "openwebui",
        "open-webui",
        "tgi",
        "xinference",
        "aphrodite",
        "lollms",
        "jan",
        "gpt4all",
        "lm-studio",
        "tabbyapi",
    }
)
AI_PATTERNS = frozenset(
    {
        "mlflow",
        "langfuse",
        "chroma",
        "milvus",
        "qdrant",
        "weaviate",
        "comfyui",
        "axolotl",
        "llamafactory",
    }
)

_RANK = {"agent": 2, "llm": 1, "ai": 0}

# The SQL query covers the most common AI process names and command-line markers.
_QUERY = (
    "SELECT pid,name,path,cmdline FROM processes"
    " WHERE name LIKE '%ollama%' OR name LIKE '%vllm%'"
    " OR cmdline LIKE '%langchain%' OR cmdline LIKE '%autogen%'"
    " OR cmdline LIKE '%crewai%' OR cmdline LIKE '%litellm%'"
    " OR cmdline LIKE '%langserve%' OR cmdline LIKE '%llama_cpp%'"
    " OR cmdline LIKE '%triton%' OR cmdline LIKE '%mlflow%'"
    " OR cmdline LIKE '%langflow%' OR cmdline LIKE '%dify%'"
    " OR cmdline LIKE '%openwebui%' OR cmdline LIKE '%text-generation%'"
    " OR cmdline LIKE '%koboldcpp%' OR cmdline LIKE '%localai%'"
    " OR cmdline LIKE '%lmdeploy%' OR cmdline LIKE '%sglang%'"
    " OR name LIKE '%mcp%' OR cmdline LIKE '%mcp-server%'"
    " OR cmdline LIKE '%modelcontextprotocol%'"
)


def _classify(name: str, cmdline: str) -> str | None:
    """Classify a process by its name and command line; None when not AI-related."""
    text = f"{name} {cmdline}".lower()
    for pattern in AGENT_PATTERNS:
        if pattern in text:
            return "agent"
    for pattern in LLM_PATTERNS:
        if pattern in text:
            return "llm"
    for pattern in AI_PATTERNS:
        if pattern in text:
            return "ai"
    return None


class OsqueryAIAdapter:
    name = TOOL
    display = "osquery AI process discovery (Meta/Kolide)"
    surfaces: Mapping[str, frozenset[str]] = {"runtime": frozenset({"snapshot"})}

    def unavailable_reason(self, env: ToolEnv) -> str | None:
        return None if env.binary(BIN) else f"no 'bin' configured for {BIN}"

    def version(self, env: ToolEnv) -> str:
        binary = env.binary(BIN)
        return cli_version(binary) if binary else "unknown"

    def invocations(self, case: MaterializedCase, env: ToolEnv, work: Path) -> list[Invocation]:
        argv = (
            env.binary(BIN) or BIN,
            "--json",
            _QUERY,
        )
        return [Invocation(argv=argv, cwd=work, env=base_env(case.home or work, work), timeout=120)]

    def normalize(self, case: MaterializedCase, work: Path, runs: list[RunResult]) -> AdapterResult:
        if not runs:
            return AdapterResult(status="error", note="osqueryi did not run")
        run = runs[0]
        if run.timed_out:
            return AdapterResult(status="error", note="osqueryi query timed out")
        if run.code != 0:
            return AdapterResult(
                status="error", note=f"osqueryi exit {run.code}: {tail(run.stderr)}"
            )
        if not run.stdout.strip():
            return AdapterResult(status="error", note=f"osqueryi printed nothing: {tail(run.stderr)}")
        try:
            data = json.loads(run.stdout)
        except json.JSONDecodeError as exc:
            return AdapterResult(status="error", note=f"osqueryi output is not JSON: {exc}")
        if not isinstance(data, list):
            return AdapterResult(status="error", note="osqueryi output is not a JSON array")
        if not all(isinstance(row, dict) for row in data):
            return AdapterResult(status="error", note="osqueryi output has a row that is not an object")
        entities: dict[str, Entity] = {}
        for row in data:
            pid = _pid(row.get("pid"))
            if pid <= 0:
                continue
            name = str(row.get("name") or "")
            cmdline = str(row.get("cmdline") or "")
            label = _classify(name, cmdline)
            if label is None:
                continue
            key = f"process:{pid}"
            current = entities.get(key)
            if current is not None and _RANK.get(current.label, 0) >= _RANK.get(label, 0):
                continue
            entities[key] = Entity(
                kind="process",
                key=key,
                label=label,
                attributes={
                    "name": name,
                    "path": str(row.get("path") or ""),
                    "cmdline": cmdline[:500],
                },
            )
        return AdapterResult(
            status="ok",
            entities=list(entities.values()),
            raw={"rows": data[:400]},
        )


def _pid(value: Any) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


ADAPTER = OsqueryAIAdapter()
