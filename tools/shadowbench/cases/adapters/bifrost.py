"""Bifrost AI gateway traffic analyzer on gateway/litellm-export and gateway/bedrock-export.

Bifrost is a purpose-built LLM gateway traffic analyzer that detects shadow AI
callers by examining proxy logs and model invocation records.  It identifies
API key aliases, service principals and user-agent products making model calls
through gateway infrastructure, and classifies them as sanctioned or
unsanctioned callers.

Build (checkout of the bifrost repository; Go or Rust binary)::

    go build -trimpath -o <tool_root>/bin/bifrost ./cmd/bifrost

or a pre-built release binary placed at ``<tool_root>/bin/bifrost``.

Invocation (``--input`` is the inputs directory containing the gateway
exports; ``--output`` writes JSON results; ``--format json`` selects
machine-readable output)::

    bifrost analyze --input <inputs> --output <work>/bifrost.json --format json

On the gateway/litellm-export modality the inputs directory contains
``litellm/spend_logs.jsonl`` (one ``/spend/logs`` row per line from the
LiteLLM proxy).  On the gateway/bedrock-export modality it contains
``bedrock/model_invocation_logs.jsonl`` (CloudWatch invocation log records).
Bifrost reads both formats and correlates callers across them.

Output: a JSON object written to the output file::

    {"callers": [{"alias": "<key alias or principal>", "model": "...",
      "call_count": 42, "first_seen": "...", "last_seen": "...",
      "user_agent": "...", "sanctioned": false}, ...],
     "summary": {"total_callers": 5, "unsanctioned": 3, ...}}

Each caller object identifies a distinct API consumer by its key alias,
service principal or user-agent product string.

Fail closed: an empty or missing output file, or output that is not a JSON
object with a ``callers`` array, is an error, never an empty inventory.
``version()`` runs ``bifrost --version`` through ``_probe`` (scrubbed
environment, throwaway home, timeout).

Mapping: each caller in the output maps to ``caller:<alias>`` where
``<alias>`` is the API key alias, principal name or user-agent product
the tool identified.  The label is ``ai`` for all callers (Bifrost
detects gateway usage but does not distinguish agent from plain LLM
callers at the traffic level).  ``sanctioned`` status is recorded in
attributes but does not affect the label: both sanctioned and
unsanctioned callers are reported as entities.
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

TOOL = "bifrost"
OUTPUT = "bifrost.json"


class BifrostAdapter:
    name = TOOL
    display = "Bifrost AI gateway analyzer"
    surfaces: Mapping[str, frozenset[str]] = {
        "gateway": frozenset({"litellm-export", "bedrock-export"}),
    }

    def unavailable_reason(self, env: ToolEnv) -> str | None:
        return None if env.binary(TOOL) else f"no 'bin' configured for {TOOL}"

    def version(self, env: ToolEnv) -> str:
        binary = env.binary(TOOL)
        return cli_version(binary) if binary else "unknown"

    def invocations(self, case: MaterializedCase, env: ToolEnv, work: Path) -> list[Invocation]:
        argv = (
            env.binary(TOOL) or TOOL,
            "analyze",
            "--input",
            str(case.inputs),
            "--output",
            str(work / OUTPUT),
            "--format",
            "json",
        )
        return [Invocation(argv=argv, cwd=work, env=base_env(case.home or work, work), timeout=300)]

    def normalize(self, case: MaterializedCase, work: Path, runs: list[RunResult]) -> AdapterResult:
        if not runs:
            return AdapterResult(status="error", note="bifrost did not run")
        run = runs[0]
        if run.timed_out:
            return AdapterResult(status="error", note="bifrost analyze timed out")
        if run.code != 0:
            return AdapterResult(
                status="error", note=f"bifrost analyze exit {run.code}: {tail(run.stderr)}"
            )
        output = work / OUTPUT
        if not output.is_file():
            note = f"bifrost wrote no output file: {tail(run.stderr or run.stdout)}"
            return AdapterResult(status="error", note=note)
        try:
            text = output.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return AdapterResult(status="error", note=f"cannot read {OUTPUT}: {exc}")
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as exc:
            return AdapterResult(status="error", note=f"bifrost output is not JSON: {exc}")
        if not isinstance(doc, dict):
            return AdapterResult(status="error", note="bifrost output is not a JSON object")
        callers = doc.get("callers")
        if not isinstance(callers, list):
            return AdapterResult(status="error", note="bifrost output has no 'callers' array")
        if not all(isinstance(c, dict) for c in callers):
            return AdapterResult(
                status="error", note="bifrost output has a caller entry that is not an object"
            )
        entities: dict[str, Entity] = {}
        for caller in callers:
            alias = str(caller.get("alias") or caller.get("principal") or caller.get("user_agent") or "")
            if not alias:
                continue
            key = f"caller:{alias}"
            if key in entities:
                continue
            entities[key] = Entity(
                kind="caller",
                key=key,
                label="ai",
                attributes={
                    "alias": alias,
                    "model": str(caller.get("model") or ""),
                    "call_count": caller.get("call_count", 0),
                    "first_seen": str(caller.get("first_seen") or ""),
                    "last_seen": str(caller.get("last_seen") or ""),
                    "user_agent": str(caller.get("user_agent") or ""),
                    "sanctioned": bool(caller.get("sanctioned")),
                },
            )
        summary = doc.get("summary")
        raw: dict[str, Any] = {"callers": callers[:400]}
        if isinstance(summary, dict):
            raw["summary"] = summary
        return AdapterResult(status="ok", entities=list(entities.values()), raw=raw)


ADAPTER = BifrostAdapter()
