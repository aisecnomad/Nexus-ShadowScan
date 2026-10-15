"""shadow-ai-detector static analysis on the code/checkout surface.

Build (PyPI ``shadow-ai-detector``, console script ``shadow-ai-detector``)::

    pip install shadow-ai-detector

Invocation (``HOME`` set to the work directory; the tool reads no home
configuration)::

    shadow-ai-detector scan --path <repo> --output <work>/sad.json --format json

The tool walks the repository working tree and matches source files against
rules for AI/ML framework usage (imports, configuration references, agent
patterns). Exit code 0 is a completed scan with or without findings; any other
exit code is an error.

Output: a JSON object with a ``findings`` array. Each finding carries
``name`` (the framework or library name, e.g. ``LangChain Agent``,
``CrewAI``, ``OpenAI client``), ``file`` (repo-relative path),
``line`` (integer), ``category`` (``framework``, ``provider``, ``agent``),
and ``confidence`` (``high``, ``medium``, ``low``). An empty ``findings``
array is a valid empty result (no AI/ML code detected).

Detection rules (code surface): each finding's ``name`` is mapped onto
taxonomy facts with ``taxonomy.facts_from_name``. ``provider:*`` facts are
labelled ``llm``; all other facts (``framework:*``, ``mcp-client-config:*``,
``agent-config:*``, ``a2a:*``) are labelled ``agent``. A finding that maps to
no fact is dropped, counted in the row's ``out_of_taxonomy`` and, with its
file, listed in the note's ``unmapped`` list: code truth holds only taxonomy
facts, so any other key could never match, but the scorer still counts the
hit as an alarm on a negative case.

Fail closed: a missing, empty or unparseable report after exit 0, or a
findings entry that is not an object, is an error, never an empty inventory.

``version()`` runs ``shadow-ai-detector --version`` through ``_probe``
(scrubbed environment, throwaway home, timeout) unless ``tools.json`` pins a
version.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from tools.discovery_benchmark import taxonomy
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

BIN = "shadow-ai-detector"
REPORT = "sad.json"
RAW_LIMIT = 200_000


def _fact_label(fact: str) -> str:
    return "llm" if fact.startswith("provider:") else "agent"


class ShadowAIDetector:
    name = "shadow-ai-detector"
    display = "shadow-ai-detector (code scanner)"
    surfaces: Mapping[str, frozenset[str]] = {
        "code": frozenset({"checkout"}),
    }

    def unavailable_reason(self, env: ToolEnv) -> str | None:
        binary = env.binary(BIN)
        if not binary:
            return f"no 'bin' configured for {BIN} in tools.json"
        if not Path(binary).exists():
            return f"{binary} does not exist"
        return None

    def version(self, env: ToolEnv) -> str:
        pinned = env.tool(BIN).get("version")
        if isinstance(pinned, str) and pinned:
            return pinned
        binary = env.binary(BIN)
        return cli_version(binary) if binary else "unknown"

    def invocations(self, case: MaterializedCase, env: ToolEnv, work: Path) -> list[Invocation]:
        repo = case.inputs / "repo"
        binary = env.binary(BIN) or BIN
        argv = (
            binary,
            "scan",
            "--path",
            str(repo),
            "--output",
            str(work / REPORT),
            "--format",
            "json",
        )
        return [Invocation(argv=argv, cwd=work, env=base_env(case.home or work, work), timeout=300)]

    def normalize(self, case: MaterializedCase, work: Path, runs: list[RunResult]) -> AdapterResult:
        if not runs:
            return AdapterResult(status="error", note="shadow-ai-detector did not run")
        run = runs[0]
        raw: dict[str, Any] = {"stdout": run.stdout[:RAW_LIMIT], "stderr": run.stderr[-RAW_LIMIT:]}
        if run.timed_out:
            return AdapterResult(status="error", note=f"timeout after {run.seconds:.0f}s", raw=raw)
        report_path = work / REPORT
        if run.code != 0:
            return AdapterResult(
                status="error",
                note=f"shadow-ai-detector exit {run.code}: {tail(run.stderr or run.stdout)}",
                raw=raw,
            )
        if not report_path.exists():
            return AdapterResult(
                status="error", note=f"shadow-ai-detector exited 0 but wrote no {REPORT}", raw=raw
            )
        try:
            doc = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return AdapterResult(status="error", note=f"{REPORT} is unreadable: {exc}", raw=raw)
        if not isinstance(doc, dict):
            return AdapterResult(status="error", note=f"{REPORT} is not a JSON object", raw=raw)
        findings = doc.get("findings")
        if not isinstance(findings, list):
            return AdapterResult(status="error", note=f"{REPORT} has no 'findings' array", raw=raw)
        if not all(isinstance(f, dict) for f in findings):
            return AdapterResult(
                status="error", note=f"{REPORT} has a finding that is not an object", raw=raw
            )
        entities: dict[str, Entity] = {}
        unmapped: list[str] = []
        for finding in findings:
            name = str(finding.get("name") or "")
            rel = str(finding.get("file") or "")
            facts = set(taxonomy.facts_from_name(name))
            if not facts:
                unmapped.append(rel or name)
                continue
            for fact in sorted(facts):
                label = _fact_label(fact)
                if fact in entities:
                    current = entities[fact]
                    if current.label == "agent" or (current.label == label):
                        continue
                entities[fact] = Entity(
                    kind="fact",
                    key=fact,
                    label=label,
                    attributes={
                        "path": rel,
                        "name": name,
                        "category": str(finding.get("category") or ""),
                        "confidence": str(finding.get("confidence") or ""),
                    },
                )
        note = f"findings={len(findings)} facts={sum(e.kind == 'fact' for e in entities.values())}"
        if unmapped:
            note += f" unmapped={sorted(set(unmapped))[:10]}"
        return AdapterResult(
            status="ok",
            entities=list(entities.values()),
            note=note,
            raw=raw,
            out_of_taxonomy=len(set(unmapped)),
        )


ADAPTER = ShadowAIDetector()
