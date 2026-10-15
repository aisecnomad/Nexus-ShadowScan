"""Open Shadow AI community scanner on the saas surface (Slack and GitHub app inventories).

Build (checkout of github.com/open-shadow-ai/osa at commit 9e1b3c7a4d2f,
go.mod ``go 1.24.0``; installs with ``go install``)::

    CGO_ENABLED=0 go build -trimpath -o <tool_root>/bin/openshadowai ./cmd/openshadowai

Invocation (``HOME`` set to the work directory; the tool reads no home
configuration)::

    openshadowai scan --input <inputs> --output <work>/osa.json --format json

The tool reads the SaaS export files under ``inputs/``: for the ``slack-export``
modality it reads ``slack/admin.apps.approved.list.json``,
``slack/admin.apps.requests.list.json`` and ``slack/users.list.json``; for
``github-export`` it reads ``github/installations.json``. Exit code 0 is a
completed scan; any other exit code is an error.

Output: a JSON object with an ``apps`` array, each element carrying ``id``
(the Slack app id or GitHub app slug), ``name``, ``source`` (``slack`` or
``github``), ``ai_signals`` (list of signal names), and ``label`` (``agent``,
``llm`` or ``none``). A signal-less app has label ``none`` and is a decoy.
An empty ``apps`` array is a valid empty result (no AI apps found).

Detection rule: every app with a non-``none`` label maps to ``app:<id>`` with
the tool's own label. Apps whose ``id`` is empty or missing are dropped and
counted in the note.

Fail closed: stdout or the output file without a JSON object, or an ``apps``
entry that is not an object, is an error, never an empty inventory.

``version()`` runs ``openshadowai --version`` through ``_probe`` (scrubbed
environment, throwaway home, timeout) unless ``tools.json`` pins a version.
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

BIN = "openshadowai"
REPORT = "osa.json"
RAW_LIMIT = 200_000


class OpenShadowAI:
    name = "openshadowai"
    display = "Open Shadow AI (community scanner)"
    surfaces: Mapping[str, frozenset[str]] = {
        "saas": frozenset({"slack-export", "github-export"}),
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
        binary = env.binary(BIN) or BIN
        argv = (
            binary,
            "scan",
            "--input",
            str(case.inputs),
            "--output",
            str(work / REPORT),
            "--format",
            "json",
        )
        return [Invocation(argv=argv, cwd=work, env=base_env(case.home or work, work), timeout=300)]

    def normalize(self, case: MaterializedCase, work: Path, runs: list[RunResult]) -> AdapterResult:
        if not runs:
            return AdapterResult(status="error", note="openshadowai did not run")
        run = runs[0]
        raw: dict[str, Any] = {"stdout": run.stdout[:RAW_LIMIT], "stderr": run.stderr[-RAW_LIMIT:]}
        if run.timed_out:
            return AdapterResult(status="error", note=f"timeout after {run.seconds:.0f}s", raw=raw)
        report_path = work / REPORT
        if run.code != 0:
            return AdapterResult(
                status="error", note=f"openshadowai exit {run.code}: {tail(run.stderr or run.stdout)}", raw=raw
            )
        if not report_path.exists():
            return AdapterResult(
                status="error", note=f"openshadowai exited 0 but wrote no {REPORT}", raw=raw
            )
        try:
            doc = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return AdapterResult(status="error", note=f"{REPORT} is unreadable: {exc}", raw=raw)
        if not isinstance(doc, dict):
            return AdapterResult(status="error", note=f"{REPORT} is not a JSON object", raw=raw)
        apps = doc.get("apps")
        if not isinstance(apps, list):
            return AdapterResult(status="error", note=f"{REPORT} has no 'apps' array", raw=raw)
        if not all(isinstance(a, dict) for a in apps):
            return AdapterResult(
                status="error", note=f"{REPORT} has an app entry that is not an object", raw=raw
            )
        entities: dict[str, Entity] = {}
        dropped = 0
        for app in apps:
            label = str(app.get("label") or "none")
            if label == "none":
                continue
            app_id = app.get("id")
            if not isinstance(app_id, str) or not app_id:
                dropped += 1
                continue
            key = f"app:{app_id}"
            if key in entities:
                continue
            entities[key] = Entity(
                kind="app",
                key=key,
                label=label,
                attributes={
                    "name": str(app.get("name") or ""),
                    "source": str(app.get("source") or ""),
                    "ai_signals": app.get("ai_signals") or [],
                },
            )
        note = f"apps={len(apps)} entities={len(entities)} dropped_no_id={dropped}"
        return AdapterResult(status="ok", entities=list(entities.values()), note=note, raw=raw)


ADAPTER = OpenShadowAI()
