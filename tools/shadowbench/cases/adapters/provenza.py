"""Provenza cloud scanner (Spectro Labs) on the cloud surface (AWS and Kubernetes).

Build (checkout of github.com/spectrolabs/provenza at commit 4f8d2a1b6c3e,
go.mod ``go 1.24.0``; installs with ``go build``)::

    CGO_ENABLED=0 go build -trimpath -o <tool_root>/bin/provenza ./cmd/provenza

Invocation (``HOME`` set to the work directory; the tool reads no home or
cloud credentials, operating entirely on exported data)::

    provenza scan --input <inputs> --output <work>/provenza.json --format json

The tool reads the cloud export files under ``inputs/``: for the ``aws-export``
modality it reads the ``aws/`` directory tree of AWS CLI JSON outputs; for
``k8s-export`` it reads ``kubernetes/workloads.json`` (a ``kubectl get`` List).
Exit code 0 is a completed scan; any other exit code is an error.

Output: a JSON object with a ``resources`` array. Each element carries ``id``
(the resource's ARN for AWS or ``<namespace>/<Kind>/<name>`` for Kubernetes),
``type`` (``aws`` or ``k8s``), ``name`` (display name), ``ai_indicators``
(list of indicator names such as ``bedrock-agent``, ``sagemaker-model``,
``ml-container``), and ``label`` (``agent``, ``llm`` or ``none``). A
resource with no AI indicators has label ``none`` and is a decoy. An empty
``resources`` array is a valid empty result (no AI/ML workloads found).

Detection rule: each resource with a non-``none`` label maps to
``resource:<ARN>`` (for ``type`` ``aws``) or
``k8s:<namespace>/<Kind>/<name>`` (for ``type`` ``k8s``) with the tool's own
label. Resources whose ``id`` is empty or missing are dropped and counted in
the note.

Fail closed: a missing, empty or unparseable report after exit 0, or a
resources entry that is not an object, is an error, never an empty inventory.

``version()`` runs ``provenza --version`` through ``_probe`` (scrubbed
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

BIN = "provenza"
REPORT = "provenza.json"
RAW_LIMIT = 200_000


def _entity_key(resource: dict[str, Any]) -> str | None:
    """Map a resource record to its entity key: ``resource:<ARN>`` or ``k8s:<ns>/<Kind>/<name>``."""
    resource_id = resource.get("id")
    if not isinstance(resource_id, str) or not resource_id:
        return None
    rtype = str(resource.get("type") or "")
    if rtype == "aws":
        return f"resource:{resource_id}"
    if rtype == "k8s":
        return f"k8s:{resource_id}"
    return None


class ProvenzaAdapter:
    name = "provenza"
    display = "Provenza (Spectro Labs cloud scanner)"
    surfaces: Mapping[str, frozenset[str]] = {
        "cloud": frozenset({"aws-export", "k8s-export"}),
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
            return AdapterResult(status="error", note="provenza did not run")
        run = runs[0]
        raw: dict[str, Any] = {"stdout": run.stdout[:RAW_LIMIT], "stderr": run.stderr[-RAW_LIMIT:]}
        if run.timed_out:
            return AdapterResult(status="error", note=f"timeout after {run.seconds:.0f}s", raw=raw)
        report_path = work / REPORT
        if run.code != 0:
            return AdapterResult(
                status="error", note=f"provenza exit {run.code}: {tail(run.stderr or run.stdout)}", raw=raw
            )
        if not report_path.exists():
            return AdapterResult(
                status="error", note=f"provenza exited 0 but wrote no {REPORT}", raw=raw
            )
        try:
            doc = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return AdapterResult(status="error", note=f"{REPORT} is unreadable: {exc}", raw=raw)
        if not isinstance(doc, dict):
            return AdapterResult(status="error", note=f"{REPORT} is not a JSON object", raw=raw)
        resources = doc.get("resources")
        if not isinstance(resources, list):
            return AdapterResult(status="error", note=f"{REPORT} has no 'resources' array", raw=raw)
        if not all(isinstance(r, dict) for r in resources):
            return AdapterResult(
                status="error", note=f"{REPORT} has a resource entry that is not an object", raw=raw
            )
        entities: dict[str, Entity] = {}
        dropped = 0
        for resource in resources:
            label = str(resource.get("label") or "none")
            if label == "none":
                continue
            key = _entity_key(resource)
            if key is None:
                dropped += 1
                continue
            if key in entities:
                current = entities[key]
                if current.label == "agent" or (current.label == label):
                    continue
            entities[key] = Entity(
                kind="resource",
                key=key,
                label=label,
                attributes={
                    "name": str(resource.get("name") or ""),
                    "type": str(resource.get("type") or ""),
                    "ai_indicators": resource.get("ai_indicators") or [],
                },
            )
        note = f"resources={len(resources)} entities={len(entities)} dropped_no_id={dropped}"
        return AdapterResult(status="ok", entities=list(entities.values()), note=note, raw=raw)


ADAPTER = ProvenzaAdapter()
