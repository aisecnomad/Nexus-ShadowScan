"""Shadow AI Detection Framework on identity/okta-export and identity/entra-export.

The Shadow AI Detection Framework (``shadow-ai-detect``) scans identity
provider exports to detect OAuth applications and service principals that
integrate with AI/ML services. It reads Okta application exports and Entra
ID (Azure AD) service principal exports, matching display names, redirect
URIs, and permission grants against known AI platform patterns.

Install (PyPI ``shadow-ai-detect``)::

    pip install shadow-ai-detect

Invocation::

    shadow-ai-detect scan --input <inputs_dir> --output <work>/detect.json --format json

The tool reads Okta JSON exports (``okta/apps.json``, ``okta/grants/*.json``,
``okta/tokens/*.json``) or Entra exports (``entra/servicePrincipals.json``,
``entra/applications.json``, ``entra/oauth2PermissionGrants.json``,
``entra/appRoleAssignments.json``) depending on which files are present in
the input directory. It exits 0 on success and writes a JSON report with
detected AI applications.

Output (``detect.json``)::

    {
      "scan_type": "okta"|"entra",
      "findings": [
        {
          "app_id": "<Okta app id | Entra appId>",
          "display_name": "...",
          "classification": "agent"|"llm"|"ai"|"none",
          "confidence": 0.0-1.0,
          "evidence": ["..."]
        }
      ]
    }

Mapping: each finding with classification ``agent``, ``llm`` or ``ai`` maps to
``app:<app_id>`` with the tool's classification as the label (``ai`` is
reported as-is since the contract allows it as a reported label). Findings
with classification ``none`` are skipped. The adapter treats ``agent`` and
``llm`` directly and maps ``ai`` to the ``Reported`` type.

Fail closed: exit != 0 or a missing/unparseable report is an error. An empty
findings array after exit 0 is a legitimate empty result. ``version()`` reads
``shadow-ai-detect --version`` through ``_probe``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from tools.shadowbench.cases.adapters._probe import run_probe
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

TOOL = "shadow-ai-detect"
REPORT = "detect.json"
_VERSION_RE = re.compile(r"(\d+\.\d+\.\d+\S*)")


class ShadowAIDetectAdapter:
    name = "shadow-ai-detect"
    display = "Shadow AI Detection Framework"
    surfaces: Mapping[str, frozenset[str]] = {
        "identity": frozenset({"okta-export", "entra-export"}),
    }

    def unavailable_reason(self, env: ToolEnv) -> str | None:
        return None if env.binary(TOOL) else f"no 'bin' configured for {TOOL}"

    def version(self, env: ToolEnv) -> str:
        binary = env.binary(TOOL)
        if not binary:
            return "unknown"
        proc = run_probe([binary, "--version"])
        if proc is None:
            return "unknown"
        match = _VERSION_RE.search(proc.stdout + proc.stderr)
        return match.group(1) if match else "unknown"

    def invocations(self, case: MaterializedCase, env: ToolEnv, work: Path) -> list[Invocation]:
        binary = env.binary(TOOL) or TOOL
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
        return [Invocation(argv=argv, cwd=work, env=base_env(case.home or work, work), timeout=120)]

    def normalize(self, case: MaterializedCase, work: Path, runs: list[RunResult]) -> AdapterResult:
        if not runs:
            return AdapterResult(status="error", note="shadow-ai-detect did not run")
        run = runs[0]
        if run.timed_out:
            return AdapterResult(status="error", note="shadow-ai-detect timed out")
        if run.code != 0:
            return AdapterResult(
                status="error",
                note=f"shadow-ai-detect exit {run.code}: {tail(run.stderr or run.stdout)}",
            )
        report = work / REPORT
        if not report.exists():
            return AdapterResult(status="error", note=f"no report written to {REPORT}")
        try:
            data = json.loads(report.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return AdapterResult(status="error", note=f"cannot parse {REPORT}: {exc}")
        if not isinstance(data, dict):
            return AdapterResult(status="error", note=f"{REPORT} is not a JSON object")
        findings = data.get("findings", [])
        if not isinstance(findings, list):
            return AdapterResult(status="error", note=f"{REPORT} findings is not an array")
        entities: list[Entity] = []
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            app_id = finding.get("app_id")
            classification = finding.get("classification", "")
            if not isinstance(app_id, str) or not app_id:
                continue
            if classification not in ("agent", "llm", "ai"):
                continue
            entities.append(
                Entity(
                    kind="app",
                    key=f"app:{app_id}",
                    label=classification,
                    attributes={
                        "display_name": str(finding.get("display_name", "")),
                        "confidence": finding.get("confidence", 0),
                    },
                )
            )
        raw: dict[str, Any] = {"findings": findings[:200]}
        return AdapterResult(status="ok", entities=entities, raw=raw)


ADAPTER = ShadowAIDetectAdapter()
