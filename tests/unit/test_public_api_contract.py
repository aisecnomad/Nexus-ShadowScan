from __future__ import annotations

import inspect
import json

import pytest

from shadowscan import api
from shadowscan.cli import _exit_code, main
from shadowscan.errors import SetupError
from shadowscan.models import ScanStats


def test_candidate_api_exports_and_call_signature():
    assert set(api.__all__) == {
        "ConnectorSpec",
        "Evidence",
        "Finding",
        "Kind",
        "Risk",
        "RiskLevel",
        "ScanConfig",
        "ScanResult",
        "SetupError",
        "Surface",
        "scan",
    }
    signature = inspect.signature(api.scan)
    assert list(signature.parameters) == ["config"]
    assert signature.parameters["config"].default is inspect.Parameter.empty


def test_public_scan_keeps_scope_findings_and_json_contract(tmp_path):
    (tmp_path / "requirements.txt").write_text("langchain==0.3.0\n")
    config = api.ScanConfig(
        connectors=[
            api.ConnectorSpec("code.filesystem", {"paths": [str(tmp_path)], "use_git": False}),
        ]
    )
    result = api.scan(config)
    document = json.loads(result.to_json())
    assert result.complete
    assert document["summary"]["complete"] is True
    assert document["findings"]
    assert {
        "version",
        "finding_identity_schema",
        "collection_scope",
        "stats",
        "summary",
        "findings",
    } <= document.keys()
    assert all({"id", "surface", "kind", "risk", "evidence"} <= f.keys() for f in document["findings"])


def test_public_api_does_not_hide_setup_errors(monkeypatch):
    def fail(self):
        raise SetupError("synthetic setup failure")

    monkeypatch.setattr("shadowscan.engine.Engine.run", fail)
    with pytest.raises(SetupError):
        api.scan(api.ScanConfig(connectors=[]))


def test_public_api_refuses_an_unenforced_process_deadline():
    with pytest.raises(api.SetupError, match="CLI process deadline"):
        api.scan(api.ScanConfig(connectors=[], job_deadline_seconds=1))


def test_triage_command_compatibility_export():
    from shadowscan.cli import triage_command

    assert triage_command is main.commands["triage"]


def test_candidate_cli_scan_exit_contract_and_existing_entry_points():
    assert {
        "code",
        "scan",
        "run",
        "endpoint",
        "gateway",
        "jwt",
        "merge",
        "dashboard",
        "diff",
        "controls",
        "inventory",
        "mcp-registry",
        "signatures",
        "connectors",
        "triage",
    } <= main.commands.keys()
    complete = api.ScanResult(
        findings=[
            api.Finding(
                surface=api.Surface.CODE,
                kind=api.Kind.AGENT,
                connector="code.filesystem",
                resource_type="repository",
                title="synthetic",
                resource="service",
                risk=api.Risk(score=80, level=api.RiskLevel.HIGH),
            )
        ],
        stats=[ScanStats(started_at="2026-10-20T09:00:00+00:00", connector="code.filesystem")],
    )
    assert _exit_code(complete, None) == 0
    assert _exit_code(complete, "high") == 2
    complete.stats[0].incomplete = True
    assert _exit_code(complete, None) == 3
    assert _exit_code(complete, "high") == 3
