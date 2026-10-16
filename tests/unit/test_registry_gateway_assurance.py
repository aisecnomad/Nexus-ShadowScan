"""An unauthenticated gateway caller can suggest a card, never inherit its approval."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.config import ScanConfig
from shadowscan.engine import Engine
from shadowscan.fleet import merge_reports
from shadowscan.models import Finding, Kind, Surface
from shadowscan.registry import Inventory, InventoryEntry

TAG = "registry-identity-unverified"


def _gateway_finding(assurance: Any, resource: str = "principal:svc-ops") -> Finding:
    observations = [] if assurance is None else [{"identity_assurance": assurance, "events": 1}]
    return Finding(
        surface=Surface.GATEWAY,
        connector="gateway.logs",
        kind=Kind.GATEWAY_CALLER,
        title="Agentic caller: svc-ops",
        resource=resource,
        resource_type="caller/principal",
        metadata={"runtime_observations": observations},
    )


def _inventory(resource: str = "principal:svc-ops") -> Inventory:
    return Inventory([InventoryEntry(agent_id="svc-ops-approved", owner="platform", resources=[resource])])


@pytest.mark.parametrize("assurance", ["operator-asserted", "unverified"])
def test_unauthenticated_gateway_caller_match_is_only_a_candidate(assurance):
    finding = _gateway_finding(assurance)

    entry = _inventory().match(finding)

    assert entry is None
    assert finding.metadata["registry_suggestions"] == ["svc-ops-approved"]
    assert finding.metadata["registry_match_reason"] == "unverified-gateway-caller-identity"
    assert finding.metadata["registry_match_assurance"] == assurance
    assert TAG in finding.tags


def test_weakest_observation_assurance_is_reported():
    finding = _gateway_finding("provider-authenticated-field")
    finding.metadata["runtime_observations"].append({"identity_assurance": "operator-asserted"})

    assert _inventory().match(finding) is None
    assert finding.metadata["registry_match_assurance"] == "operator-asserted"


@pytest.mark.parametrize(
    "observations",
    [
        None,
        [],
        "garbage",
        [{"events": 1}],
        [{"identity_assurance": 7}],
        [{"identity_assurance": []}],
        [{"identity_assurance": {}}],
        [{"identity_assurance": "provider-authenticated-field"}, None],
        [{"identity_assurance": "provider-authenticated-field"}, {"events": 1}],
        [{"identity_assurance": "provider-authenticated-field"}, {"identity_assurance": "unverified"}],
    ],
)
def test_missing_or_malformed_assurance_counts_as_unverified(observations):
    finding = _gateway_finding(None)
    finding.metadata["runtime_observations"] = observations

    assert _inventory().match(finding) is None
    assert finding.metadata["registry_match_assurance"] == "unverified"


def test_provider_authenticated_caller_is_not_flagged():
    finding = _gateway_finding("provider-authenticated-field")

    assert _inventory().match(finding) is not None
    assert "registry_match_assurance" not in finding.metadata and TAG not in finding.tags


def test_non_gateway_findings_are_not_flagged():
    finding = Finding(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.AGENT,
        title="Agent",
        resource="github:acme/ops",
        resource_type="repository",
    )

    assert _inventory("github:acme/ops").match(finding) is not None
    assert "registry_match_assurance" not in finding.metadata and TAG not in finding.tags


def test_marker_is_cleared_when_a_later_match_no_longer_qualifies():
    finding = _gateway_finding("operator-asserted")
    assert _inventory().match(finding) is None and TAG in finding.tags

    # Reconciling the same object again must not keep a stale marker.
    assert _inventory("principal:other").match(finding) is None
    assert "registry_match_assurance" not in finding.metadata and TAG not in finding.tags


def test_unmatched_gateway_finding_stays_shadow_and_unmarked():
    finding = _gateway_finding("operator-asserted", resource="principal:rogue")

    assert _inventory().match(finding) is None
    assert "registry_match_assurance" not in finding.metadata and TAG not in finding.tags


def _write_gateway_log(log: Path, caller: str) -> None:
    log.write_text(
        json.dumps(
            {
                "service": caller,
                "user_agent": "autogen/0.4",
                "model": "gpt-4o",
                "timestamp": "2026-09-22T10:00:00Z",
                "tools": [{"name": "shell"}],
            }
        )
        + "\n",
        encoding="utf-8",
    )


def test_caller_name_cannot_lower_risk_or_bypass_fail_on(tmp_path: Path):
    inventory = tmp_path / "inventory.yaml"
    inventory.write_text(
        "agents:\n  - id: svc-ops-approved\n    owner: platform\n    resources: ['principal:svc-ops']\n",
        encoding="utf-8",
    )
    findings = []
    for caller in ("rogue", "svc-ops"):
        log, out = tmp_path / f"{caller}.jsonl", tmp_path / f"{caller}.json"
        _write_gateway_log(log, caller)
        result = CliRunner().invoke(
            main,
            ["gateway", str(log), "-i", str(inventory), "-f", "json", "-o", str(out), "--fail-on", "high"],
        )
        assert result.exit_code == 2, result.output
        finding = json.loads(out.read_text(encoding="utf-8"))["findings"][0]
        assert finding["shadow"] is True and finding["registry_match"] is None
        assert finding["owner"] is None
        assert not any(factor["id"] == "registered" for factor in finding["risk"]["factors"])
        findings.append(finding)
    assert findings[0]["risk"] == findings[1]["risk"]
    assert findings[1]["metadata"]["registry_match_assurance"] == "operator-asserted"
    assert findings[1]["metadata"]["registry_suggestions"] == ["svc-ops-approved"]
    assert TAG in findings[1]["tags"]


@pytest.mark.parametrize("assurance", ["operator-asserted", "unverified", None])
def test_candidate_never_inherits_card_facts_or_risk_credit(tmp_path: Path, index, assurance):
    inventory = tmp_path / "inventory.yaml"
    inventory.write_text(
        "schema_version: 2\nmetadata:\n  agent_id: svc-ops-approved\n  owner: platform\n"
        "autonomy_profile:\n  level: 4\ngovernance:\n  eu_ai_act_risk_class: high\n"
        "discovery:\n  resources: ['principal:svc-ops']\n",
        encoding="utf-8",
    )
    engine = Engine(ScanConfig(inventory=[str(inventory)]), index)
    finding = _gateway_finding(assurance)
    engine._reconcile_and_score([finding])
    assert finding.shadow is True and finding.registry_match is None
    assert finding.owner is None
    assert "declared_governance" not in finding.metadata
    assert "declared" not in finding.metadata["autonomy"]
    assert "registered" not in {factor.id for factor in finding.risk.factors}


def test_authenticated_scoped_caller_keeps_approval_and_card_owner(tmp_path: Path, index):
    inventory = tmp_path / "inventory.yaml"
    inventory.write_text(
        "agents:\n  - id: svc-ops-approved\n    owner: platform\n"
        "    resources: ['principal:svc-ops']\n    accounts: ['tenant-a']\n",
        encoding="utf-8",
    )
    engine = Engine(ScanConfig(inventory=[str(inventory)]), index)
    finding = _gateway_finding("provider-authenticated-field")
    finding.account = "tenant-a"
    engine._reconcile_and_score([finding])
    assert finding.shadow is False and finding.registry_match == "svc-ops-approved"
    assert finding.owner == "platform" and TAG not in finding.tags
    finding.account, finding.owner = "tenant-b", None
    engine._reconcile_and_score([finding])
    assert finding.shadow is True and finding.registry_match is None and finding.owner is None


def test_fleet_merge_preserves_candidate_assurance_without_registration(tmp_path: Path):
    source = tmp_path / "gateway.jsonl"
    _write_gateway_log(source, "svc-ops")
    inventory = tmp_path / "inventory.yaml"
    inventory.write_text(
        "agents:\n  - id: svc-ops-approved\n    owner: platform\n    resources: ['principal:svc-ops']\n",
        encoding="utf-8",
    )
    output = tmp_path / "report.json"
    result = CliRunner().invoke(
        main, ["gateway", str(source), "-i", str(inventory), "-f", "json", "-o", str(output)]
    )
    assert result.exit_code == 0, result.output
    [finding] = merge_reports([("gateway", json.loads(output.read_text(encoding="utf-8")))]).findings
    assert finding.shadow is True and finding.registry_match is None and finding.owner is None
    assert finding.metadata["registry_suggestions"] == ["svc-ops-approved"]
    assert finding.metadata["registry_match_reason"] == "unverified-gateway-caller-identity"
    assert finding.metadata["registry_match_assurance"] == "operator-asserted"
    assert TAG in finding.tags
