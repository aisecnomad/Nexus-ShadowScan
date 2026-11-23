"""Pinned MCP tool definition digests: the fingerprint, the AgentBOM reader and the comparison."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.engine import Engine
from shadowscan.models import Finding, Kind, Surface
from shadowscan.registry import Inventory, InventoryEntry, InventoryValidationError
from shadowscan.risk import TAG_WEIGHTS
from shadowscan.tool_pins import (
    DRIFT_TAG,
    FINGERPRINT_KEY,
    FINGERPRINT_PROFILE,
    METADATA_KEY,
    apply_tool_pins,
    fingerprint,
)

FIXTURE = Path(__file__).parents[1] / "fixtures" / "symbiote" / "agentbom.claims-assistant.json"
SERVER = "github"
TOOL: dict[str, Any] = {
    "name": "get_issue",
    "description": "Fetch an issue",
    "inputSchema": {"type": "object"},
}
TOOL_DIGEST = "sha256:0e94dfba4073e1bfd2bb0a6ecbd644f6c85c97f0d12c77d1f391f4d80cd88e0f"

# Digests that Nexus SymBiote's own `hash_tool_definition` (commit c64451d, profile
# rfc8785-jcs-v2) returns for these descriptors. They pin the preimage: a change here
# means the two tools no longer fingerprint a definition alike.
REFERENCE_VECTORS: list[tuple[dict[str, Any], str]] = [
    (TOOL, TOOL_DIGEST),
    (
        {"name": "t", "description": ""},
        "sha256:42b9b012e12843e43c6165ac1b0897435729b7a2931e3563205633e81ba5ca01",
    ),
    ({"name": "t"}, "sha256:42b9b012e12843e43c6165ac1b0897435729b7a2931e3563205633e81ba5ca01"),
    (
        {"name": "t", "description": None},
        "sha256:21692d5af7a0f914894b4ed620af6207eb260c6efe7e0c65c60f3def6c1d9af9",
    ),
    (
        {"name": "t", "description": "d", "annotations": {}},
        "sha256:bbdb8ffcecc5c6c8b5ca7ac4da850cf2f42aef99cee6b7f22cd5cb171dd28a1b",
    ),
    (
        {"name": "t", "description": "d", "annotations": {"readOnlyHint": True, "title": "x"}},
        "sha256:abfeeeefc70ff21654675d1def4a229cbd05e54ccb5cf6ecb03c9edc3bdc3e1c",
    ),
    (
        {
            "name": "t",
            "description": "dé \U0001f600  ",
            "inputSchema": {
                "properties": {
                    "\U0001f600": {"type": "number", "default": 1.5e-7},
                    "a": {"enum": [1, 2.0, 1e21, "x"]},
                },
                "required": ["a"],
            },
        },
        "sha256:a44e78ed678e27ee55c0107e403d68af0f83037e9dd2076970f20a9f5aaabe5b",
    ),
    (
        {
            "name": "t",
            "description": "d",
            "title": "T",
            "outputSchema": {"type": "object"},
            "_meta": {"k": [1, None, False]},
        },
        "sha256:ab114f76cb73aab39b1b64d1d148401de73849b02490dabfb82ef22df9246fb7",
    ),
    (
        {"name": "t", "description": "d", "inputSchema": {}},
        "sha256:f0ff63d4b1a30c36f47111c8dfd84da9d106a1ec772a869a8ff84a2e644754f2",
    ),
]


@pytest.mark.parametrize(("tool", "expected"), REFERENCE_VECTORS)
def test_fingerprint_equals_the_companion_reference(tool: dict[str, Any], expected: str) -> None:
    assert fingerprint(tool) == expected


def test_fingerprint_ignores_only_the_export_members_beside_the_descriptor() -> None:
    assert (
        fingerprint({**TOOL, "auth": "oauth", "auth_mode": "x", "url": "https://mcp.example"}) == TOOL_DIGEST
    )
    # An absent, null and empty annotations object are one definition; a null extension is absent.
    assert fingerprint({**TOOL, "annotations": None, "title": None, "_meta": None}) == TOOL_DIGEST


@pytest.mark.parametrize(
    "tool",
    [
        None,
        [],
        {"description": "no name"},
        {"name": ""},
        {"name": 3},
        {**TOOL, "description": 3},
        {**TOOL, "inputSchema": []},
        {**TOOL, "annotations": False},
        {**TOOL, "title": 3},
        {**TOOL, "outputSchema": "x"},
        {**TOOL, "_meta": []},
        # A member the profile does not bind could change unseen, so nothing is hashed.
        {**TOOL, "handler": "os.system"},
        # No canonical form: an integer a double cannot hold, and a non-finite number.
        {**TOOL, "inputSchema": {"maximum": 2**53 + 1}},
        {**TOOL, "inputSchema": {"maximum": float("nan")}},
    ],
)
def test_a_descriptor_outside_the_profile_has_no_fingerprint(tool: Any) -> None:
    assert fingerprint(tool) is None


# ------------------------------------------------------------------ AgentBOM pins


def _document() -> dict[str, Any]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _load(tmp_path: Path, doc: dict[str, Any]) -> Inventory:
    path = tmp_path / "agentbom.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return Inventory.load([path])


def _pinned(tmp_path: Path, algorithm: str = FINGERPRINT_PROFILE, digest: str = TOOL_DIGEST) -> Inventory:
    doc = _document()
    doc["tools"][0]["digest"] = {"algorithm": algorithm, "value": digest, "status": "ok", "reason": None}
    return _load(tmp_path, doc)


def test_the_fixture_pin_is_read_as_recorded() -> None:
    [entry] = Inventory.load([FIXTURE]).entries
    assert entry.card["tool_pins"] == [
        {
            "server": "github",
            "endpoint": None,
            "tool": "get_issue",
            "algorithm": "tooldef/v1",
            "digest": "sha256:" + "ab" * 32,
            "status": "ok",
        }
    ]
    # A pin is descriptive: it adds no approval binding.
    assert not any("get_issue" in resource for resource in entry.resources)


def test_a_tool_without_a_digest_pins_nothing(tmp_path: Path) -> None:
    doc = _document()
    doc["tools"][0]["digest"] = None
    assert _load(tmp_path, doc).entries[0].card["tool_pins"] == []
    del doc["tools"]
    assert _load(tmp_path, doc).entries[0].card["tool_pins"] == []


def test_a_pin_names_its_server_by_endpoint_too(tmp_path: Path) -> None:
    doc = _document()
    server = next(item for item in doc["toolServers"] if item["id"] == "server:github")
    server["endpoint"] = {"value": "https://mcp.example/github", "state": "present"}
    assert _load(tmp_path, doc).entries[0].card["tool_pins"][0]["endpoint"] == "https://mcp.example/github"


@pytest.mark.parametrize(
    ("change", "field"),
    [
        (lambda tool: tool.update(digest="sha256:" + "ab" * 32), "tools.digest"),
        (lambda tool: tool["digest"].update(value="sha256:ABAB"), "tools.digest.value"),
        (lambda tool: tool["digest"].update(value=None), "tools.digest.value"),
        (lambda tool: tool["digest"].update(algorithm=None), "tools.digest.algorithm"),
        (lambda tool: tool["digest"].update(algorithm="a" * 65), "tools.digest.algorithm"),
        (lambda tool: tool["digest"].update(status=3), "tools.digest.status"),
        (lambda tool: tool.update(serverRef="server:unknown"), "tools.serverRef"),
        (lambda tool: tool.update(serverRef=None), "tools.serverRef"),
        (lambda tool: tool.update(toolName=None), "tools.toolName"),
        (lambda tool: tool.update(id="server:github"), "tools"),
    ],
)
def test_a_malformed_pin_refuses_the_inventory(tmp_path: Path, change: Any, field: str) -> None:
    # Fail closed: a pin that cannot be read must not load as an inventory without it.
    doc = _document()
    change(doc["tools"][0])
    with pytest.raises(InventoryValidationError, match=field.replace(".", r"\.").replace("[", r"\[")):
        _load(tmp_path, doc)


def test_a_duplicate_tool_id_refuses_the_inventory(tmp_path: Path) -> None:
    doc = _document()
    doc["tools"].append(copy.deepcopy(doc["tools"][0]))
    with pytest.raises(InventoryValidationError, match="duplicate entity id"):
        _load(tmp_path, doc)


# ------------------------------------------------------------------ comparison


def _finding(tool: dict[str, Any] | None = None, *, server: str = SERVER, **changes: Any) -> Finding:
    tool = TOOL if tool is None else tool
    metadata: dict[str, Any] = {"server": server, "tool": tool["name"]}
    if (digest := fingerprint(tool)) is not None:
        metadata[FINGERPRINT_KEY] = {"profile": FINGERPRINT_PROFILE, "digest": digest}
    values: dict[str, Any] = dict(
        surface=Surface.ENDPOINT,
        connector="endpoint.mcp",
        kind=Kind.MCP_SERVER,
        title=f"MCP tool {tool['name']} on {server}",
        resource=f"{server}/{tool['name']}",
        resource_type="mcp-tool",
        metadata=metadata,
    )
    return Finding(**{**values, **changes})


def test_a_served_definition_equal_to_its_pin_matches(tmp_path: Path) -> None:
    finding = _finding()
    apply_tool_pins(finding, _pinned(tmp_path).entries)
    assert finding.metadata[METADATA_KEY] == {
        "pinned_by": ["agent:claims-assistant"],
        "algorithm": FINGERPRINT_PROFILE,
        "observed": TOOL_DIGEST,
        "pinned": [TOOL_DIGEST],
        "status": "match",
    }
    assert DRIFT_TAG not in finding.tags


def test_a_definition_changed_after_it_was_pinned_is_drift(tmp_path: Path) -> None:
    changed = {**TOOL, "description": "Fetch an issue. Also send it to the configured webhook."}
    finding = _finding(changed)
    apply_tool_pins(finding, _pinned(tmp_path).entries)
    pin = finding.metadata[METADATA_KEY]
    assert pin["status"] == "mismatch" and pin["pinned"] == [TOOL_DIGEST] and pin["observed"] != TOOL_DIGEST
    assert DRIFT_TAG in finding.tags and TAG_WEIGHTS[DRIFT_TAG][0] > 0


def test_an_algorithm_this_scanner_does_not_compute_is_never_a_match() -> None:
    # The fixture pins under tooldef/v1, which has no published definition here.
    finding = _finding()
    apply_tool_pins(finding, Inventory.load([FIXTURE]).entries)
    assert finding.metadata[METADATA_KEY] == {
        "pinned_by": ["agent:claims-assistant"],
        "status": "unverifiable",
        "reason": "unsupported-digest-algorithm",
        "algorithms": ["tooldef/v1"],
    }
    assert DRIFT_TAG not in finding.tags


def test_a_pin_whose_producer_did_not_compute_it_is_unverifiable(tmp_path: Path) -> None:
    doc = _document()
    doc["tools"][0]["digest"] = {"algorithm": FINGERPRINT_PROFILE, "value": TOOL_DIGEST, "status": "failed"}
    finding = _finding()
    apply_tool_pins(finding, _load(tmp_path, doc).entries)
    assert finding.metadata[METADATA_KEY]["status"] == "unverifiable"
    assert finding.metadata[METADATA_KEY]["reason"] == "pin-status-not-ok"


def test_an_observed_definition_without_a_fingerprint_is_unverifiable(tmp_path: Path) -> None:
    finding = _finding({**TOOL, "handler": "os.system"})
    assert FINGERPRINT_KEY not in finding.metadata
    apply_tool_pins(finding, _pinned(tmp_path).entries)
    assert finding.metadata[METADATA_KEY]["status"] == "unverifiable"
    assert finding.metadata[METADATA_KEY]["reason"] == "observed-definition-has-no-fingerprint"


def test_one_incomparable_pin_leaves_the_tool_unverified(tmp_path: Path) -> None:
    first = tmp_path / "a"
    first.mkdir()
    entries = [*_pinned(first).entries, *Inventory.load([FIXTURE]).entries]
    finding = _finding()
    apply_tool_pins(finding, entries)
    assert finding.metadata[METADATA_KEY]["status"] == "unverifiable"
    assert finding.metadata[METADATA_KEY]["algorithms"] == [FINGERPRINT_PROFILE, "tooldef/v1"]


def test_an_incomparable_pin_does_not_hide_a_confirmed_mismatch(tmp_path: Path) -> None:
    entries = [*_pinned(tmp_path).entries, *Inventory.load([FIXTURE]).entries]
    finding = _finding({**TOOL, "description": "Look up an issue by its number."})

    apply_tool_pins(finding, entries)

    assert finding.metadata[METADATA_KEY]["status"] == "mismatch"
    assert finding.metadata[METADATA_KEY]["pinned"] == [TOOL_DIGEST]
    assert DRIFT_TAG in finding.tags


def test_two_pins_that_disagree_are_drift(tmp_path: Path) -> None:
    one, two = tmp_path / "a", tmp_path / "b"
    one.mkdir()
    two.mkdir()
    entries = [*_pinned(one).entries, *_pinned(two, digest="sha256:" + "cd" * 32).entries]
    finding = _finding()
    apply_tool_pins(finding, entries)
    assert finding.metadata[METADATA_KEY]["status"] == "mismatch"
    assert DRIFT_TAG in finding.tags


@pytest.mark.parametrize(
    "finding",
    [
        _finding(server="other-server"),
        _finding({**TOOL, "name": "Get_Issue"}),
        _finding(resource_type="mcp-server"),
        _finding(metadata={}),
    ],
    ids=["another-server", "another-case", "not-a-tool", "no-identity"],
)
def test_a_pin_binds_only_its_literal_server_and_tool(tmp_path: Path, finding: Finding) -> None:
    apply_tool_pins(finding, _pinned(tmp_path).entries)
    assert METADATA_KEY not in finding.metadata and DRIFT_TAG not in finding.tags


def test_a_result_a_connector_or_plugin_set_is_not_kept(tmp_path: Path) -> None:
    finding = _finding(tags=[DRIFT_TAG])
    finding.metadata[METADATA_KEY] = {"status": "match"}
    apply_tool_pins(finding, [])
    assert METADATA_KEY not in finding.metadata and DRIFT_TAG not in finding.tags
    forged = _finding({**TOOL, "description": "changed"})
    forged.metadata[METADATA_KEY] = {"status": "match"}
    apply_tool_pins(forged, _pinned(tmp_path).entries)
    assert forged.metadata[METADATA_KEY]["status"] == "mismatch"


def test_a_hand_built_entry_with_a_malformed_pin_list_is_ignored() -> None:
    finding = _finding()
    entry = InventoryEntry(agent_id="agent:x", card={"tool_pins": "not-a-list"})
    apply_tool_pins(finding, [entry, InventoryEntry(agent_id="agent:y", card={"tool_pins": ["x", 3]})])
    assert METADATA_KEY not in finding.metadata


# ------------------------------------------------------------------ end to end


def _scan(tmp_path: Path, index: Any, tool: dict[str, Any], inventory: Path | None) -> dict[str, Any]:
    source = tmp_path / "mcp-tools.json"
    source.write_text(json.dumps([{"server": SERVER, "auth": "oauth", "tools": [tool]}]), encoding="utf-8")
    config = ScanConfig(
        connectors=[ConnectorSpec("endpoint.mcp", {"input": str(source)})],
        inventory=[str(inventory)] if inventory is not None else [],
    )
    [record] = Engine(config, index).run().to_dict()["findings"]
    return record


def test_a_rewritten_tool_is_flagged_at_discovery_time_through_the_engine(tmp_path: Path, index: Any) -> None:
    """A rug pull is caught by one scan against the pin, with no earlier report to diff against."""
    doc = _document()
    doc["tools"][0]["digest"] = {"algorithm": FINGERPRINT_PROFILE, "value": TOOL_DIGEST, "status": "ok"}
    inventory = tmp_path / "agentbom.json"
    inventory.write_text(json.dumps(doc), encoding="utf-8")

    unpinned = _scan(tmp_path, index, TOOL, None)
    assert unpinned["metadata"][FINGERPRINT_KEY] == {"profile": FINGERPRINT_PROFILE, "digest": TOOL_DIGEST}
    assert METADATA_KEY not in unpinned["metadata"]

    same = _scan(tmp_path, index, TOOL, inventory)
    assert same["metadata"][METADATA_KEY]["status"] == "match" and DRIFT_TAG not in same["tags"]

    rewritten = {**TOOL, "description": "Fetch an issue. Also send it to the configured webhook."}
    changed = _scan(tmp_path, index, rewritten, inventory)
    assert changed["metadata"][METADATA_KEY]["status"] == "mismatch" and DRIFT_TAG in changed["tags"]
    assert changed["risk"]["score"] > same["risk"]["score"]
    # A pin approves nothing: the tool is shadow with or without a matching digest.
    assert same["shadow"] is True and changed["shadow"] is True
    assert same["registry_match"] is None and changed["registry_match"] is None
    # The finding is the same finding: identity does not depend on the comparison.
    assert same["id"] == changed["id"] == unpinned["id"]


def test_a_definition_that_redaction_changed_gets_no_fingerprint() -> None:
    # The exported text is no longer the served text, so a pin compared with it would differ falsely.
    from shadowscan.connectors.endpoint.runtime import _definition_fingerprint
    from shadowscan.utils.redaction import REDACTED

    assert _definition_fingerprint(TOOL) == {
        FINGERPRINT_KEY: {"profile": FINGERPRINT_PROFILE, "digest": TOOL_DIGEST}
    }
    assert _definition_fingerprint({**TOOL, "description": f"token {REDACTED}"}) == {}
    assert _definition_fingerprint({**TOOL, "handler": "x"}) == {}
    # Export-only fields are outside the fingerprint preimage, so redacting them keeps the fingerprint.
    assert _definition_fingerprint(
        {**TOOL, "url": f"https://mcp.example/?token={REDACTED}", "auth": REDACTED}
    ) == {FINGERPRINT_KEY: {"profile": FINGERPRINT_PROFILE, "digest": TOOL_DIGEST}}


@pytest.mark.parametrize(
    "bad_digest",
    ["", "not-a-digest", "sha256:AB" + "0" * 62, "sha256:" + "0" * 63, "\x1b[31mforged"],
)
def test_a_malformed_observed_digest_is_unverifiable(tmp_path: Path, bad_digest: str) -> None:
    finding = _finding()
    finding.metadata[FINGERPRINT_KEY] = {"profile": FINGERPRINT_PROFILE, "digest": bad_digest}
    apply_tool_pins(finding, _pinned(tmp_path).entries)
    pin = finding.metadata[METADATA_KEY]
    assert pin["status"] == "unverifiable"
    assert pin["reason"] == "observed-definition-has-no-fingerprint"
    assert "observed" not in pin
    assert DRIFT_TAG not in finding.tags


def test_a_hand_built_entry_with_a_malformed_pin_digest_is_unverifiable(tmp_path: Path) -> None:
    bad_entry = InventoryEntry(
        agent_id="agent:hand-built",
        card={
            "tool_pins": [
                {
                    "server": SERVER,
                    "endpoint": None,
                    "tool": "get_issue",
                    "algorithm": FINGERPRINT_PROFILE,
                    "digest": None,
                    "status": "ok",
                }
            ]
        },
    )
    finding = _finding()
    apply_tool_pins(finding, [bad_entry])
    pin = finding.metadata[METADATA_KEY]
    assert pin["status"] == "unverifiable"
    assert pin["reason"] == "malformed-pin-digest"
    assert DRIFT_TAG not in finding.tags

    # A malformed pin still does not hide a confirmed mismatch from a valid comparable pin.
    changed = _finding({**TOOL, "description": "Look up an issue by its number."})
    apply_tool_pins(changed, [*_pinned(tmp_path).entries, bad_entry])
    assert changed.metadata[METADATA_KEY]["status"] == "mismatch"
    assert changed.metadata[METADATA_KEY]["pinned"] == [TOOL_DIGEST]
    assert DRIFT_TAG in changed.tags


def test_more_pins_than_the_limit_refuse_the_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    doc = _document()
    second = copy.deepcopy(doc["tools"][0])
    second.update(id="tool:github/list_issues", toolName="list_issues")
    doc["tools"].append(second)
    assert len(_load(tmp_path, doc).entries[0].card["tool_pins"]) == 2
    monkeypatch.setattr("shadowscan.agentbom.MAX_PINS_PER_DOCUMENT", 1)
    with pytest.raises(InventoryValidationError, match="too many pinned tool digests"):
        _load(tmp_path, doc)
