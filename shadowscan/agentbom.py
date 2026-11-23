"""Import operator-trusted SymBiote AgentBOM 0.1 documents as inventory.

Structural validation is not seal verification or approval by the producer.
Only subject identities become approval bindings; dependency resources remain
contextual. SymBiote remains responsible for cryptographic supply-chain checks.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from shadowscan.tool_pins import MAX_PINS_PER_DOCUMENT

AGENTBOM_MARKERS = ("specVersion", "snapshot", "subject")
ISO_TO_LEVEL: dict[str, int] = {
    "notAutomated": 0,
    "assistiveAutomation": 1,
    "partialAutomation": 2,
    "conditionalAutomation": 3,
    "highAutomation": 4,
    "fullAutomation": 5,
    "autonomous": 5,
}
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ENTITY_ID = re.compile(r"[a-z][a-z0-9-]*:[A-Za-z0-9._~/@+-]+\Z")
_MAX_ENTITIES = 10_000
_ENTITY_PREFIXES = {
    "agents": "agent:",
    "parties": "party:",
    "deployments": "deploy:",
    "toolServers": "server:",
    "tools": "tool:",
}
Invalid = Callable[[Path, str, str], Exception]


def is_agentbom(doc: Any) -> bool:
    """Recognize emitted companion documents before the plain agents-list shape.

    A mapping with two of the three markers is also read as an AgentBOM, so that
    :func:`summarize` names the missing marker instead of the plain shape refusing
    the others. The plain ``agents:`` and simple-entry shapes refuse every marker
    as an unsupported field, so this rejects nothing they would accept. A card
    (``metadata`` without ``agents``) does not restrict its top-level fields and
    keeps its own shape unless all three markers are present.
    """
    if not isinstance(doc, dict):
        return False
    present = sum(marker in doc for marker in AGENTBOM_MARKERS)
    if present == len(AGENTBOM_MARKERS):
        return True
    return present == len(AGENTBOM_MARKERS) - 1 and ("agents" in doc or "metadata" not in doc)


class _Reader:
    def __init__(self, path: Path, location: str, invalid: Invalid) -> None:
        self.path, self.location, self.invalid = path, location, invalid
        self.ids: set[str] = set()

    def error(self, field: str, reason: str) -> Exception:
        return self.invalid(self.path, f"{self.location}.{field}", reason)

    def text(self, value: Any, field: str) -> str:
        if not isinstance(value, str) or not value or value != value.strip():
            raise self.error(field, "expected a nonempty unpadded string")
        return value

    def optional_text(self, value: Any, field: str) -> str | None:
        return None if value is None else self.text(value, field)

    def mapping(self, value: Any, field: str) -> dict[str, Any]:
        if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
            raise self.error(field, "expected an object")
        return value

    def objects(self, value: Any, field: str) -> list[dict[str, Any]]:
        if not isinstance(value, list) or len(value) > _MAX_ENTITIES:
            raise self.error(field, "expected a bounded list of objects")
        return [self.mapping(item, f"{field}[{index}]") for index, item in enumerate(value)]

    def entities(self, doc: dict[str, Any], field: str) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for index, item in enumerate(self.objects(doc.get(field, []), field)):
            identity = self.entity_id(item.get("id"), f"{field}[{index}].id")
            if not identity.startswith(_ENTITY_PREFIXES[field]):
                raise self.error(field, "entity id has the wrong collection prefix")
            if identity in self.ids:
                raise self.error(field, "duplicate entity id")
            self.ids.add(identity)
            out[identity] = item
        return out

    def entity_id(self, value: Any, field: str) -> str:
        identity = self.text(value, field)
        if len(identity) > 512 or not _ENTITY_ID.fullmatch(identity):
            raise self.error(field, "expected an AgentBOM entity id")
        return identity

    def claim(self, value: Any, field: str) -> Any:
        if value is None:
            return None
        claim = self.mapping(value, field)
        state = claim.get("state", "present")  # Producer schema default, not an unknown claim.
        if state not in ("present", "unknown", "absent-verified"):
            raise self.error(field, "unsupported claim state")
        item = claim.get("value")
        if state == "present":
            if item is None:
                raise self.error(field, "a present claim requires a value")
            return item
        if state == "unknown":
            if item is not None:
                raise self.error(field, "an unknown claim cannot carry a value")
            self.text(claim.get("unknownReason"), f"{field}.unknownReason")
        elif item not in (None, "", [], {}, False):
            raise self.error(field, "an absent-verified claim must be empty")
        return None


_MISSING_MARKER = "missing; an AgentBOM document requires specVersion, snapshot and subject"


def _require_markers(doc: dict[str, Any], reader: _Reader) -> None:
    for marker in AGENTBOM_MARKERS:
        if marker not in doc:
            raise reader.error(marker, _MISSING_MARKER)


def _snapshot(doc: dict[str, Any], subject: str, reader: _Reader) -> dict[str, Any]:
    if doc.get("specVersion") != "0.1":
        raise reader.error("specVersion", "unsupported AgentBOM version; expected 0.1")
    snapshot = reader.mapping(doc.get("snapshot"), "snapshot")
    digest = reader.text(snapshot.get("digest"), "snapshot.digest")
    if not _DIGEST.fullmatch(digest):
        raise reader.error("snapshot.digest", "expected a lowercase sha256: digest with 64 hex digits")
    serial = snapshot.get("serial")
    if type(serial) is not int or serial < 1:
        raise reader.error("snapshot.serial", "expected a positive integer")
    if snapshot.get("id") != f"snap:{serial}:{digest[7:19]}":
        raise reader.error("snapshot.id", "does not agree with snapshot serial and digest")
    if snapshot.get("agentRef") != subject:
        raise reader.error("snapshot.agentRef", "must identify the document subject")
    if doc.get("merkle") is not None:
        merkle = reader.mapping(doc["merkle"], "merkle")
        if merkle.get("root") != digest:
            raise reader.error("merkle.root", "must agree with the snapshot digest")
    return snapshot


def _owner(agent: dict[str, Any], parties: dict[str, dict[str, Any]], reader: _Reader) -> str | None:
    identity = reader.optional_text(agent.get("ownerRef"), "agents.subject.ownerRef")
    if identity is None:
        return None
    if identity not in parties:
        raise reader.error("agents.subject.ownerRef", "does not identify a party")
    return reader.optional_text(parties[identity].get("name"), "parties.owner.name")


def _autonomy(agent: dict[str, Any], reader: _Reader) -> int | None:
    ladder = reader.claim(agent.get("automationLevel"), "agents.subject.automationLevel")
    if ladder is None:
        return None
    if not isinstance(ladder, str) or ladder not in ISO_TO_LEVEL:
        raise reader.error("agents.subject.automationLevel", "expected an isoAutomationLevel name")
    return ISO_TO_LEVEL[ladder]


def _frameworks(agent: dict[str, Any], reader: _Reader) -> list[str]:
    value = reader.claim(agent.get("framework"), "agents.subject.framework")
    if value is None:
        return []
    framework = reader.mapping(value, "agents.subject.framework.value")
    return [f"framework.{reader.text(framework.get('name'), 'agents.subject.framework.name').lower()}"]


def _deployment_resources(
    deployments: dict[str, dict[str, Any]], subject: str, reader: _Reader
) -> tuple[list[str], list[str]]:
    resources: list[str] = []
    uids: list[str] = []
    for deployment in deployments.values():
        if reader.entity_id(deployment.get("agentRef"), "deployments.agentRef") != subject:
            continue
        if deployment.get("workloadRef") is None:
            continue
        workload = reader.mapping(deployment["workloadRef"], "deployments.workloadRef")
        if uid := reader.optional_text(workload.get("uid"), "deployments.workloadRef.uid"):
            uids.append(uid)
        if resource := _workload_identity(deployment, workload, reader):
            resources.append(resource)
    return resources, uids


def _workload_identity(deployment: dict[str, Any], workload: dict[str, Any], reader: _Reader) -> str | None:
    environment = reader.mapping(deployment.get("environment", {}), "deployments.environment")
    if environment.get("kind") != "k8s":
        return None
    namespace = reader.optional_text(environment.get("namespace"), "deployments.environment.namespace")
    if namespace is not None and workload.get("namespace") not in (None, namespace):
        raise reader.error("deployments.workloadRef.namespace", "conflicts with deployment namespace")
    values = (
        environment.get("cluster"),
        workload.get("namespace"),
        workload.get("kind"),
        workload.get("name"),
    )
    parts = [reader.optional_text(value, "deployments.workloadIdentity") for value in values]
    if any(part is not None and "/" in part for part in parts):
        raise reader.error("deployments.workloadIdentity", "identity components cannot contain slashes")
    if not all(part is not None for part in parts):
        return None
    return "k8s:" + "/".join(part for part in parts if part is not None)


def _subject_resources(agent: dict[str, Any], reader: _Reader) -> list[str]:
    resources: list[str] = []
    for ref in reader.objects(agent.get("externalRefs", []), "agents.subject.externalRefs"):
        reader.text(ref.get("type"), "agents.subject.externalRefs.type")
        resources.append(reader.text(ref.get("url"), "agents.subject.externalRefs.url"))
    if agent.get("a2ACard") is not None:
        card = reader.mapping(agent["a2ACard"], "agents.subject.a2ACard")
        if url := reader.optional_text(card.get("url"), "agents.subject.a2ACard.url"):
            resources.append(url)
    return resources


def _component_resources(servers: dict[str, dict[str, Any]], reader: _Reader) -> list[str]:
    resources: list[str] = []
    for server in servers.values():
        endpoint = reader.claim(server.get("endpoint"), "toolServers.endpoint")
        if endpoint is not None:
            resources.append(reader.text(endpoint, "toolServers.endpoint.value"))
        package = reader.claim(server.get("package"), "toolServers.package")
        if package is not None:
            package = reader.mapping(package, "toolServers.package.value")
            if purl := reader.optional_text(package.get("purl"), "toolServers.package.purl"):
                resources.append(purl)
    return list(dict.fromkeys(resources))


def _tool_pins(
    doc: dict[str, Any], servers: dict[str, dict[str, Any]], reader: _Reader
) -> list[dict[str, Any]]:
    """The definition digests the document pins for its tools, by server and tool name.

    A pin is descriptive: :mod:`shadowscan.tool_pins` compares it with the definition
    a scan observes, and it approves nothing. A tool without a digest pins nothing.
    The algorithm is kept as named; one this scanner does not compute is reported as
    unverifiable when compared, never as a match.
    """
    pins: list[dict[str, Any]] = []
    for tool in reader.entities(doc, "tools").values():
        if tool.get("digest") is None:
            continue
        digest = reader.mapping(tool["digest"], "tools.digest")
        server_ref = reader.entity_id(tool.get("serverRef"), "tools.serverRef")
        if server_ref not in servers:
            raise reader.error("tools.serverRef", "the server is not among the toolServers")
        algorithm = reader.text(digest.get("algorithm"), "tools.digest.algorithm")
        if len(algorithm) > 64:
            raise reader.error("tools.digest.algorithm", "expected at most 64 characters")
        value = reader.text(digest.get("value"), "tools.digest.value")
        if not _DIGEST.fullmatch(value):
            raise reader.error("tools.digest.value", "expected a sha256 digest")
        server = servers[server_ref]
        endpoint = reader.claim(server.get("endpoint"), "toolServers.endpoint")
        pins.append(
            {
                "server": reader.optional_text(server.get("name"), "toolServers.name")
                or server_ref.split(":", 1)[-1],
                "endpoint": reader.text(endpoint, "toolServers.endpoint.value")
                if endpoint is not None
                else None,
                "tool": reader.text(tool.get("toolName"), "tools.toolName"),
                "algorithm": algorithm,
                "digest": value,
                "status": reader.optional_text(digest.get("status"), "tools.digest.status") or "ok",
            }
        )
        if len(pins) > MAX_PINS_PER_DOCUMENT:
            raise reader.error("tools", "too many pinned tool digests")
    return pins


def summarize(doc: dict[str, Any], path: Path, location: str, invalid: Invalid) -> dict[str, Any]:
    """Return subject inventory fields, never treating components or seals as approval."""
    reader = _Reader(path, location, invalid)
    _require_markers(doc, reader)
    subject = reader.entity_id(doc.get("subject"), "subject")
    snapshot = _snapshot(doc, subject, reader)
    agents = reader.entities(doc, "agents")
    if subject not in agents:
        raise reader.error("agents", "subject is not among the agents")
    agent = agents[subject]
    parties = reader.entities(doc, "parties")
    deployments = reader.entities(doc, "deployments")
    servers = reader.entities(doc, "toolServers")
    resources, uids = _deployment_resources(deployments, subject, reader)
    resources.extend(_subject_resources(agent, reader))
    name = reader.optional_text(agent.get("name"), "agents.subject.name")
    return {
        "agent_id": subject,
        "name": name,
        "owner": _owner(agent, parties, reader),
        "resources": list(dict.fromkeys(resources)),
        "names": [subject.split(":", 1)[-1], *([name] if name else [])],
        "frameworks": _frameworks(agent, reader),
        "tags": ["agentbom"],
        "autonomy_level": _autonomy(agent, reader),
        "card": {
            "schema": "symbiote-agentbom",
            "spec_version": doc["specVersion"],
            "snapshot_id": snapshot["id"],
            "snapshot_digest": snapshot["digest"],
            "snapshot_serial": snapshot["serial"],
            "verification": "not-verified",
            "component_resources": _component_resources(servers, reader),
            "workload_uids": list(dict.fromkeys(uids)),
            "tool_pins": _tool_pins(doc, servers, reader),
        },
    }


__all__ = ["AGENTBOM_MARKERS", "ISO_TO_LEVEL", "is_agentbom", "summarize"]
