"""Compare observed MCP tool definitions with the digests an inventory pins.

An AgentBOM in the sanctioned inventory can pin a tool's definition digest
(:mod:`shadowscan.agentbom` reads ``tools[].digest``). The endpoint connector
records a fingerprint of each tool definition it observes. When the two name the
same server and tool under a profile this module computes, a difference means the
definition changed after it was pinned: the "rug pull" a pinned digest exists to
catch.

A pin is never an approval. It does not change ``shadow`` or ``registry_match``,
and a matching digest says only that the served text equals the pinned text: it
does not authenticate the server, the AgentBOM or its producer. A pin that cannot
be compared is reported as ``unverifiable``, never as a match.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any, TypeGuard

from shadowscan.utils.jcs import CanonicalizationError, canonicalize

if TYPE_CHECKING:
    from shadowscan.models import Finding
    from shadowscan.registry import InventoryEntry

# The profile of Nexus SymBiote's tool fingerprint: SHA-256 over the RFC 8785
# canonical form of the model-visible descriptor members.
FINGERPRINT_PROFILE = "rfc8785-jcs-v2"
SUPPORTED_PROFILES = frozenset({FINGERPRINT_PROFILE})
DRIFT_TAG = "tool-definition-drift"
METADATA_KEY = "tool_pin"
FINGERPRINT_KEY = "tool_definition_fingerprint"
STATUSES = ("match", "mismatch", "unverifiable")
MAX_PINS_PER_DOCUMENT = 2000

DESCRIPTOR_FIELDS = frozenset(
    {"name", "description", "inputSchema", "annotations", "title", "outputSchema", "_meta"}
)
# Members a ShadowScan tool export adds beside the descriptor; they are not model-visible.
_EXPORT_FIELDS = frozenset({"auth", "auth_mode", "url"})
_OBJECT_FIELDS = ("inputSchema", "annotations", "outputSchema", "_meta")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def _is_digest(value: Any) -> TypeGuard[str]:
    return isinstance(value, str) and bool(_DIGEST.fullmatch(value))


def _incomparable_reason(pins: list[tuple[str, dict[str, Any]]]) -> str:
    if any(pin.get("status") != "ok" for _, pin in pins):
        return "pin-status-not-ok"
    if any(pin.get("algorithm") not in SUPPORTED_PROFILES for _, pin in pins):
        return "unsupported-digest-algorithm"
    return "malformed-pin-digest"


def fingerprint(tool: Any) -> str | None:
    """The ``rfc8785-jcs-v2`` fingerprint of an MCP tool descriptor, or None when it has none.

    The preimage holds the name, the description (absent reads as ``""``), the
    input schema when present, the annotations (absent, null and empty are equal),
    and the title, output schema and ``_meta`` only when present and not null. A
    descriptor with any other member, a member of the wrong type, or a value
    without a canonical form has no fingerprint: hashing it without that part
    would let the part change unseen.
    """
    if not isinstance(tool, dict) or set(tool) - DESCRIPTOR_FIELDS - _EXPORT_FIELDS:
        return None
    name, description, title = tool.get("name"), tool.get("description", ""), tool.get("title")
    if not isinstance(name, str) or not name:
        return None
    if description is not None and not isinstance(description, str):
        return None
    if title is not None and not isinstance(title, str):
        return None
    if any(tool.get(key) is not None and not isinstance(tool[key], dict) for key in _OBJECT_FIELDS):
        return None
    definition: dict[str, Any] = {"name": name, "description": description}
    if tool.get("inputSchema") is not None:
        definition["inputSchema"] = tool["inputSchema"]
    definition["annotations"] = tool.get("annotations") or {}
    for key in ("title", "outputSchema", "_meta"):
        if tool.get(key) is not None:
            definition[key] = tool[key]
    try:
        return "sha256:" + hashlib.sha256(canonicalize(definition)).hexdigest()
    except (CanonicalizationError, RecursionError):
        return None


def _pins_for(finding: Finding, entries: Iterable[InventoryEntry]) -> list[tuple[str, dict[str, Any]]]:
    server, tool = finding.metadata.get("server"), finding.metadata.get("tool")
    if not isinstance(server, str) or not isinstance(tool, str) or not server or not tool:
        return []
    found: list[tuple[str, dict[str, Any]]] = []
    for entry in entries:
        pins = entry.card.get("tool_pins") if isinstance(entry.card, dict) else None
        for pin in pins if isinstance(pins, list) else ():
            # Literal, case-sensitive identity: the server by the name or endpoint the
            # AgentBOM records, as the tool export names it.
            if (
                isinstance(pin, dict)
                and pin.get("tool") == tool
                and server in (pin.get("server"), pin.get("endpoint"))
            ):
                found.append((entry.agent_id, pin))
    return found


def apply_tool_pins(finding: Finding, entries: Iterable[InventoryEntry]) -> None:
    """Record how ``finding``'s observed tool definition compares with the inventory's pins.

    Sets ``metadata.tool_pin`` and, on a difference, the ``tool-definition-drift`` tag.
    Both are rebuilt on every call, so a value a connector or plugin set is not kept.
    """
    finding.metadata.pop(METADATA_KEY, None)
    if DRIFT_TAG in finding.tags:
        finding.tags.remove(DRIFT_TAG)
    if finding.resource_type != "mcp-tool":
        return
    pins = _pins_for(finding, entries)
    if not pins:
        return
    observed = finding.metadata.get(FINGERPRINT_KEY)
    digest = observed.get("digest") if isinstance(observed, dict) else None
    profile = observed.get("profile") if isinstance(observed, dict) else None
    result: dict[str, Any] = {"pinned_by": sorted({agent for agent, _ in pins})}
    comparable = [
        pin
        for _, pin in pins
        if pin.get("status") == "ok"
        and pin.get("algorithm") in SUPPORTED_PROFILES
        and _is_digest(pin.get("digest"))
    ]
    pinned = {pin["digest"] for pin in comparable}
    has_fingerprint = _is_digest(digest) and profile == FINGERPRINT_PROFILE
    mismatch = has_fingerprint and bool(pinned) and pinned != {digest}
    # An unchecked pin prevents a match. A checked pin can still establish drift.
    if len(comparable) != len(pins) and not mismatch:
        result["status"] = "unverifiable"
        result["reason"] = _incomparable_reason(pins)
        result["algorithms"] = sorted({str(pin.get("algorithm")) for _, pin in pins})
    elif not has_fingerprint:
        result["status"] = "unverifiable"
        result["reason"] = "observed-definition-has-no-fingerprint"
    else:
        result["algorithm"] = FINGERPRINT_PROFILE
        result["observed"] = digest
        result["pinned"] = sorted(pinned)
        result["status"] = "mismatch" if mismatch else "match"
        if mismatch:
            finding.add_tag(DRIFT_TAG)
    finding.metadata[METADATA_KEY] = result


__all__ = [
    "DESCRIPTOR_FIELDS",
    "DRIFT_TAG",
    "FINGERPRINT_KEY",
    "FINGERPRINT_PROFILE",
    "MAX_PINS_PER_DOCUMENT",
    "METADATA_KEY",
    "STATUSES",
    "SUPPORTED_PROFILES",
    "apply_tool_pins",
    "fingerprint",
]
