"""Whether JSON that repeats a key is a data file no reading makes configuration.

The integrity checks refuse JSON with a repeated key, because parsers keep
different values for it. A provider catalog or an editor grammar that repeats
one is still read by no client as configuration, so the file scanner charges
it to the coverage budget instead of failing the scan, but only when every
reading of the key (first value kept, last value kept, repeated objects
merged; ``json_readings``) is data to every detector that needs a parse. The
file is analyzed without one, so a detector asked nothing here would lose
what a reading holds.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import PurePosixPath
from typing import Any

from shadowscan.connectors.code.catalogs import configuration_document
from shadowscan.connectors.code.lockfiles import LOCKFILE_NAMES
from shadowscan.connectors.code.manifests import is_manifest_name, parse_manifest
from shadowscan.connectors.code.mcp_config import json_readings, json_readings_declare_mcp
from shadowscan.connectors.code.semantic_config import structured_code_matches
from shadowscan.signatures.matcher import SignatureIndex


def ambiguous_data_file(
    index: SignatureIndex, rel: str, text: str, agent_configuration: Callable[[str], bool]
) -> bool:
    """Whether JSON the integrity checks refused is a data file that no reading makes configuration.

    No reading holds an MCP server table (``json_readings_declare_mcp``), and
    none is anything but data to a detector that needs a parse: a structured
    agent definition, or one those detectors refuse or stop at a limit on
    (``structured_code_matches``: an exported n8n workflow that repeats a
    harmless key is still an agent); an infrastructure template
    (``parse_manifest``: a CloudFormation template need not name its format
    version); or a deployment or configuration document under any project
    root (``configuration_document``: an ECS task definition). A manifest or
    lockfile is never such a file (npm keeps a repeated ``dependencies`` key's
    last value, which hides the first from a reader that keeps it), nor is
    agent configuration (``agent_configuration``).
    """
    name = PurePosixPath(rel).name
    if (
        not name.lower().endswith(".json")
        or is_manifest_name(name)
        or name.lower() in LOCKFILE_NAMES
        or agent_configuration(rel)
        or json_readings_declare_mcp(text) is not False
    ):
        return False
    readings = json_readings(text) or []
    env_names = {m.value for m in index.match_envs_in_text(text)}
    roots = [str(parent) for parent in PurePosixPath(rel).parents]
    return bool(readings) and not any(
        _read_as_configuration(index, rel, text, reading, env_names, roots) for reading in readings
    )


def _read_as_configuration(
    index: SignatureIndex, rel: str, text: str, reading: Any, env_names: set[str], roots: list[str]
) -> bool:
    """Whether a detector that needs ``rel``'s parse reads ``reading`` as configuration or cannot tell."""
    errors: list[str] = []
    limits: list[str] = []
    if structured_code_matches(index, rel, text, errors, limits, documents=[reading]) or errors:
        return True
    if parse_manifest(rel, text, reading) is not None:
        return True
    configured = any(
        configuration_document(rel, text, reading, env_names, root, limits=limits) for root in roots
    )
    return configured or bool(limits)
