"""Regression tests for the estate fixes after the second review round.

A Snyk Agent Scan, Numbat or vet home report of the wrong shape (an error object, rows
without the agent fields) normalized to a complete empty inventory, which earns true
negatives. It is now an adapter error.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tools.shadowbench.estate.adapters.code_wrappers import VetEstateAdapter
from tools.shadowbench.estate.adapters.mcp_scan import McpScanAdapter
from tools.shadowbench.estate.adapters.numbat import NumbatAdapter

# --- E2: a report of the wrong shape is an error, not an empty inventory --------------------------


@pytest.mark.parametrize(
    "text",
    [
        '{"error": "Traceback: boom"}',
        '{"error": {"message": "could not parse file", "is_failure": true}}',
        '{"/home/u/.cursor/mcp.json": {"path": "/home/u/.cursor/mcp.json", "servers": null}}',
        '{"a": 1, "b": [2], "c": null}',
        '{"/p": {"client": "", "servers": "x"}}',
        '{"/p": {"client": "cursor", "servers": "x"}}',
        '{"/p": {"client": null, "servers": null}}',
    ],
    ids=[
        "error-string",
        "error-object",
        "servers-null-without-client",
        "scalars",
        "blank-client",
        "client-with-bad-servers",
        "null-client-no-servers",
    ],
)
def test_mcp_scan_report_without_a_client_record_is_an_error(tmp_path: Path, text: str) -> None:
    (tmp_path / "inspect.json").write_text(text, encoding="utf-8")

    normalized = McpScanAdapter().normalize("home:laptop", tmp_path)

    assert normalized.error == "inspect.json holds no client record"
    assert normalized.predictions == []


@pytest.mark.parametrize(
    ("text", "facts"),
    [
        ("{}", []),
        ('{"/p": {"path": "/p", "servers": []}}', []),
        ('{"/p": {"client": "cursor", "servers": null}, "error": "partial"}', ["ai-client:cursor"]),
        (
            '{"/p": {"client": "windsurf", "servers": [{"name": "github", "server": {"command": "npx"}}]}}',
            ["ai-client:windsurf", "mcp:server"],
        ),
        # A null client names no client: it used to read as a client called "None".
        (
            '{"/p": {"client": null, "servers": [{"name": "github", "server": {"command": "npx"}}]},'
            ' "/q": {"client": "cursor", "servers": {}}}',
            ["mcp:server", "ai-client:cursor"],
        ),
    ],
    ids=["empty", "servers-list", "client-beside-junk", "client-and-server", "null-client"],
)
def test_mcp_scan_report_with_client_records_normalizes(tmp_path: Path, text: str, facts: list[str]) -> None:
    (tmp_path / "inspect.json").write_text(text, encoding="utf-8")

    normalized = McpScanAdapter().normalize("home:laptop", tmp_path)

    assert normalized.error is None
    assert [p.fact for p in normalized.predictions] == facts


@pytest.mark.parametrize(
    "text",
    [
        '[{"error": "Traceback: boom"}]',
        '[{"name": "Cursor", "present": true}]',
        '[{"agent": "Cursor"}]',
        '[{"agent": "", "present": true}]',
        '[1, "two", null]',
    ],
    ids=["error-object", "no-agent-field", "no-presence-field", "blank-agent", "non-records"],
)
def test_numbat_report_without_an_agent_record_is_an_error(tmp_path: Path, text: str) -> None:
    (tmp_path / "agents.json").write_text(text, encoding="utf-8")

    normalized = NumbatAdapter().normalize("home:laptop", tmp_path)

    assert normalized.error == "agents.json holds no agent record"
    assert normalized.predictions == []


@pytest.mark.parametrize(
    ("text", "facts"),
    [
        ("[]", []),
        ('[{"agent": "Cursor", "present": false}]', []),
        ('[{"agent": "Cursor", "detected": true}, {"error": "partial"}]', ["ai-client:cursor"]),
        # Rows without an agent name are skipped, not read as a nameless generic client.
        (
            '[{"agent": "Cursor", "present": true}, {"present": true}, {"agent": 5, "detected": true}]',
            ["ai-client:cursor"],
        ),
    ],
    ids=["empty", "absent-agent", "agent-beside-junk", "nameless-rows-beside-agent"],
)
def test_numbat_report_with_agent_records_normalizes(tmp_path: Path, text: str, facts: list[str]) -> None:
    (tmp_path / "agents.json").write_text(text, encoding="utf-8")

    normalized = NumbatAdapter().normalize("home:laptop", tmp_path)

    assert normalized.error is None
    assert [p.fact for p in normalized.predictions] == facts


@pytest.mark.parametrize(
    ("text", "error"),
    [
        ('{"error": "Traceback: boom"}', "ai.json is not a list"),
        ('{"App": "claude_code", "Name": "github"}', "ai.json is not a list"),
        ("42", "ai.json is not a list"),
        ('"no tools found"', "ai.json is not a list"),
        ('[{"error": "Traceback: boom"}]', "ai.json holds no vet record"),
        ('[{"App": "", "Name": ""}]', "ai.json holds no vet record"),
        ('[{"MCPServer": {}}]', "ai.json holds no vet record"),
        ("[1, null]", "ai.json holds no vet record"),
    ],
    ids=[
        "error-object",
        "single-object",
        "number",
        "string",
        "error-row",
        "blank-names",
        "empty-server",
        "non-records",
    ],
)
def test_vet_home_report_of_the_wrong_shape_is_an_error(tmp_path: Path, text: str, error: str) -> None:
    (tmp_path / "ai.json").write_text(text, encoding="utf-8")

    normalized = VetEstateAdapter().normalize("home:laptop", tmp_path)

    assert normalized.error == error
    assert normalized.predictions == []


@pytest.mark.parametrize(
    ("text", "facts"),
    [
        # The code-surface vet adapter records that vet writes `null` or `[]` when it finds nothing.
        ("null", []),
        ("[]", []),
        (
            '[{"App": "claude_code", "Name": "github", "ConfigPath": "/h/.claude.json",'
            ' "MCPServer": {"Command": "npx"}}, {"error": "partial"}]',
            ["mcp:server", "ai-client:claude-code"],
        ),
        # Items that are not records are skipped, not read as a client named "5".
        (
            '[{"App": "claude_code", "Name": "github", "ConfigPath": "/h/.claude.json"}, {"App": 5},'
            ' {"Name": ["x"]}]',
            ["ai-client:claude-code"],
        ),
    ],
    ids=["null", "empty", "record-beside-junk", "non-records-beside-record"],
)
def test_vet_home_report_with_records_normalizes(tmp_path: Path, text: str, facts: list[str]) -> None:
    (tmp_path / "ai.json").write_text(text, encoding="utf-8")

    normalized = VetEstateAdapter().normalize("home:laptop", tmp_path)

    assert normalized.error is None
    assert [p.fact for p in normalized.predictions] == facts
