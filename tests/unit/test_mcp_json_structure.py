"""JSON that left BerriAI/litellm, continuedev/continue and openai/openai-agents-python incomplete.

litellm's provider catalog repeats a key, and its 1.86 MB OpenAPI snapshot,
over the size limit, describes an ``mcp_servers`` field. continue's F#
TextMate grammar repeats a key. openai-agents-python's 1.15 MB API contract
names ``mcp_servers`` fields deeper than the server-table walk's 12 levels.
Each is now decided by its structure under both readings of a repeated key;
a server table either reading holds, a manifest, agent configuration and JSON
that does not parse still fail the scan.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from shadowscan.connectors.code.mcp_config import json_readings, json_readings_declare_mcp, mcp_server_holders

SNAPSHOT = {
    "openapi": "3.1.0",
    "components": {
        "schemas": {
            "TeamRequest": {
                "type": "object",
                "title": "TeamRequest",
                "properties": {
                    "mcp_servers": {
                        "anyOf": [{"type": "array", "items": {"type": "string"}}],
                        "title": "Mcp",
                    },
                    "pad": {"type": "string", "description": "x" * 6_000},
                },
            }
        }
    },
}


def _project(root: Path, files: dict[str, str]) -> Path:
    """121 ordinary files, so gaps of two entries are within the default 2% budget."""
    (root / "src").mkdir(parents=True, exist_ok=True)
    for i in range(120):
        (root / "src" / f"m{i}.py").write_text(f"x = {i}\n")
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return root


def _gaps(ctx) -> list[tuple[str, str, str]]:
    return [
        (gap["path"], gap["kind"], gap["reason"]) for gap in (ctx.stats.coverage or {}).get("details", [])
    ]


# --------------------------------------------------------- litellm JSON catalogs


def test_both_readings_of_a_repeated_key_are_walked():
    assert json_readings_declare_mcp('{"a": 1, "a": 2}') is False
    # The table one reading holds is found whichever reading keeps it.
    assert json_readings_declare_mcp('{"x": {"mcpServers": {"s": {"command": "c"}}}, "x": 1}') is True
    assert json_readings_declare_mcp('{"x": 1, "x": {"mcpServers": {"s": {"command": "c"}}}}') is True
    assert json_readings_declare_mcp("{bad") is None


def test_a_provider_catalog_with_a_repeated_key_is_budgeted(tmp_path, run_connector):
    # provider_endpoints_support.json lists one provider twice.
    catalog = '{"providers": {"charity_engine": {"chat": true}, "charity_engine": {"chat": true}}, "mcp": {}}'
    _project(tmp_path, {"provider_endpoints_support.json": catalog})
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.incomplete, (ctx.stats.errors, ctx.stats.warnings)
    assert {(path, kind) for path, kind, _ in _gaps(ctx)} == {("provider_endpoints_support.json", "partial")}


def test_a_repeated_key_that_hides_a_server_table_still_fails(tmp_path, run_connector):
    hidden = '{"mcpServers": {"s": {"command": "evil"}}, "mcpServers": {}}'
    _project(tmp_path, {"config/tools.json": hidden})
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete


def test_a_schema_that_describes_an_mcp_servers_field_holds_no_server_table():
    assert mcp_server_holders(SNAPSHOT) == ([], False)
    # A value with a server name under the same field map is a server table.
    served = {"type": "object", "properties": {"mcpServers": {"evil": {"command": "x"}}}}
    assert mcp_server_holders(served)[0]
    # Outside a schema's field map the key alone still decides.
    assert mcp_server_holders({"config": {"mcp_servers": {"title": "t"}}})[0]


def test_an_oversize_openapi_snapshot_is_one_budgeted_gap(tmp_path, run_connector):
    _project(tmp_path, {"proxy/_lazy_openapi_snapshot.json": json.dumps(SNAPSHOT)})
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, max_file_size=4_000)
    assert not ctx.stats.incomplete, (ctx.stats.errors, ctx.stats.warnings)
    assert _gaps(ctx) == [("proxy/_lazy_openapi_snapshot.json", "partial", "oversize-file")]


def test_an_oversize_json_server_table_stays_blinding(tmp_path, run_connector):
    padded = json.dumps({"mcpServers": {"s": {"command": "evil"}}, "pad": "v" * 6_000})
    _project(tmp_path, {"deploy/tools.json": padded})
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, max_file_size=4_000)
    assert ctx.stats.incomplete
    assert _gaps(ctx) == [("deploy/tools.json", "blinding", "oversize-file")]


def test_an_oversize_json_that_does_not_parse_stays_blinding(tmp_path, run_connector):
    _project(tmp_path, {"deploy/tools.json": '{"mcpServers": {' + " " * 6_000})
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, max_file_size=4_000)
    assert ctx.stats.incomplete
    assert [kind for _, kind, _ in _gaps(ctx)] == ["blinding"]


# ------------------------------------------ continue and openai-agents-python


def test_a_textmate_grammar_with_a_repeated_key_is_budgeted(tmp_path, run_connector):
    # continue's textmate-syntaxes/fsharp.json repeats a repository key.
    grammar = '{"scopeName": "source.fsharp", "repository": {"comments": {}, "comments": {"name": "c"}}}'
    _project(tmp_path, {"extensions/vscode/textmate-syntaxes/fsharp.json": grammar})
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.incomplete, (ctx.stats.errors, ctx.stats.warnings)
    assert {kind for _, kind, _ in _gaps(ctx)} == {"partial"}


def _nested(depth: int, leaf: object) -> object:
    for level in range(depth):
        leaf = {f"level{level}": leaf, "type": "object"}
    return leaf


def test_a_deep_oversize_api_contract_is_decided_by_its_structure(tmp_path, run_connector):
    # released_api_contract.json nests past the server-table walk's 12 levels and
    # names mcp_servers fields; parsed whole, it holds no server table.
    contract = {
        "classes": _nested(
            20, {"type": "object", "properties": {"mcp_servers": {"anyOf": [{"type": "array"}]}}}
        ),
        "pad": "v" * 6_000,
    }
    _project(tmp_path, {"tests/fixtures/released_api_contract.json": json.dumps(contract)})
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, max_file_size=4_000)
    assert not ctx.stats.incomplete, (ctx.stats.errors, ctx.stats.warnings)
    assert [kind for _, kind, _ in _gaps(ctx)] == ["partial"]


def test_a_server_table_deep_in_an_oversize_contract_stays_blinding(tmp_path, run_connector):
    contract = {"classes": _nested(20, {"mcpServers": {"s": {"command": "evil"}}}), "pad": "v" * 6_000}
    _project(tmp_path, {"tests/fixtures/released_api_contract.json": json.dumps(contract)})
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, max_file_size=4_000)
    assert ctx.stats.incomplete
    assert [kind for _, kind, _ in _gaps(ctx)] == ["blinding"]


def test_the_readings_walk_every_level_and_entry():
    deep = "[" * 900 + '{"mcpServers": {"s": {"command": "x"}}}' + "]" * 900
    assert json_readings_declare_mcp(deep) is True
    wide = json.dumps([{"k": [1]} for _ in range(1_000)] + [{"mcpServers": {}}])
    assert json_readings_declare_mcp(wide) is True


@pytest.mark.parametrize(
    ("rel", "text"),
    [
        # npm keeps the last of a repeated key: the first dependencies table is hidden from it.
        ("package.json", '{"dependencies": {"openai": "4"}, "dependencies": {}}'),
        ("composer.json", '{"require": {}, "metadata": 1e999}'),
        (".vscode/settings.json", '{"a": 1, "a": 2}'),
    ],
)
def test_a_repeated_key_in_a_manifest_or_agent_configuration_still_fails(tmp_path, run_connector, rel, text):
    _project(tmp_path, {rel: text})
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete


# ------------------------------------------------------- review follow-ups


def test_a_structured_agent_definition_with_a_repeated_key_still_fails(tmp_path, run_connector):
    # An exported n8n workflow is agent configuration the structured detectors read; a
    # harmless repeated key must not turn its unreadable definition into a budgeted gap.
    nodes = [
        {"id": "1", "name": "Agent", "type": "@n8n/n8n-nodes-langchain.agent", "parameters": {}},
        {"id": "2", "name": "Shell", "type": "n8n-nodes-base.executeCommand", "parameters": {}},
        {"id": "3", "name": "Model", "type": "@n8n/n8n-nodes-langchain.lmChatOpenAi", "parameters": {}},
    ]
    workflow = json.dumps({"name": "ops", "nodes": nodes, "connections": {}})
    _project(tmp_path, {"automation/ops.json": workflow[:-1] + ', "name": "ops2"}'})
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete


def test_a_table_only_a_merged_reading_holds_is_found():
    # Go's decoder merges repeated objects: neither first-wins nor last-wins sees this table.
    merged = '{"client": {"cfg": {}, "cfg": {"mcpServers": {"s": {"command": "x"}}}}, "client": {}}'
    assert json_readings_declare_mcp(merged) is True


def test_a_table_only_a_merged_reading_holds_still_fails_the_scan(tmp_path, run_connector):
    merged = '{"client": {"cfg": {}, "cfg": {"mcpServers": {"s": {"command": "x"}}}}, "client": {}}'
    _project(tmp_path, {"deploy/tools.json": merged})
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete


@pytest.mark.parametrize("key", ["McpServers", "mcp-servers", "MCP_SERVERS"])
def test_a_server_key_in_another_spelling_is_undecided(key):
    assert json_readings_declare_mcp(json.dumps({key: {"s": {"command": "x"}}})) is None
    assert json_readings_declare_mcp(json.dumps({"MCP": {"Servers": {}}})) is None


def test_an_oversize_json_with_a_case_variant_server_key_stays_blinding(tmp_path, run_connector):
    padded = json.dumps({"McpServers": {"s": {"command": "evil"}}, "pad": "v" * 6_000})
    _project(tmp_path, {"deploy/tools.json": padded})
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, max_file_size=4_000)
    assert ctx.stats.incomplete
    assert [kind for _, kind, _ in _gaps(ctx)] == ["blinding"]


@pytest.mark.parametrize("server", ["default", "type", "title"])
def test_a_server_named_like_a_schema_keyword_is_still_a_server(server):
    document = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": {"mcpServers": {server: {"command": "npx", "args": ["-y", "x"]}}},
    }
    assert mcp_server_holders(document)[0]


@pytest.mark.parametrize(
    "server", ["properties", "patternProperties", "items", "not", "additionalProperties"]
)
def test_a_server_behind_a_mapping_keyword_is_still_a_server(server):
    # A keyword that takes a mapping accepts a server record; a field map holds
    # schemas and the schema-taking keywords hold a schema's keywords only.
    document = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": {"mcpServers": {server: {"command": "npx", "args": ["-y", "x"]}}},
    }
    assert mcp_server_holders(document)[0]
    # A real field map and a real nested schema still describe values, not servers.
    schema = {
        "type": "object",
        "properties": {"mcp_servers": {"properties": {"url": {"type": "string"}}}},
    }
    assert mcp_server_holders(schema) == ([], False)


def test_an_exact_mcp_key_with_a_variant_servers_key_is_undecided():
    # Go's and .NET's decoders match keys without regard to case: either name
    # of the pair may carry the variant, not only the outer one.
    assert json_readings_declare_mcp(json.dumps({"mcp": {"Servers": {"s": {"command": "x"}}}})) is None
    assert json_readings_declare_mcp(json.dumps({"MCP": {"servers": {"s": {"command": "x"}}}})) is None
    # The exact pair is read by the walk itself, not a variant.
    assert json_readings_declare_mcp(json.dumps({"mcp": {"servers": {"s": {"command": "x"}}}})) is True


def test_a_variant_case_servers_section_with_a_repeated_key_still_fails(tmp_path, run_connector):
    hidden = '{"mcp": {"Servers": {"s": {"command": "evil"}}}, "a": 1, "a": 2}'
    _project(tmp_path, {"config/tools.json": hidden})
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete


# ------------------------------------------------------- resource bounds


def test_a_document_without_a_repeated_key_is_one_reading():
    # One parse decides a file without repeats; the readings differ only on repeats.
    assert json_readings('{"a": {"b": 1}}') == [{"a": {"b": 1}}]
    assert json_readings('{"a": 1, "a": 2}') == [{"a": 2}, {"a": 1}, {"a": [1, 2]}]
    assert json_readings("{bad") is None


def test_container_dense_text_is_left_undecided_quickly():
    # json.loads cannot be interrupted, so text that opens more than
    # _MAX_JSON_CONTAINERS containers is undecided before anything is parsed —
    # a reading drops a repeated key's other values, so only the text's own
    # brackets bound what every reading could rebuild.
    dense = '{"a": 1, "a": 2, "data": [' + "{}," * 100_001 + "{}]}"
    started = time.thread_time()
    assert json_readings(dense) is None
    assert json_readings_declare_mcp(dense) is None
    assert time.thread_time() - started < 5.0
    # The repeated huge value a last-wins reading drops still counts.
    hidden = '{"pad": [' + "[]," * 100_001 + '[]], "pad": 1}'
    assert json_readings(hidden) is None


def test_an_oversize_container_dense_json_stays_blinding(tmp_path, run_connector):
    # Within the container bound this schema is one budgeted gap
    # (test_an_oversize_openapi_snapshot_is_one_budgeted_gap); past it the
    # repeated key is undecided and the gap keeps the byte check's answer.
    dense = (
        '{"components": {"schemas": {"T": {"type": "object", "properties":'
        ' {"mcp_servers": {"anyOf": []}}}}}, "pad": [' + "[]," * 100_001 + '[]], "pad": 1}'
    )
    _project(tmp_path, {"deploy/tools.json": dense})
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, max_file_size=4_000)
    assert ctx.stats.incomplete
    assert [kind for _, kind, _ in _gaps(ctx)] == ["blinding"]
