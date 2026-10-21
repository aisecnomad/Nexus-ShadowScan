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
from pathlib import Path

import pytest

from shadowscan.connectors.code.mcp_config import json_readings_declare_mcp, mcp_server_holders

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
