"""Gaps that left crewAIInc/crewAI and BerriAI/litellm incomplete.

crewAI ships the project templates ``crewai create`` renders under ordinary
names (``templates/crew/crew.py`` declares ``class {{crew_name}}():``, its
``pyproject.toml`` a ``{{folder_name}} = ...`` key), so neither parses as
written. litellm holds a provider catalog with one repeated key, an OpenAPI
snapshot over the size limit that describes an ``mcp_servers`` field, and
modules of 50,000 to 90,000 syntax-tree nodes.

Each of these is charged to the coverage budget or analyzed in full; each
counter-case keeps the scan failing closed.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from shadowscan.connectors.code.mcp_config import json_readings_declare_mcp, mcp_server_holders
from shadowscan.connectors.code.source_semantics import MAX_AST_NODES, MAX_BOUND_CALLS
from shadowscan.connectors.code.template_source import unrendered_template
from shadowscan.models import Kind

CREW = (
    "from crewai import Agent, Crew, Process, Task\n"
    "from crewai.project import CrewBase, agent, crew\n\n"
    "@CrewBase\n"
    "class {{crew_name}}():\n"
    '    """{{crew_name}} crew"""\n\n'
    "    @agent\n"
    "    def researcher(self) -> Agent:\n"
    "        return Agent(config=self.agents_config['researcher'])\n"
)
PYPROJECT = (
    '[project]\nname = "{{folder_name}}"\nversion = "0.1.0"\n'
    'dependencies = ["crewai[tools]>=0.80.0"]\n\n'
    '[project.scripts]\n{{folder_name}} = "{{folder_name}}.main:run"\n'
)
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


# ------------------------------------------------------------ crewAI templates


@pytest.mark.parametrize(
    ("rel", "text"),
    [
        ("templates/crew/crew.py", CREW),
        ("templates/crew/pyproject.toml", PYPROJECT),
        ("templates/flow/main.py", "{% if flow %}\nimport os\n{% endif %}\nprint({{value}})\n"),
        ("templates/data.json", '{"count": {{count}}}'),
    ],
)
def test_template_placeholders_are_recognized(rel, text):
    assert unrendered_template(rel, text)


@pytest.mark.parametrize(
    ("rel", "text"),
    [
        ("templates/crew/crew.py", "class {{crew_name}}(:\n"),  # broken past its placeholders
        ("templates/crew/crew.py", "def f(:\n"),  # no placeholder at all
        ("templates/crew/crew.py", "x = '{{name}}'\n"),  # parses as written
        ("templates/crew/README.md", "{{name}}\n"),  # a format not judged
    ],
)
def test_other_files_are_not_templates(rel, text):
    assert not unrendered_template(rel, text)


def test_crewai_templates_under_ordinary_names_are_budgeted(tmp_path, run_connector):
    _project(tmp_path, {"templates/crew/crew.py": CREW, "templates/crew/pyproject.toml": PYPROJECT})
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.incomplete, (ctx.stats.errors, ctx.stats.warnings)
    assert sorted(_gaps(ctx)) == [
        ("templates/crew/crew.py", "partial", "unparsed-input"),
        ("templates/crew/pyproject.toml", "partial", "unparsed-input"),
    ]
    assert any("parses once its placeholders are filled in" in w for w in ctx.stats.warnings)
    assert any(finding.kind == Kind.AGENT or "framework.crewai" in finding.frameworks for finding in findings)


def test_broken_source_beside_a_placeholder_still_fails(tmp_path, run_connector):
    _project(tmp_path, {"templates/crew/crew.py": "class {{crew_name}}(:\n    pass\n"})
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete


def test_strict_accounting_keeps_a_content_template_a_gap(tmp_path, run_connector):
    _project(tmp_path, {"templates/crew/crew.py": CREW})
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, strict_coverage=True)
    assert ctx.stats.incomplete


def test_a_tree_of_templates_exhausts_the_budget(tmp_path, run_connector):
    for i in range(3):
        (tmp_path / f"t{i}.py").write_text(CREW)
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete and not ctx.stats.coverage["within_budget"]


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


# ------------------------------------------------------------ large modules


def test_a_module_of_90000_nodes_is_bound(tmp_path, run_connector):
    # litellm/proxy/proxy_server.py: 90,611 nodes and more source calls than the old bound of 512.
    body = "".join(
        f"def handler_{i}(request):\n"
        f"    limits = [{i}, {i} + 1, {i} + 2, {i} + 3, {i} + 4, {i} + 5, {i} + 6, {i} + 7]\n"
        f"    return client.chat(model=request.m{i}, x=limits)\n"
        for i in range(1_000)
    )
    source = "from openai import OpenAI\nclient = OpenAI()\n" + body
    (tmp_path / "proxy_server.py").write_text(source)

    nodes = sum(1 for _ in ast.walk(ast.parse(source)))
    assert 50_000 < nodes < MAX_AST_NODES
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.incomplete, (ctx.stats.errors, ctx.stats.warnings)
    assert findings
    assert MAX_BOUND_CALLS == 2_048
