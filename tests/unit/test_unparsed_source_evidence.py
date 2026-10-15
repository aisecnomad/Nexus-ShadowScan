"""An unavailable Python parse cannot promote lexical patterns into semantic findings."""

from __future__ import annotations

import ast
import json

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.connectors.code import filesystem
from shadowscan.connectors.code.source_semantics import SourceBudgetExceeded, SourceNotParsed
from shadowscan.models import Kind

GRAPH = """from langgraph.graph import StateGraph
from typing import TypedDict

class State(TypedDict):
    messages: list

def make_graph():
    graph = StateGraph(State)
    graph.add_node("agent", lambda state: state)
    graph.set_entry_point("agent")
    return graph.compile()
"""
AGENT = "from langgraph.prebuilt import create_react_agent\napp = create_react_agent(model, tools)\n"
MCP = """from mcp.server.fastmcp import FastMCP
mcp = FastMCP("ops")

@mcp.tool()
def run_command(command: str) -> str:
    return command
"""


def _notebook(*cells: str) -> str:
    return json.dumps({"cells": [{"cell_type": "code", "source": [cell]} for cell in cells]})


def test_newer_python_syntax_never_promotes_a_fixed_graph(tmp_path, run_connector, fixtures):
    """PEP 696 is valid on 3.13; older supported interpreters must disclose the missing parse."""
    source = (fixtures / "code/unparsed_source/workflow_py313.py").read_text()
    try:
        ast.parse(source)
    except SyntaxError:
        supported = False
    else:
        supported = True
    (tmp_path / "workflow.py").write_text(source)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert findings and all(f.kind == Kind.FRAMEWORK_USAGE for f in findings)
    assert all(not f.capabilities for f in findings)
    assert ctx.stats.incomplete is not supported
    assert bool(ctx.stats.warnings) is not supported
    assert not ctx.stats.errors
    if not supported:
        assert any(e.attributes.get("source_analysis") == "unparsed" for f in findings for e in f.evidence)


@pytest.mark.parametrize("source", [GRAPH, AGENT, MCP], ids=["fixed-graph", "agent", "mcp-tools"])
@pytest.mark.parametrize("granularity", ["project", "source"])
def test_parser_failure_cannot_restore_semantics_through_another_pass(
    tmp_path, run_connector, monkeypatch, source, granularity
):
    # The source is parseable, so the independent MCP-name pass would otherwise
    # restore tool capabilities after the required semantic pass rejected it.
    def unavailable(*args, **kwargs):
        raise SourceNotParsed("source did not parse")

    monkeypatch.setattr(filesystem, "bound_source_matches", unavailable)
    (tmp_path / "app.py").write_text(source)
    findings, ctx = run_connector(
        "code.filesystem", path=str(tmp_path), use_git=False, agent_granularity=granularity
    )
    assert ctx.stats.incomplete
    assert findings and all(f.kind == Kind.FRAMEWORK_USAGE for f in findings)
    assert all(not f.capabilities for f in findings)
    assert all(not f.metadata.get("agent_indicators") for f in findings)
    assert all("mcp_tools" not in f.metadata and "mcp_server" not in f.metadata for f in findings)
    assert any(e.attributes.get("source_analysis") == "unparsed" for f in findings for e in f.evidence)


def test_unparsed_file_keeps_a_valid_neighbor_agent(tmp_path, run_connector):
    (tmp_path / "broken.py").write_text(MCP + "def broken(:\n    pass\n")
    (tmp_path / "agent.py").write_text(AGENT)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete
    agent = next(f for f in findings if f.kind == Kind.AGENT)
    assert "framework.langgraph" in agent.frameworks
    assert "mcp-server" not in agent.capabilities and "code-exec" not in agent.capabilities
    assert "mcp_tools" not in agent.metadata and "mcp_server" not in agent.metadata
    assert any(e.location == "agent.py:2" for e in agent.evidence)


def test_notebook_retains_parsed_agent_but_no_unparsed_tool_capabilities(tmp_path, run_connector, fixtures):
    (tmp_path / "agent.ipynb").write_bytes((fixtures / "code/unparsed_source/mixed_cells.ipynb").read_bytes())
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete
    agent = next(f for f in findings if f.kind == Kind.AGENT)
    assert "framework.langgraph" in agent.frameworks
    assert "mcp-server" not in agent.capabilities and "code-exec" not in agent.capabilities
    assert "mcp_tools" not in agent.metadata and "mcp_server" not in agent.metadata
    assert any(e.attributes.get("source_analysis") == "unparsed" for e in agent.evidence)


def test_notebook_retains_only_tools_from_parsed_cells(tmp_path, run_connector):
    setup = 'from mcp.server.fastmcp import FastMCP\nmcp = FastMCP("notes")\n'
    good = "@mcp.tool()\ndef list_notes():\n    return []\n"
    bad = "@mcp.tool()\ndef run_command(command):\n    return command\ndef broken(:\n    pass\n"
    (tmp_path / "server.ipynb").write_text(_notebook(setup, bad, good))
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete
    server = next(f for f in findings if "protocol.mcp" in f.frameworks)
    assert server.metadata["mcp_tools"] == ["list_notes"]
    assert "mcp-server" in server.capabilities and "code-exec" not in server.capabilities
    assert server.metadata["mcp_server"]["constructions"]


def test_notebook_parse_gap_survives_a_later_discounted_test_budget(tmp_path, run_connector, monkeypatch):
    def exhausted(*args, **kwargs):
        raise SourceBudgetExceeded("source binding AST limit exceeded")

    monkeypatch.setattr(filesystem, "bound_source_matches", exhausted)
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_agent.ipynb").write_text(_notebook('print "legacy"\n', AGENT))
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, include_tests=False)
    # The historical test-only AST limit is a non-incomplete warning; the
    # independently observed syntax failure must still remain incomplete.
    assert ctx.stats.incomplete
    assert any("notebook cell 1" in warning for warning in ctx.stats.warnings)
    assert any("AST limit exceeded" in warning for warning in ctx.stats.warnings)


def test_unparsed_source_without_a_finding_still_exits_incomplete(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "plain.py").write_text('print "legacy syntax without AI"\n')
    report = tmp_path / "report.json"
    result = CliRunner().invoke(main, ["code", str(root), "--format", "json", "-o", str(report)])
    assert result.exit_code == 3
    document = json.loads(report.read_text())
    assert not document["findings"]
    assert document["stats"][0]["incomplete"]
    assert any("source did not parse" in warning for warning in document["stats"][0]["warnings"])
