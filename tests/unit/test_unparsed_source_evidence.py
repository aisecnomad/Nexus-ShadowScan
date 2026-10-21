"""An unavailable Python parse cannot promote lexical patterns into semantic findings."""

from __future__ import annotations

import ast
import json

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.connectors.code import file_scan
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

    monkeypatch.setattr(file_scan, "bound_source_matches", unavailable)
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


@pytest.mark.parametrize(
    ("directory", "options", "incomplete"),
    [
        ("tests", {}, False),
        ("tests", {"strict_coverage": True}, True),
        ("tests", {"include_tests": True}, True),
        ("src", {}, True),
    ],
    ids=["discounted-test", "strict-test", "included-test", "source"],
)
def test_notebook_parse_gap_survives_a_later_budget_failure(
    tmp_path, run_connector, monkeypatch, directory, options, incomplete
):
    def exhausted(*args, **kwargs):
        raise SourceBudgetExceeded("source binding AST limit exceeded")

    monkeypatch.setattr(file_scan, "bound_source_matches", exhausted)
    (tmp_path / directory).mkdir()
    (tmp_path / directory / "test_agent.ipynb").write_text(_notebook('print "legacy"\n', AGENT))
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, **options)
    # The syntax failure is reported before binding, so the budget failure that then stops
    # the binder cannot erase it. Discounted test code warns of both without a gap (unless
    # strict_coverage); elsewhere both leave coverage incomplete.
    diagnostics = ctx.stats.warnings + ctx.stats.errors
    assert any("notebook cell 1" in message for message in diagnostics)
    assert any("AST limit exceeded" in message for message in diagnostics)
    assert ctx.stats.incomplete is incomplete


@pytest.mark.parametrize(
    ("rel", "options", "incomplete"),
    [
        ("tests/fixtures/bad_syntax.py", {}, False),
        ("tests/fixtures/bad_syntax.py", {"strict_coverage": True}, True),
        ("tests/fixtures/bad_syntax.py", {"include_tests": True}, True),
        ("test_parser_errors.py", {}, False),
        ("app/bad_syntax.py", {}, True),
        ("templates/{{cookiecutter.slug}}/main.py", {}, True),
    ],
)
def test_unparsed_source_in_a_discounted_test_path_only_warns(
    tmp_path, run_connector, rel, options, incomplete
):
    """Regression: a deliberately invalid fixture under a test path the scan discounts made the
    scan incomplete; it now warns, as a test file over the binder's budget does, while invalid
    source elsewhere (a Python 2 module, a template) stays a coverage gap until excluded."""
    (tmp_path / "agent.py").write_text(AGENT)
    target = tmp_path / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("{% if cookiecutter.flag %}import os{% endif %}\ndef f(:\n    pass\n")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, **options)
    # Python under a template-named directory runs as written: it is a template only by its
    # content, and an inline tag does not render, so it is judged as any other source.
    message = f"code.filesystem: {rel}: import-bound analysis skipped (source did not parse); lexical evidence retained"
    assert ctx.stats.warnings == [message]
    assert ctx.stats.incomplete is incomplete
    assert any(finding.kind == Kind.AGENT for finding in findings)


def test_excluded_invalid_source_is_not_read(tmp_path, run_connector):
    (tmp_path / "agent.py").write_text(AGENT)
    (tmp_path / "legacy").mkdir()
    (tmp_path / "legacy" / "py2.py").write_text('print "hello"\n')
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, exclude=["legacy/**"])
    assert not ctx.stats.warnings and not ctx.stats.incomplete


@pytest.mark.parametrize(
    "metadata",
    [
        {"kernelspec": {"display_name": "R", "language": "R", "name": "ir"}, "language_info": {"name": "R"}},
        {"language_info": {"name": "julia"}},
        {"kernelspec": {"name": "ir", "language": "R"}},
    ],
)
def test_a_notebook_with_another_kernel_language_is_not_parsed_as_python(tmp_path, run_connector, metadata):
    """Regression: every notebook was parsed as Python, so an R or Julia notebook made the scan
    incomplete. Its cells are lexical evidence only."""
    (tmp_path / "agent.py").write_text(AGENT)
    cells = ["library(dplyr)\ndf %>% filter(x > 1)\n", 'println("it\'s done")\n']
    document = {"cells": [{"cell_type": "code", "source": [cell]} for cell in cells], "metadata": metadata}
    (tmp_path / "analysis.ipynb").write_text(json.dumps(document))
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.warnings and not ctx.stats.incomplete
    assert any(finding.kind == Kind.AGENT for finding in findings)


# An agent with code-execution tools, in one notebook cell.
TOOL_AGENT = (
    "from langchain.agents import AgentExecutor, create_tool_calling_agent\n"
    "from langchain_openai import ChatOpenAI\n"
    "from langchain_experimental.tools import PythonREPLTool\n"
    "from langchain_community.tools import ShellTool\n"
    "import subprocess\n"
    "\n"
    'llm = ChatOpenAI(model="gpt-4o")\n'
    "tools = [PythonREPLTool(), ShellTool()]\n"
    "agent = create_tool_calling_agent(llm, tools, prompt)\n"
    "executor = AgentExecutor(agent=agent, tools=tools)\n"
    'executor.invoke({"input": "clean up the disk"})\n'
    'subprocess.run(["rm", "-rf", "/tmp/x"])\n'
)
PYTHON_KERNEL = {"kernelspec": {"name": "python3", "display_name": "Python 3", "language": "python"}}


@pytest.mark.parametrize(
    ("metadata", "magic"),
    [
        (PYTHON_KERNEL, ""),
        # Jupyter starts the kernel its name selects, so this cell runs as Python.
        ({"kernelspec": {"name": "python3", "display_name": "Python 3", "language": "R"}}, ""),
        # The repository writes the metadata and magics: they cannot hide code that parses.
        ({"language_info": {"name": "R"}}, ""),
        ({"kernelspec": {"name": "ir", "language": "R"}, "language_info": {"name": "R"}}, ""),
        (PYTHON_KERNEL, "%%script env python3\n"),
        (PYTHON_KERNEL, "%%script ipython\n"),
        (PYTHON_KERNEL, "%%bash\n"),
    ],
    ids=[
        "python",
        "python-kernel-labelled-r",
        "language-info-r",
        "r-kernel",
        "script-env-python3",
        "script-ipython",
        "bash-magic",
    ],
)
def test_python_in_a_cell_declared_another_language_is_bound(tmp_path, run_connector, metadata, magic):
    """Regression: notebook metadata or a cell magic, which the scanned repository controls, that
    declared another language kept a cell from the import binder however it parsed, so an agent
    with code-execution tools was reported as framework usage without capabilities, on a
    complete scan. A cell is now bound whenever it parses as Python."""
    document = {"cells": [{"cell_type": "code", "source": [magic + TOOL_AGENT]}], "metadata": metadata}
    (tmp_path / "ops.ipynb").write_text(json.dumps(document))
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.warnings and not ctx.stats.incomplete
    [agent] = [finding for finding in findings if finding.kind == Kind.AGENT]
    assert {"code-exec", "tool-use"} <= set(agent.capabilities)


@pytest.mark.parametrize(
    "metadata",
    [
        {},
        {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}},
        {"language_info": {"name": "python"}},
        # The kernel's name, not its language label, says what runs the cells.
        {"kernelspec": {"name": "python3", "language": "R"}, "language_info": {"name": "R"}},
        {"kernelspec": {"name": "conda-env-agents-py", "language": "julia"}},
    ],
)
def test_a_python_notebook_cell_that_does_not_parse_stays_a_gap(tmp_path, run_connector, metadata):
    document = {"cells": [{"cell_type": "code", "source": ['print "legacy"\n']}], "metadata": metadata}
    (tmp_path / "analysis.ipynb").write_text(json.dumps(document))
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete
    assert any("notebook cell 1" in warning for warning in ctx.stats.warnings)


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
