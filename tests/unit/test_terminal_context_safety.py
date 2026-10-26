"""Repository and provider text is inert in terminal output."""

from __future__ import annotations

from io import StringIO

import pytest
from click.testing import CliRunner
from rich.console import Console

from shadowscan.cli import main
from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.engine import Engine
from shadowscan.models import Evidence, Finding, Kind, RiskFactor, ScanResult, ScanStats, Surface
from shadowscan.reporters.table import print_table
from shadowscan.utils.output import terminal_text


@pytest.mark.parametrize(
    "control", ["\x1b[2J", "\x1b]52;c;dGVzdA==\x07", "\x9b2J", "\r", "\x08", "\u202e", "\u2066"]
)
@pytest.mark.parametrize("terminal", [False, True])
def test_terminal_fields_do_not_emit_attacker_controls(control, terminal):
    unsafe = f"before{control}after"
    finding = Finding(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.AGENT,
        title=unsafe,
        resource=unsafe,
        resource_type="project",
        owner=unsafe,
        registry_match=unsafe,
        shadow=False,
        capabilities=[unsafe],
        frameworks=[unsafe],
        metadata={"runtime_activity": {"status": unsafe}},
        evidence=[Evidence("import", unsafe, location=unsafe)],
    )
    finding.risk.factors = [RiskFactor("example", unsafe, 5)]
    result = ScanResult(
        findings=[finding],
        inventory_size=1,
        version=unsafe,
        finished_at=unsafe,
        stats=[ScanStats(connector=unsafe, started_at="2026-09-25", errors=[unsafe], warnings=[unsafe])],
    )
    output = StringIO()
    print_table(
        result, Console(file=output, force_terminal=terminal, color_system=None, width=240), verbose=True
    )
    rendered = output.getvalue()
    assert control not in rendered
    assert "\\u" in rendered
    assert "before" in rendered and "after" in rendered


def test_engine_repository_filename_is_inert_in_verbose_output(tmp_path):
    (tmp_path / "agent\x1b[2J.py").write_text("from crewai import Agent\n", encoding="utf-8")
    result = Engine(
        ScanConfig(
            connectors=[
                ConnectorSpec(
                    "code.filesystem",
                    {
                        "path": str(tmp_path),
                        "use_git": False,
                    },
                )
            ]
        )
    ).run()
    assert result.complete and result.findings
    output = StringIO()
    print_table(result, Console(file=output, force_terminal=False, width=240), verbose=True)
    assert "\x1b[2J" not in output.getvalue()
    assert r"agent\u001b[2J.py:1" in output.getvalue()


@pytest.mark.parametrize("control", ["\x1b]52;c;dGVzdA==\x07", "\x9b2J"])
@pytest.mark.parametrize(
    "command",
    [
        ["inventory", "check", "{cards}"],
        ["code", "{src}", "-i", "{cards}", "-f", "json"],
        ["merge", "{stale}", "{current}", "-f", "json"],
        ["controls", "{stale}", "{current}", "-f", "json"],
        ["dashboard", "{stale}", "{current}", "-o", "{out}"],
    ],
)
def test_untrusted_file_name_in_a_cli_error_is_inert(tmp_path, command, control):
    # Click strips only CSI sequences, and only off a terminal: an OSC clipboard write
    # or a C1 control in a card or report file name reached stderr as it was.
    cards = tmp_path / "agents"
    cards.mkdir()
    (cards / f"card{control}.yaml").write_text("agents: [unclosed\n", encoding="utf-8")
    (tmp_path / "src").mkdir()
    stale = tmp_path / f"host{control}.json"
    stale.write_text('{"findings": [], "finding_identity_schema": "legacy"}', encoding="utf-8")
    (tmp_path / "current.json").write_text('{"findings": []}', encoding="utf-8")
    paths = {"cards": cards, "src": tmp_path / "src", "stale": stale}
    paths |= {"current": tmp_path / "current.json", "out": tmp_path / "dashboard.html"}

    result = CliRunner().invoke(main, [arg.format_map(paths) for arg in command])

    assert result.exit_code == 1, result.output
    assert control not in result.output
    assert terminal_text(control) in result.stderr
