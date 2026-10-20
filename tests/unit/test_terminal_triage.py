from __future__ import annotations

import io
import json

import pytest
from click.testing import CliRunner
from rich.console import Console

from shadowscan.cli import main
from shadowscan.cli._triage import _browse
from shadowscan.models import Finding, Kind, Risk, RiskLevel, ScanResult, ScanStats, Surface


def _result(*, complete=True, count=1):
    return ScanResult(
        findings=[
            Finding(
                surface=Surface.CODE,
                kind=Kind.AGENT,
                connector="code.filesystem",
                resource_type="repository",
                title=f"agent {i} [bold]literal[/bold]\x1b]0;injected\x07",
                resource=f"service-{i}",
                risk=Risk(score=70, level=RiskLevel.HIGH),
            )
            for i in range(count)
        ],
        stats=[
            ScanStats(
                started_at="2026-10-20T09:00:00+00:00", connector="code.filesystem", incomplete=not complete
            )
        ],
    )


@pytest.mark.parametrize("complete,code", [(True, 0), (False, 3)])
def test_filter_does_not_erase_incomplete_status(tmp_path, complete, code):
    report = tmp_path / "report.json"
    report.write_text(_result(complete=complete).to_json())
    before = report.read_bytes()
    result = CliRunner().invoke(main, ["triage", str(report), "--list", "--search", "no match"])
    assert result.exit_code == code, result.output
    assert "0 matching findings" in result.output
    assert ("INCOMPLETE" in result.output) is (not complete)
    assert report.read_bytes() == before


def test_triage_refuses_duplicate_keys_and_symlinks(tmp_path):
    report = tmp_path / "report.json"
    report.write_text('{"findings":[],"findings":[]}')
    assert CliRunner().invoke(main, ["triage", str(report), "--list"]).exit_code == 1
    report.write_text(_result().to_json())
    link = tmp_path / "alias.json"
    link.symlink_to(report)
    assert CliRunner().invoke(main, ["triage", str(link), "--list"]).exit_code == 1


def test_forged_complete_summary_cannot_clear_failed_connector(tmp_path):
    document = _result(complete=False).to_dict()
    document["summary"]["complete"] = True
    document["summary"]["status"] = "complete"
    report = tmp_path / "report.json"
    report.write_text(json.dumps(document))
    result = CliRunner().invoke(main, ["triage", str(report), "--list"])
    assert result.exit_code == 3
    assert "INCOMPLETE" in result.output


def test_browser_pages_searches_and_displays_literal_untrusted_values(monkeypatch):
    commands = iter(["n", "1", "/service-0", "1", "all", "p", "unknown", "q"])
    monkeypatch.setattr("click.prompt", lambda *args, **kwargs: next(commands))
    stream = io.StringIO()
    _browse(Console(file=stream, width=220, color_system=None), _result(count=12), None, "")
    output = stream.getvalue()
    assert "page 2" in output
    assert "1 matching findings" in output
    assert "service-10" in output
    assert "[bold]literal[/bold]" in output
    assert "\x1b" not in output and "\x07" not in output
    assert "Use n, p" in output


def test_browser_eof_keeps_report_status(monkeypatch):
    def abort(*args, **kwargs):
        raise EOFError

    monkeypatch.setattr("click.prompt", abort)
    stream = io.StringIO()
    _browse(Console(file=stream), _result(complete=False), None, "")
    assert "INCOMPLETE" in stream.getvalue()
