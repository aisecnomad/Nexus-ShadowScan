"""`shadowscan code --preflight`, `--max-file-size` and the remediation that follows an exit 3.

A first scan of a large repository used to end in exit 3 with a list of reason
categories and nothing more. After its readiness check, the preflight lists the
static coverage gaps a full scan would record (files over the size limit, links,
non-regular entries) without reading any other content, using the scanner's own
walk and accounting, so it can only agree with the scan it predicts. It reports
no finding (``scan_performed: false``), so its output can never be read as a
clean scan.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from shadowscan.cli import _REMEDIATION, _remediation_lines, main
from shadowscan.connectors.code.file_scan import FileScanner
from shadowscan.coverage import INCOMPLETE_REASONS

# A JSON document whose bytes may name an MCP server table: unread, it could hide
# agent configuration, so a full scan records a blinding gap whatever the budget.
OVERSIZE_MCP = json.dumps({"mcpServers": {}, "rows": ["v" * 60] * 300})
LIMIT = 4_000


def _project(root: Path, extra: dict[str, str] | None = None) -> Path:
    (root / "src").mkdir(parents=True, exist_ok=True)
    (root / "requirements.txt").write_text("crewai==0.80.0\n")
    (root / "src" / "app.py").write_text("from crewai import Agent\nagent = Agent(role='r', goal='g')\n")
    for rel, text in (extra or {}).items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return root


def _invoke(*args: str):
    return CliRunner().invoke(main, ["code", *args])


def _gaps(*args: str) -> tuple[int, dict]:
    """Run a JSON preflight and return its exit code and the first root's static gaps."""
    result = _invoke(*args, "--preflight", "--format", "json")
    report = json.loads(result.stdout)
    assert report["scan_performed"] is False and "findings" not in report
    return result.exit_code, report["roots"][0]["static_gaps"]


def test_preflight_of_a_tree_without_static_gaps_exits_0_and_reports_no_finding(tmp_path):
    repo = _project(tmp_path)
    code, gaps = _gaps(str(repo))
    assert code == 0
    assert gaps["reasons"] == {} and gaps["files"] == []
    table = _invoke(str(repo), "--preflight")
    assert table.exit_code == 0, table.output
    assert "static gaps: none found" in table.stdout
    assert "no scan performed" in table.stdout


def test_preflight_predicts_the_oversize_gap_a_full_scan_records(tmp_path):
    repo = _project(tmp_path, {"data/servers.json": OVERSIZE_MCP})
    code, gaps = _gaps(str(repo), "--max-file-size", str(LIMIT))
    assert code == 3
    assert gaps["reasons"] == {"oversize-file": 1}
    assert gaps["files"] == [{"path": "data/servers.json", "reason": "oversize-file"}]
    table = _invoke(str(repo), "--preflight", "--max-file-size", str(LIMIT))
    assert table.exit_code == 3, table.output
    assert "oversize-file 1" in table.stdout and "data/servers.json" in table.stdout
    remedy = " ".join(table.stderr.split())
    assert "to resolve:" in remedy and "--max-file-size" in remedy
    assert "servers.json" not in table.stderr  # the remediation never names a path
    full = _invoke(str(repo), "--max-file-size", str(LIMIT), "--format", "json")
    assert full.exit_code == 3, full.output
    assert json.loads(full.stdout)["summary"]["incomplete_reasons"] == {"oversize-file": 1}


def test_raising_max_file_size_clears_the_gap_in_the_preflight_and_the_scan(tmp_path):
    repo = _project(tmp_path, {"data/servers.json": OVERSIZE_MCP})
    raised = str(len(OVERSIZE_MCP) + 1)
    assert _gaps(str(repo), "--max-file-size", raised)[0] == 0
    full = _invoke(str(repo), "--max-file-size", raised, "--format", "json")
    assert full.exit_code == 0, full.output
    assert json.loads(full.stdout)["summary"]["complete"] is True


@pytest.mark.parametrize(
    "extra",
    [
        pytest.param({"data/servers.json": OVERSIZE_MCP}, id="oversize-mcp-bytes"),
        pytest.param({"data/plain.json": json.dumps({"rows": ["v" * 60] * 300})}, id="oversize-plain"),
        pytest.param({"package-lock.json": json.dumps({"x": "v" * 6_000})}, id="oversize-skip-glob"),
        pytest.param({"tests/fixtures/servers.json": OVERSIZE_MCP}, id="oversize-test-fixture"),
        pytest.param({"docs/guide.md": "# Guide\n" + "text " * 2_000}, id="oversize-docs"),
        pytest.param({"nb/big.ipynb": json.dumps({"cells": [], "pad": "v" * 6_000})}, id="oversize-notebook"),
    ],
)
def test_preflight_reasons_equal_the_full_scans_on_a_tree_of_static_gaps(tmp_path, extra):
    # The preflight is the full scan's own walk with content analysis left out,
    # so on a tree whose only gaps are static the two agree on every reason.
    repo = _project(tmp_path, extra)
    full = _invoke(str(repo), "--max-file-size", str(LIMIT), "--format", "json")
    expected = json.loads(full.stdout)["summary"]["incomplete_reasons"]
    code, gaps = _gaps(str(repo), "--max-file-size", str(LIMIT))
    assert code == (3 if expected else 0)
    assert gaps["reasons"] == expected


def test_preflight_predicts_an_agent_configuration_link_out_of_the_tree(tmp_path):
    outside = tmp_path / "outside.md"
    outside.write_text("# Rules\n")
    repo = _project(tmp_path / "repo")
    (repo / "AGENTS.md").symlink_to(outside)
    full = _invoke(str(repo), "--format", "json")
    assert json.loads(full.stdout)["summary"]["incomplete_reasons"] == {"unresolved-link": 1}
    code, gaps = _gaps(str(repo))
    assert code == 3
    assert gaps["reasons"] == {"unresolved-link": 1}


def test_preflight_reads_no_file_content(tmp_path, monkeypatch):
    def refuse(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("the preflight analyzed a file")

    monkeypatch.setattr(FileScanner, "scan_file", refuse)
    repo = _project(tmp_path, {"data/servers.json": OVERSIZE_MCP})
    assert _gaps(str(repo), "--max-file-size", str(LIMIT))[0] == 3


def test_preflight_refuses_a_scan_report_format(tmp_path):
    result = _invoke(str(_project(tmp_path)), "--preflight", "--format", "sarif")
    assert result.exit_code == 1, result.output
    assert "--preflight supports --format table or json" in result.output


def test_preflight_applies_to_local_paths_only():
    result = _invoke("--github-repo", "octo/repo", "--preflight")
    assert result.exit_code == 1
    assert "--preflight supports local PATHS only" in result.output


@pytest.mark.parametrize("value", ["0", "-1", "big"])
def test_max_file_size_must_be_a_positive_integer(tmp_path, value):
    result = _invoke(str(tmp_path), "--max-file-size", value)
    assert result.exit_code == 1, result.output
    assert "--max-file-size" in result.output


def test_exit_3_is_followed_by_remediation_that_names_no_path(tmp_path):
    repo = _project(tmp_path, {"data/servers.json": OVERSIZE_MCP})
    result = _invoke(str(repo), "--max-file-size", str(LIMIT), "--format", "json")
    assert result.exit_code == 3
    # The console wraps long lines; the order of the parts is what matters.
    stderr = " ".join(result.stderr.split())
    assert "scan incomplete (exit 3): oversize-file 1" in stderr
    remedy = stderr[stderr.index("to resolve:") :]
    assert stderr.index("scan incomplete (exit 3)") < stderr.index("to resolve:")
    assert "--max-file-size" in remedy and "--exclude" in remedy and "--preflight" in remedy
    assert "servers.json" not in result.stderr and os.fspath(repo) not in result.stderr


def test_every_reason_category_but_other_has_a_remediation():
    assert set(_REMEDIATION) == set(INCOMPLETE_REASONS) - {"other"}
    # In the summary's order (most frequent first), then the guide; a category without one adds nothing.
    lines = _remediation_lines({"timeout": 2, "other": 1, "oversize-file": 1})
    assert [line.split(":")[0].strip() for line in lines] == ["timeout", "oversize-file", "guide"]
    assert _remediation_lines({"other": 1}) == []
