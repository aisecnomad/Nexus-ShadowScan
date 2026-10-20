"""The CLI exit-code contract: 0 pass, 1 not run, 2 --fail-on reached, 3 incomplete scan."""

from __future__ import annotations

import json
import subprocess
import sys

import click
import pytest
from click.testing import CliRunner

from shadowscan.cli import main


@pytest.mark.parametrize(
    "args",
    [
        ["code", "{repo}", "--min-confidence", "1.5", "--fail-on", "high"],
        ["code", "{missing}", "--fail-on", "high"],
        ["scan", "-c", "{missing}", "--fail-on", "high"],
        ["scan", "-c", "{bad_threshold}", "--fail-on", "high"],
        ["scan", "--fail-on", "high"],
        ["code", "{repo}", "--fail-on", "severe"],
        ["code", "{repo}", "--fail-on", "high", "--no-such-option"],
        ["--no-such-option", "code", "{repo}"],
        ["sacn", "-c", "{missing}"],
        ["run", "no.such.connector", "--fail-on", "high"],
        ["code", "--fail-on", "high"],
        ["inventory"],
        [],
    ],
)
def test_usage_errors_exit_1_not_the_fail_on_code(tmp_path, args):
    # Exit 2 means a complete scan reached --fail-on. A command that never
    # scanned anything must not be readable as that policy result.
    (tmp_path / "requirements.txt").write_text("crewai==0.80.0\n")
    bad_threshold = tmp_path / "scan.yaml"
    bad_threshold.write_text("options:\n  min_confidence: 1.5\nconnectors: []\n")
    values = {"repo": tmp_path, "missing": tmp_path / "missing.yaml", "bad_threshold": bad_threshold}
    result = CliRunner().invoke(main, [arg.format(**values) for arg in args])
    assert result.exit_code == 1, result.output
    assert isinstance(result.exception, SystemExit)
    assert "Usage:" in result.output and "Traceback" not in result.output


def test_usage_error_text_is_unchanged(tmp_path):
    result = CliRunner().invoke(main, ["code", str(tmp_path), "--fail-on", "severe"], prog_name="shadowscan")
    assert result.exit_code == 1
    assert result.output.startswith(
        "Usage: shadowscan code [OPTIONS] [PATHS]...\nTry 'shadowscan code --help' for help.\n\n"
        "Error: Invalid value for '--fail-on': 'severe' is not one of"
    )


@pytest.mark.parametrize(
    "args,message",
    [(["code", "--fail-on", "severe"], "'severe' is not one of"), (["scan"], "Missing option '--config'")],
)
def test_embedded_callers_still_receive_a_click_usage_error(args, message):
    with pytest.raises(click.UsageError) as failure:
        main.main(args, standalone_mode=False)
    assert failure.value.exit_code == 1
    assert message in failure.value.format_message()
    assert str(failure.value)


@pytest.mark.parametrize("args", [["--help"], ["--version"], ["scan", "--help"], ["inventory", "--help"]])
def test_help_and_version_exit_0(args):
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 0, result.output


def test_configuration_error_exits_1(tmp_path):
    config = tmp_path / "scan.yaml"
    config.write_text("connectors: [ unterminated\n")
    result = CliRunner().invoke(main, ["scan", "-c", str(config), "--fail-on", "high"])
    assert result.exit_code == 1, result.output
    assert "invalid scan configuration" in result.output


def test_complete_scan_exits_2_only_when_fail_on_is_reached(tmp_path):
    (tmp_path / "requirements.txt").write_text("crewai==0.80.0\n")
    reached = CliRunner().invoke(main, ["code", str(tmp_path), "--format", "json", "--fail-on", "low"])
    assert reached.exit_code == 2, reached.output
    passed = CliRunner().invoke(main, ["code", str(tmp_path), "--format", "json", "--fail-on", "medium"])
    assert passed.exit_code == 0, passed.output


def test_incomplete_scan_exits_3_and_names_the_reason_category(tmp_path):
    # The stderr line names reason categories only, never a path or a value,
    # so it can reach a CI log the private report does not.
    (tmp_path / "requirements.txt").write_text("crewai==0.80.0\n")
    (tmp_path / "tests" / "fixtures").mkdir(parents=True)
    (tmp_path / "tests" / "fixtures" / "contract.json").write_text("x: " + "y" * 400 + "\n")
    result = CliRunner().invoke(
        main,
        ["run", "code.filesystem", "-S", f"path={tmp_path}", "-S", "max_file_size=100", "--format", "json"],
    )
    assert result.exit_code == 3, result.output
    assert "scan incomplete (exit 3): oversize-file 1" in result.stderr
    assert "contract.json" not in result.stderr
    assert "raise the limit with --max-file-size BYTES" in " ".join(result.stderr.split())
    assert json.loads(result.stdout)["summary"]["incomplete_reasons"] == {"oversize-file": 1}


def test_exit_3_line_names_undecodable_source_as_unparsed_input_whatever_its_path(tmp_path):
    # The path names an upstream error, a denial and a deadline; the file's own
    # gap is content that could not be decoded.
    (tmp_path / "requirements.txt").write_text("crewai==0.80.0\n")
    (tmp_path / "src" / "403" / "deadline").mkdir(parents=True)
    (tmp_path / "src" / "403" / "deadline" / "http_client.py").write_bytes(b"import os\x00\n")
    result = CliRunner().invoke(main, ["code", str(tmp_path), "--format", "json"])
    assert result.exit_code == 3, result.output
    assert "scan incomplete (exit 3): unparsed-input 1;" in result.stderr
    assert json.loads(result.stdout)["summary"]["incomplete_reasons"] == {"unparsed-input": 1}
    assert "did not parse or decode" in " ".join(result.stderr.split())


def test_ci_profile_turns_a_declared_omission_into_exit_0(tmp_path):
    (tmp_path / "requirements.txt").write_text("crewai==0.80.0\n")
    (tmp_path / "docs").mkdir(parents=True)
    (tmp_path / "docs" / "contract.json").write_text("x: " + "y" * 400 + "\n")
    # Credential detection off: an oversize file it would have read is never declared.
    settings = ["-S", f"path={tmp_path}", "-S", "max_file_size=100", "-S", "scan_secrets=false"]
    settings += ["--format", "json"]
    gap = CliRunner().invoke(main, ["run", "code.filesystem", *settings])
    assert gap.exit_code == 3, gap.output
    declared = CliRunner().invoke(main, ["run", "code.filesystem", "-S", "profile=ci", *settings])
    assert declared.exit_code == 0, declared.output
    report = json.loads(declared.stdout)
    assert report["summary"]["declared_omissions"] == 1 and report["summary"]["incomplete_reasons"] == {}
    assert report["stats"][0]["declared_omissions"] == 1
    # A gap in source still exits 3 under the profile, and the two flags conflict.
    (tmp_path / "settings.json").write_text("x: " + "y" * 400 + "\n")
    source_gap = CliRunner().invoke(main, ["run", "code.filesystem", "-S", "profile=ci", *settings])
    assert source_gap.exit_code == 3, source_gap.output
    conflict = CliRunner().invoke(main, ["code", str(tmp_path), "--profile", "ci", "--strict-coverage"])
    assert conflict.exit_code == 1 and "--profile ci and --strict-coverage conflict" in conflict.output


def test_ci_profile_exits_3_for_a_gap_in_a_deployable_project_named_demo(tmp_path):
    # demo/ holds its own manifest: a deployable project, reported at full
    # weight, so a NUL byte hiding its tool code is not a declared omission.
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "root"\nversion = "0.1"\n')
    (tmp_path / "demo").mkdir()
    (tmp_path / "demo" / "pyproject.toml").write_text(
        '[project]\nname = "support-agent"\nversion = "1.0"\ndependencies = ["openai-agents"]\n'
    )
    (tmp_path / "demo" / "tools.py").write_bytes(b"from agents import function_tool\n\x00\n@function_tool\n")
    result = CliRunner().invoke(main, ["code", str(tmp_path), "--profile", "ci", "-f", "json"])
    assert result.exit_code == 3, result.output
    # Without that manifest demo/ is sample code whose gap the profile declares.
    (tmp_path / "demo" / "pyproject.toml").unlink()
    result = CliRunner().invoke(main, ["code", str(tmp_path), "--profile", "ci", "-f", "json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["summary"]["declared_omissions"] == 1


def test_module_entry_point_exits_1_on_a_usage_error(tmp_path):
    result = subprocess.run(
        [sys.executable, "-m", "shadowscan", "code", str(tmp_path), "--min-confidence", "1.5"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 1, result.stderr
    assert "min_confidence must be a finite number between 0 and 1" in result.stderr
