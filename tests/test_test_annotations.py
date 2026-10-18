"""tools.test_annotations names each failing test as a GitHub Actions error annotation."""

from __future__ import annotations

from pathlib import Path

from tools import test_annotations

_REPORT = """<?xml version="1.0" encoding="utf-8"?>
<testsuites><testsuite name="pytest" errors="1" failures="2" tests="4">
<testcase classname="tests.unit.test_plugin_process" name="test_worker_starts" file="tests/unit/test_plugin_process.py" line="41">
<failure message="AssertionError: worker exited 1, expected 0&#10;more detail" type="AssertionError">trace</failure>
</testcase>
<testcase classname="tests.unit.test_plugin_process.TestLifecycle" name="test_kill[a,b:c]" file="tests/unit/test_plugin_process.py" line="99">
<failure message="secret = &quot;{key}&quot;" type="builtins.ValueError">trace</failure>
</testcase>
<testcase classname="tests.unit.test_other" name="test_setup_breaks"><error message="fixture 'x' not found" type="pytest.FixtureLookupError"/></testcase>
<testcase classname="tests.unit.test_other" name="test_passes"/>
</testsuite></testsuites>
"""


def _report(tmp_path: Path, key: str = "") -> Path:
    path = tmp_path / "junit.xml"
    path.write_text(_REPORT.replace("{key}", key), encoding="utf-8")
    return path


def test_each_failure_and_error_becomes_one_annotation(tmp_path, capsys):
    assert test_annotations.main([str(_report(tmp_path))]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == (
        "::error file=tests/unit/test_plugin_process.py,line=42,"
        "title=tests/unit/test_plugin_process.py%3A%3Atest_worker_starts"
        "::AssertionError: AssertionError: worker exited 1, expected 0"
    )
    # Node ids keep the class; commas and colons in a parameter id are escaped.
    assert "title=tests/unit/test_plugin_process.py%3A%3ATestLifecycle%3A%3Atest_kill[a%2Cb%3Ac]" in lines[1]
    assert '::ValueError: secret = "[REDACTED]"' in lines[1]
    assert lines[2].endswith("::FixtureLookupError: fixture 'x' not found")
    assert len(lines) == 3


def test_a_credential_in_a_failure_message_is_withheld(tmp_path, capsys):
    key = "sk-" + "proj-" + "Zx9" * 16
    test_annotations.main([str(_report(tmp_path, key))])
    out = capsys.readouterr().out
    assert key not in out and "[REDACTED]" in out


def test_annotations_are_bounded_and_missing_reports_are_ignored(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(test_annotations, "MAX_ANNOTATIONS", 2)
    assert test_annotations.main([str(_report(tmp_path)), str(tmp_path / "absent.xml")]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 3 and lines[-1].startswith("1 more failing test(s)")


def test_a_newline_in_a_message_cannot_start_a_second_workflow_command(tmp_path):
    failure = test_annotations.Failure("t::x", "", None, "Error", "a\n::warning::forged")
    command = test_annotations.annotation(failure)
    assert "\n" not in command and command.count("::") == 4
