"""The complexity ratchet (``tools/complexity_gate.py``), run for real on small synthetic projects.

Ruff does the measuring, so the projects below hold actual source and the gate calls the actual ruff; only the
checkout root is swapped. The first half exercises the gate with negative controls (growth, slack, a baseline
that cannot be trusted, a ruff that fails). The second half checks this repository against its committed
baseline and that the Makefile, CI and the documents keep describing the same gate.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from tools import complexity_gate as gate
from tools.complexity_gate import MAX_FUNCTION_COMPLEXITY, MAX_MODULE_LINES

ROOT = Path(__file__).resolve().parents[1]
COMMAND = "python -m tools.complexity_gate"
FILE = "shadowscan/a.py"


def branchy(name: str, branches: int, indent: str = "") -> str:
    """A function whose McCabe complexity is ``branches + 1``."""
    body = "".join(f"{indent}    if x == {n}:\n{indent}        x += 1\n" for n in range(branches))
    return f"{indent}def {name}(x):\n{body}{indent}    return x\n"


# `branchy(name, JUST_OVER)` has complexity MAX_FUNCTION_COMPLEXITY + 1, the lowest the gate reports;
# `AT_LIMIT` has exactly MAX_FUNCTION_COMPLEXITY.
JUST_OVER = MAX_FUNCTION_COMPLEXITY
AT_LIMIT = MAX_FUNCTION_COMPLEXITY - 1
OVER = JUST_OVER + 1  # the complexity of branchy(name, JUST_OVER)


def lines_of(count: int, *, newline: str = "\n", final_newline: bool = True) -> str:
    text = newline.join("x = 1" for _ in range(count))
    return text + newline if final_newline else text


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A checkout the gate measures instead of the repository: ruff's own configuration, no sources."""
    (tmp_path / "ruff.toml").write_text("line-length = 110\n", encoding="utf-8")
    for name in (*gate.SOURCE_ROOTS, "tests"):
        (tmp_path / name).mkdir(exist_ok=True)
    monkeypatch.setattr(gate, "ROOT", tmp_path)
    return tmp_path


def write(project: Path, relative: str, text: str) -> None:
    path = project / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="")


def baseline_path(project: Path) -> Path:
    return project / gate.BASELINE


def baseline_data(project: Path) -> dict[str, Any]:
    data = json.loads(baseline_path(project).read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def run(*arguments: str) -> int:
    return gate.main(list(arguments))


def baselined(project: Path, source: str, relative: str = FILE) -> None:
    """Write ``source`` into the project and record it as the accepted state."""
    write(project, relative, source)
    assert run("--rebaseline") == 0


# --- measuring ---------------------------------------------------------------------------------------------


def test_functions_over_the_limit_are_keyed_by_qualified_name(project: Path) -> None:
    write(
        project,
        FILE,
        branchy("flat", JUST_OVER)
        + "\n\nclass Box:\n"
        + branchy("method", JUST_OVER, "    ")
        + "\n\ndef outer(x):\n"
        + branchy("inner", JUST_OVER, "    ")
        + "    return inner(x)\n",
    )
    assert gate.measure_functions(project) == {
        f"{FILE}::flat": OVER,
        f"{FILE}::Box.method": OVER,
        # Ruff counts a nested function into the one around it and reports each on its own.
        f"{FILE}::outer": OVER + 1,
        f"{FILE}::outer.<locals>.inner": OVER,
    }


def test_a_function_at_the_limit_is_not_measured(project: Path) -> None:
    write(project, FILE, branchy("edge", AT_LIMIT))
    assert gate.measure_functions(project) == {}


def test_the_tooling_and_the_benchmarks_are_measured_but_the_tests_are_not(project: Path) -> None:
    for path in ("tools/helper.py", "benchmarks/score.py", "tests/test_big.py"):
        write(project, path, branchy("big", JUST_OVER))
    assert gate.measure_functions(project) == {"tools/helper.py::big": OVER, "benchmarks/score.py::big": OVER}


def test_a_noqa_comment_does_not_hide_a_function(project: Path) -> None:
    write(project, FILE, branchy("quiet", JUST_OVER).replace("def quiet(x):", "def quiet(x):  # noqa: C901"))
    assert gate.measure_functions(project) == {f"{FILE}::quiet": OVER}


def test_a_name_defined_twice_in_a_file_gets_a_ceiling_for_each_definition(project: Path) -> None:
    write(
        project,
        FILE,
        "if __debug__:\n"
        + branchy("twin", JUST_OVER, "    ")
        + "else:\n"
        + branchy("twin", JUST_OVER + 1, "    ")
        + "\n\nclass Box:\n"
        + branchy("twin", JUST_OVER, "    "),
    )
    assert gate.measure_functions(project) == {
        f"{FILE}::twin": OVER,
        f"{FILE}::twin#2": OVER + 1,
        f"{FILE}::Box.twin": OVER,
    }


def test_a_decorated_or_async_function_is_found_on_its_def_line(project: Path) -> None:
    write(
        project,
        FILE,
        "import functools\n\n\n@functools.cache\n@functools.cache\n"
        + branchy("cached", JUST_OVER)
        + "\n\nasync "
        + branchy("slow", JUST_OVER),
    )
    assert gate.measure_functions(project) == {f"{FILE}::cached": OVER, f"{FILE}::slow": OVER}


def test_what_ruff_excludes_stays_excluded(project: Path) -> None:
    (project / "ruff.toml").write_text(
        'line-length = 110\nextend-exclude = ["tools/generated", "shadowscan/generated"]\n', encoding="utf-8"
    )
    write(project, "tools/generated/out.py", branchy("big", JUST_OVER))
    write(project, "shadowscan/generated/out.py", lines_of(MAX_MODULE_LINES + 1))
    assert gate.measure_functions(project) == {}
    assert gate.measure_modules(project) == {}


def test_only_package_modules_over_the_line_limit_are_measured(project: Path) -> None:
    write(project, "shadowscan/big.py", lines_of(MAX_MODULE_LINES + 1))
    write(project, "shadowscan/edge.py", lines_of(MAX_MODULE_LINES))
    write(project, "tools/huge.py", lines_of(MAX_MODULE_LINES + 500))
    write(project, "tests/test_huge.py", lines_of(MAX_MODULE_LINES + 500))
    assert gate.measure_modules(project) == {"shadowscan/big.py": MAX_MODULE_LINES + 1}


@pytest.mark.parametrize(
    ("newline", "final_newline"), [("\n", True), ("\n", False), ("\r\n", True), ("\r\n", False)]
)
def test_lines_are_counted_the_same_with_any_line_ending_and_without_a_final_one(
    project: Path, newline: str, final_newline: bool
) -> None:
    write(
        project,
        "shadowscan/big.py",
        lines_of(MAX_MODULE_LINES + 1, newline=newline, final_newline=final_newline),
    )
    assert gate.measure_modules(project) == {"shadowscan/big.py": MAX_MODULE_LINES + 1}


# --- comparing ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("measured", "ceilings", "grown", "slack"),
    [
        ({"a": 25}, {"a": 25}, [], []),
        ({"a": 26}, {"a": 25}, ["a"], []),
        ({"a": 24}, {"a": 25}, [], ["a"]),
        ({"a": 25, "new": 21}, {"a": 25}, ["new"], []),
        ({"a": 25}, {"a": 25, "gone": 30}, [], ["gone"]),
        ({}, {}, [], []),
        ({"up": 31, "down": 21}, {"up": 30, "down": 22}, ["up"], ["down"]),
    ],
)
def test_compare_names_what_grew_and_what_the_baseline_still_allows(
    measured: dict[str, int], ceilings: dict[str, int], grown: list[str], slack: list[str]
) -> None:
    got_grown, got_slack = gate.compare(measured, ceilings, 20, str)
    assert [line.split(":")[0] for line in got_grown] == grown
    assert [line.split(":")[0] for line in got_slack] == slack


# --- the gate end to end -----------------------------------------------------------------------------------


def test_rebaseline_writes_a_sorted_two_space_json_file_with_a_final_newline(project: Path) -> None:
    write(project, "shadowscan/z.py", branchy("zed", JUST_OVER))
    write(project, FILE, branchy("alpha", JUST_OVER + 1))
    write(project, "shadowscan/big.py", lines_of(MAX_MODULE_LINES + 3))
    assert run("--rebaseline") == 0
    text = baseline_path(project).read_text(encoding="utf-8")
    assert text.endswith("}\n") and not text.endswith("\n\n")
    data = json.loads(text)
    assert data == {
        "schema": 1,
        "ruff": gate.ruff_version(project),
        "functions": {f"{FILE}::alpha": OVER + 1, "shadowscan/z.py::zed": OVER},
        "modules": {"shadowscan/big.py": MAX_MODULE_LINES + 3},
    }
    assert text == json.dumps(data, indent=2) + "\n"
    assert list(data["functions"]) == sorted(data["functions"])


def test_a_checkout_that_matches_its_baseline_passes_and_says_what_it_checked(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    baselined(project, branchy("big", JUST_OVER + 4))
    capsys.readouterr()
    assert run() == 0
    out = capsys.readouterr().out
    assert "Checked 1 functions" in out and f"{FILE}::big at {OVER + 4}" in out


def test_measuring_leaves_no_ruff_cache_behind_and_never_trusts_one(project: Path) -> None:
    write(project, FILE, branchy("big", JUST_OVER))
    assert run("--rebaseline") == 0
    assert not (project / ".ruff_cache").exists()
    # A cache from an earlier run must not decide the result: the measurement is of the files as they are.
    write(project, FILE, branchy("big", JUST_OVER + 1))
    assert run() == 1
    assert not (project / ".ruff_cache").exists()


def test_an_empty_checkout_passes_an_empty_baseline(project: Path) -> None:
    write(project, FILE, "x = 1\n")
    assert run("--rebaseline") == 0
    assert baseline_data(project)["functions"] == {} and baseline_data(project)["modules"] == {}
    assert run() == 0


def test_a_new_function_over_the_limit_fails_even_when_the_others_are_within_their_baseline(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    baselined(project, branchy("old", JUST_OVER + 5))
    write(project, "shadowscan/b.py", branchy("added", JUST_OVER))
    capsys.readouterr()
    assert run() == 1
    err = capsys.readouterr().err
    assert (
        f"shadowscan/b.py::added: complexity {JUST_OVER + 1}, over the limit of {MAX_FUNCTION_COMPLEXITY} and not in the baseline"
        in err
    )
    assert "--rebaseline" in err


def test_a_listed_function_that_grows_fails(project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    baselined(project, branchy("big", JUST_OVER))
    write(project, FILE, branchy("big", JUST_OVER + 1))
    capsys.readouterr()
    assert run() == 1
    assert f"{FILE}::big: complexity {OVER + 1}, up from {OVER} in the baseline" in capsys.readouterr().err


def test_a_nested_function_adds_to_the_function_around_it(project: Path) -> None:
    baselined(project, branchy("big", JUST_OVER))
    write(
        project,
        FILE,
        branchy("big", JUST_OVER).replace(
            "    return x\n",
            "    def helper(y):\n        if y:\n            return y\n        return x\n    return helper\n",
        ),
    )
    assert run() == 1


def test_an_improvement_fails_until_the_baseline_is_lowered_and_then_holds(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    baselined(project, branchy("big", JUST_OVER + 1))
    write(project, FILE, branchy("big", JUST_OVER))
    capsys.readouterr()
    assert run() == 1
    err = capsys.readouterr().err
    assert f"{FILE}::big: now complexity {OVER}, but the baseline still allows {OVER + 1}" in err
    assert "--update" in err
    assert run("--update") == 0
    assert baseline_data(project)["functions"] == {f"{FILE}::big": OVER}
    assert run() == 0
    # The room the improvement made is gone: going back up is growth again.
    write(project, FILE, branchy("big", JUST_OVER + 1))
    assert run() == 1


def test_a_function_that_drops_under_the_limit_leaves_the_baseline_on_update(project: Path) -> None:
    baselined(project, branchy("big", JUST_OVER) + "\n\n" + branchy("other", JUST_OVER))
    write(project, FILE, branchy("big", AT_LIMIT) + "\n\n" + branchy("other", JUST_OVER))
    assert run() == 1
    assert run("--update") == 0
    assert baseline_data(project)["functions"] == {f"{FILE}::other": OVER}
    assert run() == 0


def test_a_function_that_is_deleted_or_renamed_must_leave_the_baseline(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    baselined(project, branchy("old", JUST_OVER))
    write(project, FILE, branchy("renamed", AT_LIMIT))
    capsys.readouterr()
    assert run() == 1
    assert (
        f"{FILE}::old: now within the limit of {MAX_FUNCTION_COMPLEXITY} (or gone)" in capsys.readouterr().err
    )
    # Renaming without improving is a new function over the limit, not a free pass.
    write(project, FILE, branchy("renamed", JUST_OVER))
    assert run() == 1
    err = capsys.readouterr().err
    assert f"{FILE}::renamed" in err and "not in the baseline" in err


def test_update_refuses_to_raise_or_add_anything_and_leaves_the_baseline_alone(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    baselined(project, branchy("down", JUST_OVER + 1) + "\n\n" + branchy("up", JUST_OVER))
    before = baseline_path(project).read_bytes()
    # `down` improves, which `--update` would take, but `up` grew and `fresh` is new: nothing is written.
    write(
        project,
        FILE,
        branchy("down", JUST_OVER)
        + "\n\n"
        + branchy("up", JUST_OVER + 1)
        + "\n\n"
        + branchy("fresh", JUST_OVER),
    )
    capsys.readouterr()
    assert run("--update") == 1
    err = capsys.readouterr().err
    assert "Refusing to raise the baseline" in err
    assert f"{FILE}::up" in err and f"{FILE}::fresh" in err
    assert baseline_path(project).read_bytes() == before


def test_rebaseline_records_a_rise_that_review_accepted(project: Path) -> None:
    baselined(project, branchy("big", JUST_OVER))
    write(project, FILE, branchy("big", JUST_OVER + 3) + "\n\n" + branchy("fresh", JUST_OVER))
    assert run() == 1
    assert run("--rebaseline") == 0
    assert baseline_data(project)["functions"] == {f"{FILE}::big": OVER + 3, f"{FILE}::fresh": OVER}
    assert run() == 0


def test_a_module_that_grows_fails_and_one_that_shrinks_must_be_lowered(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    baselined(project, lines_of(MAX_MODULE_LINES + 10), "shadowscan/big.py")
    write(project, "shadowscan/big.py", lines_of(MAX_MODULE_LINES + 11))
    capsys.readouterr()
    assert run() == 1
    assert f"shadowscan/big.py: {MAX_MODULE_LINES + 11} lines, up from {MAX_MODULE_LINES + 10}" in (
        capsys.readouterr().err
    )
    write(project, "shadowscan/big.py", lines_of(MAX_MODULE_LINES + 9))
    assert run() == 1
    assert run("--update") == 0
    assert baseline_data(project)["modules"] == {"shadowscan/big.py": MAX_MODULE_LINES + 9}
    write(project, "shadowscan/big.py", lines_of(MAX_MODULE_LINES))
    assert run() == 1
    assert run("--update") == 0
    assert baseline_data(project)["modules"] == {}
    # A second module past the limit is new, whatever the first one did.
    write(project, "shadowscan/another.py", lines_of(MAX_MODULE_LINES + 1))
    assert run() == 1


def test_a_rise_in_the_function_limit_cannot_come_through_the_baseline_alone(project: Path) -> None:
    """The limit is code, not data: a baseline listing a function below the limit is just slack."""
    baselined(project, branchy("big", JUST_OVER))
    data = baseline_data(project)
    data["functions"] = {f"{FILE}::big": 99}
    baseline_path(project).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    # A hand-raised ceiling passes the growth check but the unused room is slack, so the gate still fails.
    assert run() == 1
    assert run("--update") == 0
    assert baseline_data(project)["functions"] == {f"{FILE}::big": OVER}


def test_a_ruff_version_change_is_named_when_the_gate_fails(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    baselined(project, branchy("big", JUST_OVER))
    data = baseline_data(project)
    data["ruff"] = "0.0.1"
    baseline_path(project).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    write(project, FILE, branchy("big", JUST_OVER + 1))
    capsys.readouterr()
    assert run() == 1
    err = capsys.readouterr().err
    assert "The baseline was written with ruff 0.0.1 and this is ruff " in err
    # With nothing wrong the version difference alone is not an error.
    write(project, FILE, branchy("big", JUST_OVER))
    assert run() == 0


def test_both_modes_at_once_are_a_usage_error() -> None:
    with pytest.raises(SystemExit) as raised:
        run("--update", "--rebaseline")
    assert raised.value.code == 2


# --- fail closed -------------------------------------------------------------------------------------------


def test_a_missing_baseline_is_an_error_not_an_empty_baseline(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write(project, FILE, branchy("big", JUST_OVER))
    assert run() == 2
    assert "--rebaseline" in capsys.readouterr().err
    assert run("--update") == 2
    assert not baseline_path(project).exists()


GOOD = {"schema": 1, "ruff": "0.1.0", "functions": {"a.py::f": 21}, "modules": {"b.py": 2001}}


@pytest.mark.parametrize(
    "text",
    [
        "",
        "not json",
        "[]",
        "null",
        "[" * 100_000,
        '{"schema": 1, "ruff": "0.1.0", "functions": {}}',
        json.dumps({**GOOD, "extra": 1}),
        json.dumps({**GOOD, "schema": 2}),
        json.dumps({**GOOD, "schema": True}),
        json.dumps({**GOOD, "schema": "1"}),
        json.dumps({**GOOD, "ruff": 1}),
        json.dumps({**GOOD, "functions": []}),
        json.dumps({**GOOD, "modules": None}),
        json.dumps({**GOOD, "functions": {"a.py::f": 0}}),
        json.dumps({**GOOD, "functions": {"a.py::f": -3}}),
        json.dumps({**GOOD, "functions": {"a.py::f": True}}),
        json.dumps({**GOOD, "functions": {"a.py::f": "21"}}),
        json.dumps({**GOOD, "functions": {"a.py::f": 21.0}}),
        json.dumps({**GOOD, "modules": {"b.py": None}}),
        '{"schema": 1, "ruff": "0.1.0", "functions": {"a.py::f": 21, "a.py::f": 99}, "modules": {}}',
        '{"schema": 1, "ruff": "0.1.0", "functions": {"a.py::f": NaN}, "modules": {}}',
    ],
)
def test_a_baseline_that_cannot_be_trusted_fails_closed_in_every_mode(project: Path, text: str) -> None:
    write(project, FILE, "x = 1\n")
    write(project, gate.BASELINE, text)
    for mode in ((), ("--update",)):
        assert run(*mode) == 2
    assert baseline_path(project).read_text(encoding="utf-8") == text


def test_a_baseline_with_unknown_names_is_read_and_only_flagged_as_slack(project: Path) -> None:
    write(project, FILE, "x = 1\n")
    write(project, gate.BASELINE, json.dumps(GOOD))
    assert run() == 1
    assert run("--update") == 0
    assert baseline_data(project)["functions"] == {} and baseline_data(project)["modules"] == {}


def test_a_ruff_that_cannot_start_fails_closed(
    project: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    baselined(project, branchy("big", JUST_OVER))
    monkeypatch.setattr(gate.sys, "executable", str(project / "no-such-python"))
    capsys.readouterr()
    assert run() == 2
    assert "could not run ruff" in capsys.readouterr().err
    assert run("--rebaseline") == 2


def test_a_ruff_that_exits_with_an_error_fails_closed_and_writes_nothing(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (project / "ruff.toml").write_text("line-length = [\n", encoding="utf-8")
    capsys.readouterr()
    assert run("--rebaseline") == 2
    assert "ruff exited with status" in capsys.readouterr().err
    assert not baseline_path(project).exists()


def test_a_file_ruff_cannot_parse_fails_closed_instead_of_dropping_out_of_the_count(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    baselined(project, branchy("big", JUST_OVER))
    write(project, "shadowscan/broken.py", "def (:\n")
    capsys.readouterr()
    assert run() == 2
    assert "not a C901 complexity finding" in capsys.readouterr().err


def test_a_timeout_fails_closed(project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gate, "RUFF_TIMEOUT_SECONDS", 0.000001)
    write(project, FILE, "x = 1\n")
    assert run("--rebaseline") == 2


@pytest.mark.parametrize(
    "row",
    [
        None,
        [],
        "C901",
        {},
        {
            "code": "E501",
            "filename": "a.py",
            "message": f"`f` is too complex (25 > {MAX_FUNCTION_COMPLEXITY})",
            "location": {"row": 1},
        },
        {"code": None, "filename": "a.py", "message": "SyntaxError", "location": {"row": 1}},
        {
            "code": "C901",
            "filename": 3,
            "message": f"`f` is too complex (25 > {MAX_FUNCTION_COMPLEXITY})",
            "location": {"row": 1},
        },
        {"code": "C901", "filename": "a.py", "message": 3, "location": {"row": 1}},
        {
            "code": "C901",
            "filename": "a.py",
            "message": f"`f` is too complex (25 > {MAX_FUNCTION_COMPLEXITY})",
        },
        {
            "code": "C901",
            "filename": "a.py",
            "message": f"`f` is too complex (25 > {MAX_FUNCTION_COMPLEXITY})",
            "location": {},
        },
        {
            "code": "C901",
            "filename": "a.py",
            "message": f"`f` is too complex (25 > {MAX_FUNCTION_COMPLEXITY})",
            "location": {"row": True},
        },
        {
            "code": "C901",
            "filename": "a.py",
            "message": f"`f` is too complex (25 > {MAX_FUNCTION_COMPLEXITY})",
            "location": {"row": "1"},
        },
        {
            "code": "C901",
            "filename": "a.py",
            "message": "`f` is complicated (25 > 20)",
            "location": {"row": 1},
        },
        # The threshold in the message must be the one this gate asked for, so a stray config cannot lower it.
        {
            "code": "C901",
            "filename": "a.py",
            "message": "`f` is too complex (25 > 10)",
            "location": {"row": 1},
        },
    ],
)
def test_a_ruff_row_that_is_not_a_complexity_finding_is_an_error(row: Any, project: Path) -> None:
    with pytest.raises(gate.MeasurementError):
        gate._finding(row, project)


def test_a_finding_on_a_line_where_no_function_starts_is_an_error(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write(project, FILE, "x = 1\n")
    row = {
        "code": "C901",
        "filename": str(project / FILE),
        "message": f"`f` is too complex (25 > {MAX_FUNCTION_COMPLEXITY})",
        "location": {"row": 1, "column": 5},
    }
    monkeypatch.setattr(gate, "_run_ruff", lambda root, *arguments: json.dumps([row]))
    with pytest.raises(gate.MeasurementError, match="no function starts on the line"):
        gate.measure_functions(project)


@pytest.mark.parametrize("output", ["", "not json", "{}", "null", '["C901"]'])
def test_ruff_output_that_is_not_a_list_of_findings_is_an_error(
    project: Path, monkeypatch: pytest.MonkeyPatch, output: str
) -> None:
    monkeypatch.setattr(gate, "_run_ruff", lambda root, *arguments: output)
    with pytest.raises(gate.MeasurementError):
        gate.measure_functions(project)


def test_a_file_outside_the_checkout_is_an_error(
    project: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    outside = tmp_path_factory.mktemp("outside") / "a.py"
    outside.write_text("x = 1\n", encoding="utf-8")
    with pytest.raises(gate.MeasurementError, match="outside the checkout"):
        gate._relative(str(outside), project)
    assert gate._relative(str(project / FILE), project) == FILE
    assert gate._relative(FILE, project) == FILE


def test_a_source_file_python_cannot_parse_is_an_error(project: Path) -> None:
    write(project, FILE, "def (:\n")
    with pytest.raises(gate.MeasurementError, match="cannot parse"):
        gate._qualified_names(project / FILE)
    with pytest.raises(gate.MeasurementError, match="cannot parse"):
        gate._qualified_names(project / "does-not-exist.py")


def test_the_version_line_is_checked(project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+\S*", gate.ruff_version(project))
    monkeypatch.setattr(gate, "_run_ruff", lambda root, *arguments: "some other tool 1.0\n")
    with pytest.raises(gate.MeasurementError):
        gate.ruff_version(project)


# --- this repository ---------------------------------------------------------------------------------------


def test_the_gate_measures_this_checkout_and_the_checkout_is_within_its_baseline(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert gate.ROOT == ROOT
    assert gate.main([]) == 0, capsys.readouterr().err


def test_the_committed_baseline_is_exactly_what_the_gate_writes() -> None:
    path = ROOT / gate.BASELINE
    text = path.read_text(encoding="utf-8")
    baseline = gate.load_baseline(path)
    assert (
        text
        == json.dumps(
            {
                "schema": gate.SCHEMA,
                "ruff": baseline.ruff,
                "functions": dict(sorted(baseline.functions.items())),
                "modules": dict(sorted(baseline.modules.items())),
            },
            indent=2,
        )
        + "\n"
    ), f"{gate.BASELINE} was edited by hand; write it with `{COMMAND} --update` or `--rebaseline`"
    assert all(value > MAX_FUNCTION_COMPLEXITY for value in baseline.functions.values())
    assert all(value > MAX_MODULE_LINES for value in baseline.modules.values())
    for key in (*baseline.functions, *baseline.modules):
        assert (ROOT / key.split("::")[0]).is_file(), f"{key} names a file that is not in this checkout"


def test_the_baseline_lists_no_module_outside_the_package_and_no_test() -> None:
    baseline = gate.load_baseline(ROOT / gate.BASELINE)
    assert all(path.startswith("shadowscan/") for path in baseline.modules)
    assert not any(key.startswith("tests/") for key in baseline.functions)


# --- the Makefile, CI and the documents describe the same gate -----------------------------------------


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def _prerequisites(target: str) -> list[str]:
    match = re.search(rf"^{target}:([^#\n]*)", _read("Makefile"), re.MULTILINE)
    assert match, f"the Makefile has no {target} target"
    return match.group(1).split()


def test_make_complexity_runs_the_gate_and_is_part_of_check_and_check_fast() -> None:
    makefile = _read("Makefile")
    assert re.search(r"^\.PHONY: complexity$", makefile, re.MULTILINE)
    recipe = re.search(r"^complexity:.*\n((?:\t.*\n)+)", makefile, re.MULTILINE)
    assert recipe, "the Makefile has no complexity recipe"
    assert recipe.group(1).strip() == COMMAND
    for aggregate in ("check", "check-fast"):
        assert "complexity" in _prerequisites(aggregate), f"make {aggregate} no longer runs the gate"


def test_ci_runs_the_gate_in_every_leg_of_the_test_job_and_cannot_wave_it_through() -> None:
    workflow = yaml.safe_load(_read(".github/workflows/ci.yml"))
    steps = workflow["jobs"]["test"]["steps"]
    (step,) = [s for s in steps if s.get("run", "").strip() == COMMAND]
    assert not {"if", "continue-on-error"} & set(step)
    # The gate needs the locked ruff, so it runs after the hash-locked install and, like lint, before the tests.
    names = [s.get("run", "") for s in steps]
    install = next(i for i, run_ in enumerate(names) if "pip install --require-hashes" in run_)
    first_test = next(i for i, run_ in enumerate(names) if "pytest" in run_)
    assert install < steps.index(step) < first_test


def test_the_documents_name_the_gate_its_two_limits_and_the_two_ways_to_move_the_baseline() -> None:
    testing = _read("docs/testing.md")
    assert "make complexity" in testing
    assert f"complexity above {MAX_FUNCTION_COMPLEXITY}" in testing
    assert f"{MAX_MODULE_LINES:,} lines" in testing
    for flag in ("--update", "--rebaseline"):
        assert flag in testing, f"docs/testing.md no longer explains {flag}"
    for document in ("CONTRIBUTING.md", "tools/README.md", ".github/workflows/README.md"):
        assert "complexity" in _read(document).lower(), f"{document} no longer mentions the complexity gate"
    assert "complexity" in _read(".github/PULL_REQUEST_TEMPLATE.md").lower()
