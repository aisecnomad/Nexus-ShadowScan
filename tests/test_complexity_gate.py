"""The complexity ratchet, exercised with stubbed measurements and a temporary baseline."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools import complexity_gate
from tools.complexity_gate import main

KEPT = "shadowscan/a.py::kept"
GONE = "shadowscan/b.py::gone"
NEW = "shadowscan/c.py::new"


@pytest.fixture
def baseline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A baseline allowing ``KEPT`` 20 and ``GONE`` 18, in place of the committed one."""
    path = tmp_path / "tools" / "complexity_baseline.json"
    path.parent.mkdir()
    monkeypatch.setattr(complexity_gate, "ROOT", tmp_path)
    monkeypatch.setattr(complexity_gate, "BASELINE", path)
    complexity_gate.write_baseline({KEPT: 20, GONE: 18})
    return path


def _measured(monkeypatch: pytest.MonkeyPatch, current: dict[str, int]) -> None:
    monkeypatch.setattr(complexity_gate, "measure", lambda package=complexity_gate.PACKAGE: dict(current))


def _allowances(path: Path) -> dict[str, int]:
    allowances: dict[str, int] = json.loads(path.read_text(encoding="utf-8"))["allowances"]
    return allowances


def test_update_records_decreases_and_removals(baseline: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _measured(monkeypatch, {KEPT: 17})
    assert main(["--update"]) == 0
    assert _allowances(baseline) == {KEPT: 17}


@pytest.mark.parametrize(
    ("current", "named"),
    [
        ({KEPT: 21, GONE: 18}, f"complexity rose: {KEPT} is 21, baseline allows 20"),
        ({KEPT: 20, GONE: 18, NEW: 16}, f"new function over the complexity target: {NEW} is 16"),
    ],
    ids=["increase", "new-function"],
)
def test_update_refuses_an_increase_and_records_nothing(
    baseline: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    current: dict[str, int],
    named: str,
) -> None:
    before = baseline.read_bytes()
    _measured(monkeypatch, current)
    assert main(["--update"]) == 1
    assert baseline.read_bytes() == before
    out = capsys.readouterr()
    assert named in out.out
    assert "--allow-increase" in out.err


def test_update_refuses_an_increase_even_beside_an_improvement(
    baseline: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A removal must not carry an unrelated increase into the baseline with it."""
    before = baseline.read_bytes()
    _measured(monkeypatch, {KEPT: 25})
    assert main(["--update"]) == 1
    assert baseline.read_bytes() == before


def test_an_explicit_allow_increase_records_it(baseline: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _measured(monkeypatch, {KEPT: 21, NEW: 16})
    assert main(["--update", "--allow-increase"]) == 0
    assert _allowances(baseline) == {KEPT: 21, NEW: 16}


def test_allow_increase_alone_is_a_usage_error(baseline: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _measured(monkeypatch, {KEPT: 21})
    with pytest.raises(SystemExit) as raised:
        main(["--allow-increase"])
    assert raised.value.code == 2


def test_the_check_names_the_flag_that_records_an_increase(
    baseline: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _measured(monkeypatch, {KEPT: 21})
    assert main([]) == 1
    assert "--update --allow-increase" in capsys.readouterr().err


def test_the_recorded_comment_says_how_an_entry_rises(baseline: Path) -> None:
    comment = json.loads(baseline.read_text(encoding="utf-8"))["_comment"]
    assert "--allow-increase" in comment
