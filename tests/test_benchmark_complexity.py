"""Real Ruff measurements must keep moved harnesses under their old ceilings."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from tools import benchmark_complexity as gate
from tools import complexity_gate


def _branchy(branches: int) -> str:
    return (
        "def harness(x):\n"
        + "".join(f"    if x == {n}:\n        x += 1\n" for n in range(branches))
        + "    return x\n"
    )


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    suite = tmp_path / "benchmark-suite"
    for name in gate.SOURCE_ROOTS:
        (suite / name).mkdir(parents=True, exist_ok=True)
    (suite / "ruff.toml").write_text("line-length = 110\n")
    source = suite / "tools/benchmark/harness.py"
    source.write_text(_branchy(15))
    (tmp_path / "tools").mkdir()
    complexity_gate.write_baseline(
        tmp_path / gate.BASELINE,
        {"tools/benchmark/harness.py::harness": 16},
        {},
        complexity_gate.ruff_version(suite),
    )
    monkeypatch.setattr(gate, "ROOT", tmp_path)
    # Pin behavior has separate real-Git tests. These inputs exercise actual
    # Ruff measurements without putting synthetic history in the companion.
    monkeypatch.setattr(gate.benchmark_suite, "verify_pin", lambda root: "a" * 40)
    return tmp_path, source


def test_harness_growth_fails_and_update_cannot_raise_the_ceiling(project, capsys):
    root, source = project
    assert gate.main([]) == 0
    original = (root / gate.BASELINE).read_bytes()
    source.write_text(_branchy(16))
    assert gate.main([]) == 1
    assert "complexity 17, up from 16" in capsys.readouterr().err
    assert gate.main(["--update"]) == 1
    assert (root / gate.BASELINE).read_bytes() == original


def test_new_complex_harness_fails_without_a_baseline_entry(project, capsys):
    _, source = project
    source.with_name("new.py").write_text(_branchy(15))
    assert gate.main([]) == 1
    assert "not in the baseline" in capsys.readouterr().err


def test_improvement_requires_and_allows_only_a_lower_baseline(project):
    root, source = project
    source.write_text(_branchy(14))
    assert gate.main([]) == 1
    assert gate.main(["--update"]) == 0
    assert json.loads((root / gate.BASELINE).read_text())["functions"] == {}
    assert gate.main([]) == 0


def test_unverified_companion_is_rejected_before_measurement(project, monkeypatch):
    def reject(root):
        raise ValueError("unreviewed companion")

    def unexpected(*args, **kwargs):
        pytest.fail("must not measure before the pin is verified")

    monkeypatch.setattr(gate.benchmark_suite, "verify_pin", reject)
    monkeypatch.setattr(complexity_gate, "measure_functions", unexpected)
    assert gate.main([]) == 2


def test_empty_source_selection_cannot_silently_measure_the_wrong_roots(project):
    root, _ = project
    with pytest.raises(complexity_gate.MeasurementError, match="source root"):
        complexity_gate.measure_functions(root, source_roots=())


def test_ci_requires_companion_complexity_after_pin_verification():
    workflow = yaml.safe_load((gate.ROOT / ".github/workflows/ci.yml").read_text())
    job = workflow["jobs"]["benchmark-tests"]
    steps = job["steps"]
    index = next(
        i for i, step in enumerate(steps) if step.get("run") == "python -m tools.benchmark_complexity"
    )
    assert "python -m tools.benchmark_suite" in steps[index - 1]["run"]
    assert steps[index + 1]["working-directory"] == "benchmark-suite"
    assert not {"if", "continue-on-error"} & steps[index].keys()
    assert "benchmark-tests" in workflow["jobs"]["gate"]["needs"]
