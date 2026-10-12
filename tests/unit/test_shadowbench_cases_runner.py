"""Unit tests for the ShadowBench cases runner (tools/shadowbench/cases)."""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest

from tools.shadowbench.cases import runner
from tools.shadowbench.cases.contract import (
    AdapterResult,
    Invocation,
    MaterializedCase,
    RunResult,
    ToolEnv,
    base_env,
)
from tools.shadowbench.cases.corpus import Case

ROOT = Path(__file__).resolve().parents[2]


def _case(
    case_id: str = "okta-1",
    files: dict[str, str] | None = None,
    checkout: dict[str, Any] | None = None,
    surface: str = "identity",
    modality: str = "okta-export",
) -> Case:
    return Case(
        case_id=case_id,
        surface=surface,
        modality=modality,
        family="test",
        difficulty="easy",
        rationale="test",
        files=dict(files or {}),
        checkout=checkout,
    )


def _git_repo(path: Path, files: dict[str, str], links: dict[str, str] | None = None) -> str:
    path.mkdir(parents=True)

    def git(*args: str) -> str:
        cmd = ["git", "-C", str(path), "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
        cmd += ["-c", "commit.gpgsign=false", *args]
        return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout.strip()

    git("init", "-q")
    for rel, content in files.items():
        (path / rel).parent.mkdir(parents=True, exist_ok=True)
        (path / rel).write_text(content, encoding="utf-8")
    for rel, target in (links or {}).items():
        os.symlink(target, path / rel)
    git("add", "-A")
    git("commit", "-q", "-m", "fixture")
    return git("rev-parse", "HEAD")


needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")


class FakeAdapter:
    """An adapter whose invocation and normalized result the test decides."""

    name = "fake"
    display = "Fake"
    surfaces: Mapping[str, frozenset[str]] = {"identity": frozenset({"okta-export"})}

    def __init__(
        self,
        result: AdapterResult | None = None,
        script: str = "true",
        normalize: Callable[[Path, list[RunResult]], AdapterResult] | None = None,
    ) -> None:
        self.result = result or AdapterResult("ok")
        self.script = script
        self._normalize = normalize
        self.work: Path | None = None

    def unavailable_reason(self, env: ToolEnv) -> str | None:
        return None

    def version(self, env: ToolEnv) -> str:
        return "0"

    def invocations(self, case: MaterializedCase, env: ToolEnv, work: Path) -> list[Invocation]:
        self.work = work
        return [Invocation(argv=("sh", "-c", self.script), cwd=work, env=base_env(work, work), timeout=30)]

    def normalize(self, case: MaterializedCase, work: Path, runs: list[RunResult]) -> AdapterResult:
        return self._normalize(work, runs) if self._normalize else self.result


# --- corpus ids and files never write outside the case --------------------------------------------


@pytest.mark.parametrize("bad", ["../escape", "a/b", ".", "..", "", "with space", "/abs", "x\0y"])
def test_materialize_rejects_unsafe_checkout_ids(tmp_path: Path, bad: str) -> None:
    (tmp_path / "checkouts").mkdir()
    case = _case(surface="code", modality="checkout", checkout={"id": bad, "commit": "0" * 40})
    with pytest.raises(ValueError, match="unsafe checkout id"):
        runner.materialize(case, tmp_path / "case", tmp_path / "checkouts")


@needs_git
def test_materialize_rejects_a_checkout_that_resolves_outside_the_checkouts_dir(tmp_path: Path) -> None:
    commit = _git_repo(tmp_path / "elsewhere", {"README.md": "x\n"})
    (tmp_path / "checkouts").mkdir()
    os.symlink(tmp_path / "elsewhere", tmp_path / "checkouts" / "pinned")
    case = _case(surface="code", modality="checkout", checkout={"id": "pinned", "commit": commit})
    with pytest.raises(ValueError, match="outside"):
        runner.materialize(case, tmp_path / "case", tmp_path / "checkouts")
    assert not (tmp_path / "case" / "inputs" / "repo").exists()


@needs_git
def test_materialize_refuses_files_beside_a_checkout(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    commit = _git_repo(tmp_path / "checkouts" / "pinned", {"README.md": "x\n"}, links={"docs": str(outside)})
    case = _case(
        surface="code",
        modality="checkout",
        checkout={"id": "pinned", "commit": commit},
        files={"repo/docs/planted.txt": "planted"},
    )
    with pytest.raises(ValueError, match="beside its checkout"):
        runner.materialize(case, tmp_path / "case", tmp_path / "checkouts")
    assert not (outside / "planted.txt").exists()


def test_materialize_never_writes_through_a_symlink(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / "case" / "inputs").mkdir(parents=True)
    os.symlink(outside, tmp_path / "case" / "inputs" / "okta")
    with pytest.raises(ValueError, match="symlink"):
        runner.materialize(_case(files={"okta/apps.json": "[]"}), tmp_path / "case")
    assert not (outside / "apps.json").exists()


@pytest.mark.parametrize("rel", ["../escape.txt", "okta/../../escape.txt", "/escape.txt", "okta//apps.json"])
def test_materialize_rejects_input_paths_that_leave_inputs(tmp_path: Path, rel: str) -> None:
    with pytest.raises(ValueError, match="unsafe input path"):
        runner.materialize(_case(files={rel: "x"}), tmp_path / "case")
    assert not (tmp_path / "case" / "escape.txt").exists()
    assert not (tmp_path / "escape.txt").exists()


def test_materialize_writes_nested_inputs(tmp_path: Path) -> None:
    mat = runner.materialize(
        _case(files={"okta/apps.json": "[]", "okta/grants/0oa1.json": "{}"}), tmp_path / "case"
    )
    assert (mat.inputs / "okta" / "apps.json").read_text(encoding="utf-8") == "[]"
    assert (mat.inputs / "okta" / "grants" / "0oa1.json").read_text(encoding="utf-8") == "{}"


@pytest.mark.parametrize("bad", ["../../etc/x", "a/b", "..", ""])
def test_runner_rejects_unsafe_case_ids(tmp_path: Path, bad: str) -> None:
    assert runner.unsafe_ids([_case(case_id=bad)])
    with pytest.raises(ValueError, match="unsafe case id"):
        runner.run_one(FakeAdapter(), _case(case_id=bad), ToolEnv(tmp_path), tmp_path, ROOT, tmp_path, None)
