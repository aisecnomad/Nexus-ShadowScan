"""Regression tests for residual fixes to the ShadowBench cases harness (tools/shadowbench/cases)."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from tools.shadowbench.cases import fetch_code, report, runner
from tools.shadowbench.cases.contract import ToolEnv
from tools.shadowbench.cases.corpus import Corpus, dump_corpus

ROOT = Path(__file__).resolve().parents[2]
CASES = ROOT / "benchmarks" / "shadowbench" / "cases"
RUN = CASES / "results" / "2026-10-11"

# --- fetch_code: the documented command runs ------------------------------------------------------


def test_fetch_code_documents_the_command_that_runs() -> None:
    """The docstring showed ``python tools/shadowbench/cases/fetch_code.py``, which cannot import its package."""
    command = "python -m tools.shadowbench.cases.fetch_code DEST"
    assert command in " ".join((fetch_code.__doc__ or "").split())
    proc = subprocess.run(
        [sys.executable, "-m", "tools.shadowbench.cases.fetch_code"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 2
    assert proc.stderr.strip() == f"usage: {command}"


# --- runner.main: refusals before any tool runs ---------------------------------------------------


def _main(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tools: dict[str, object] | None = None) -> int:
    """Run ``runner.main`` on an empty corpus as if root, with ``unshare`` present and isolation clean."""
    monkeypatch.setattr(runner.os, "geteuid", lambda: 0)
    monkeypatch.setattr(runner.shutil, "which", lambda name, path=None: f"/usr/bin/{name}")
    monkeypatch.setattr(runner, "isolation_problems", lambda scratch, env: [])
    corpus = tmp_path / "corpus.json"
    dump_corpus(Corpus([], 1, "generator", "2026-10-11T00:00:00Z"), corpus)
    tools_json = tmp_path / "tools.json"
    tools_json.write_text(json.dumps({"tool_root": str(tmp_path), "tools": tools or {}}), encoding="utf-8")
    argv = ["--corpus", str(corpus), "--tools", str(tools_json), "--out", str(tmp_path / "out")]
    return runner.main([*argv, "--scratch", str(tmp_path / "scratch")])


@pytest.mark.parametrize(
    ("gcc", "reason"),
    [
        (None, "(gcc is not on PATH)"),
        ("echo '/usr/bin/ld: cannot find -lc' >&2; exit 1", "(gcc exited 1: /usr/bin/ld: cannot find -lc)"),
    ],
)
def test_runner_refuses_when_the_inert_binary_cannot_be_built(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    gcc: str | None,
    reason: str,
) -> None:
    """A missing gcc or static libc surfaced as a traceback from deep in the runner, not a refusal."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    if gcc is not None:
        (bindir / "gcc").write_text(f"#!/bin/sh\n{gcc}\n", encoding="utf-8")
        (bindir / "gcc").chmod(0o755)
    monkeypatch.setenv("PATH", str(bindir))
    assert _main(tmp_path, monkeypatch) == 2
    err = capsys.readouterr().err
    assert f"cannot build the inert process binary {reason}" in err
    assert "gcc that can link a static binary" in err
    assert not (tmp_path / "out").exists(), "a refused run leaves no output directory behind"


# --- provenance: the manifest names the harness commit, the report renders it only when recorded ---

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")


def _git(repo: Path, *args: str) -> str:
    cmd = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    cmd += ["-c", "commit.gpgsign=false", *args]
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout.strip()


@needs_git
def test_harness_revision_names_the_commit_and_any_change_under_tools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "harness"
    (repo / "tools" / "adapters").mkdir(parents=True)
    (repo / "tools" / "adapters" / "a.py").write_text("A = 1\n", encoding="utf-8")
    (repo / "README.md").write_text("x\n", encoding="utf-8")
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "fixture")
    head = _git(repo, "rev-parse", "HEAD")
    assert runner.harness_revision(repo) == {"commit": head, "dirty": False}
    (repo / "README.md").write_text("changed outside tools/\n", encoding="utf-8")
    assert runner.harness_revision(repo) == {"commit": head, "dirty": False}
    # The registry imports every module in adapters/, so an uncommitted one changes what runs.
    (repo / "tools" / "adapters" / "b.py").write_text("B = 1\n", encoding="utf-8")
    assert runner.harness_revision(repo) == {"commit": head, "dirty": True}
    (repo / "tools" / "adapters" / "b.py").unlink()
    (repo / "tools" / "adapters" / "a.py").write_text("A = 2\n", encoding="utf-8")
    assert runner.harness_revision(repo) == {"commit": head, "dirty": True}
    # The caller's GIT_* variables cannot point git at another repository.
    other = tmp_path / "other"
    other.mkdir()
    _git(other, "init", "-q")
    monkeypatch.setenv("GIT_DIR", str(other / ".git"))
    assert runner.harness_revision(repo) == {"commit": head, "dirty": True}


def test_harness_revision_is_null_outside_a_checkout(tmp_path: Path) -> None:
    assert runner.harness_revision(tmp_path) == {"commit": None, "dirty": None}


@needs_git
def test_harness_revision_ignores_a_checkout_above_the_harness(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q")
    (tmp_path / "f").write_text("x\n", encoding="utf-8")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-q", "-m", "fixture")
    (tmp_path / "harness").mkdir()
    assert runner.harness_revision(tmp_path / "harness") == {"commit": None, "dirty": None}


@pytest.mark.skipif(shutil.which("git") is None or not (ROOT / ".git").exists(), reason="needs a checkout")
def test_harness_revision_names_this_checkout() -> None:
    revision = runner.harness_revision()
    assert revision["commit"] == _git(ROOT, "rev-parse", "HEAD")
    assert isinstance(revision["dirty"], bool)


class _Unavailable:
    """An adapter the runner records as not run, so ``main`` writes a manifest without running a tool."""

    name = "absent"
    display = "Absent"
    surfaces: dict[str, frozenset[str]] = {}

    def unavailable_reason(self, env: ToolEnv) -> str | None:
        return "not installed"


def test_runner_manifest_records_the_harness_revision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The manifest named the corpus and tool versions but not the code that produced the rows."""
    commit = "c" * 40
    monkeypatch.setattr(runner, "build_fakeproc", lambda path: path)
    monkeypatch.setattr(runner, "load_adapters", lambda: ({"absent": _Unavailable()}, {}))
    monkeypatch.setattr(runner, "harness_revision", lambda repo: {"commit": commit, "dirty": True})
    assert _main(tmp_path, monkeypatch) == 0
    manifest = json.loads((tmp_path / "out" / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["harness_commit"] == commit
    assert manifest["harness_dirty"] is True
    assert manifest["tools"] == {"absent": {"skipped": "not installed"}}


def _render(manifest: dict[str, Any]) -> str:
    committed = json.loads((RUN / "metrics.json").read_text(encoding="utf-8"))
    committed["manifest"] = {**committed["manifest"], **manifest}
    return report.render(committed, CASES / "corpus.json")


@pytest.mark.parametrize(
    ("fields", "sentence"),
    [
        (
            {"harness_commit": "c" * 40, "harness_dirty": False},
            f"ran from harness commit `{'c' * 40}` with no uncommitted changes under `tools/`.",
        ),
        (
            {"harness_commit": "c" * 40, "harness_dirty": True},
            f"ran from harness commit `{'c' * 40}` with uncommitted or untracked files under `tools/`",
        ),
        (
            {"harness_commit": "c" * 40, "harness_dirty": None},
            f"ran from harness commit `{'c' * 40}` with an unknown working-tree state.",
        ),
        ({"harness_commit": None, "harness_dirty": None}, "could not name the harness commit"),
        ({"harness_commit": "`HEAD`", "harness_dirty": False}, "is not a commit id"),
    ],
)
def test_report_names_the_recorded_harness_revision(fields: dict[str, Any], sentence: str) -> None:
    text = _render(fields)
    first = text.split("\n\n")[1]  # the paragraph naming the corpus, the run and its platform
    assert first.startswith("Corpus: ")
    assert sentence in first
    assert "`HEAD`" not in text


def test_report_of_the_committed_run_names_no_harness_commit() -> None:
    """The committed manifest predates the fields; its re-rendered report must not change."""
    committed = json.loads((RUN / "metrics.json").read_text(encoding="utf-8"))
    assert "harness_commit" not in committed["manifest"]
    assert "harness_commit" not in json.loads((RUN / "manifest.json").read_text(encoding="utf-8"))
    text = report.render(committed, CASES / "corpus.json")
    assert text == (RUN / "REPORT.md").read_text(encoding="utf-8")
    assert "harness commit" not in text
