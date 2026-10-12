"""Regression tests for residual fixes to the ShadowBench cases harness (tools/shadowbench/cases)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from tools.shadowbench.cases import fetch_code, runner
from tools.shadowbench.cases.corpus import Corpus, dump_corpus

ROOT = Path(__file__).resolve().parents[2]

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
