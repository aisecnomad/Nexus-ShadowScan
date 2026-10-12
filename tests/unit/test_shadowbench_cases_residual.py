"""Regression tests for residual fixes to the ShadowBench cases harness (tools/shadowbench/cases)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from tools.shadowbench.cases import fetch_code

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
