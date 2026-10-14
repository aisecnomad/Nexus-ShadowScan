"""Unit tests for the ShadowBench estate track (tools/shadowbench/estate)."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from tools.shadowbench.estate.__main__ import cmd_validate, cmd_verify_freeze

ROOT = Path(__file__).resolve().parents[2]
TRACK = ROOT / "benchmarks" / "shadowbench" / "estate"
CORPUS = TRACK / "corpus.json"
ARTIFACTS = TRACK / "artifacts"
FREEZE = TRACK / "FREEZE.json"


# --- the committed estate -------------------------------------------------------------------------


def test_committed_estate_validates() -> None:
    assert cmd_validate(CORPUS, ARTIFACTS) == 0


def test_committed_estate_matches_its_freeze_manifest() -> None:
    assert cmd_verify_freeze(CORPUS, ARTIFACTS, FREEZE) == 0


@pytest.mark.skipif(not shutil.which("git") or not (ROOT / ".git").exists(), reason="needs a git checkout")
def test_every_frozen_estate_file_is_tracked() -> None:
    """A frozen file that .gitignore keeps out of the repository breaks every clean checkout.

    #194 froze an estate ``.vscode/`` file the repository's ``.vscode/`` ignore rule had kept
    out of the commit, so validate and verify-freeze failed on every clone.
    """
    listed = subprocess.run(
        ["git", "ls-files", "-z", "--", str(TRACK.relative_to(ROOT))],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout.decode()
    tracked = {name for name in listed.split("\0") if name}
    frozen = json.loads(FREEZE.read_text(encoding="utf-8"))["sha256"]
    track = TRACK.relative_to(ROOT).as_posix()
    untracked = sorted(name for name in frozen if f"{track}/{name}" not in tracked)
    assert not untracked, f"frozen but not tracked (check .gitignore): {untracked}"
