"""Regression tests for the ShadowBench estate freeze and validation."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest

from tools.shadowbench.estate import corpus as estate_corpus
from tools.shadowbench.estate.__main__ import cmd_freeze, cmd_validate, cmd_verify_freeze
from tools.shadowbench.estate.corpus import CorpusError, corpus_from_dict

MCP_CONFIG = '{"mcpServers": {"freight-mcp-x1": {"command": "freight-mcp"}}}\n'


def _entities() -> list[dict[str, Any]]:
    return [
        {
            "id": "endpoint.freight-mcp",
            "surface": "endpoint",
            "class": "positive",
            "difficulty": "easy",
            "expected": [{"fact": "mcp:server", "evidence": ["home/dev-x/dana/.cursor/mcp.json"]}],
            "anchors": ["freight-mcp-x1"],
            "artifacts": ["home/dev-x/dana/.cursor/mcp.json"],
            "unit": "home:dev-x",
        },
        {
            "id": "code.repo-a",
            "surface": "code",
            "class": "positive",
            "difficulty": "easy",
            "expected": [{"fact": "provider:openai", "evidence": ["code/repo-a/app.py"]}],
            "anchors": ["repo-a-marker"],
            "artifacts": ["code/repo-a"],
            "unit": "code:repo-a",
        },
    ]


def _make_estate(
    tmp_path: Path,
    *,
    entities: list[dict[str, Any]] | None = None,
    app: str = "import openai  # repo-a-marker\n",
) -> tuple[Path, Path, Path]:
    """A two-unit estate with its corpus and a freeze manifest: (corpus, artifacts, freeze)."""
    track = tmp_path / "track"
    artifacts = track / "artifacts"
    cursor = artifacts / "home" / "dev-x" / "dana" / ".cursor"
    cursor.mkdir(parents=True)
    (cursor / "mcp.json").write_text(MCP_CONFIG, encoding="utf-8")
    repo = artifacts / "code" / "repo-a"
    repo.mkdir(parents=True)
    (repo / "app.py").write_text(app, encoding="utf-8")
    corpus = track / "corpus.json"
    payload = {"schema": 1, "metadata": {"name": "test"}, "entities": entities or _entities()}
    corpus.write_text(json.dumps(payload), encoding="utf-8")
    freeze = track / "FREEZE.json"
    assert cmd_freeze(corpus, artifacts, freeze) == 0
    return corpus, artifacts, freeze


# --- freeze, verify-freeze and validate never follow a symlink --------------------------------------


def test_freeze_and_verify_freeze_reject_symlinks(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """freeze and verify-freeze followed symlinks out of the estate (rglob + is_file)."""
    corpus, artifacts, freeze = _make_estate(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("operator secret\n", encoding="utf-8")
    link = artifacts / "home" / "dev-x" / "dana" / ".cursor" / "extra.json"
    link.symlink_to(outside / "secret.txt")

    fresh = tmp_path / "FREEZE.new.json"
    assert cmd_freeze(corpus, artifacts, fresh) == 1 and not fresh.exists()
    assert (
        "PROBLEM symlink or special file in estate: home/dev-x/dana/.cursor/extra.json"
        in capsys.readouterr().out
    )

    # A manifest that already records the link (as the old freeze wrote it) still fails.
    recorded = json.loads(freeze.read_text(encoding="utf-8"))
    digest = hashlib.sha256((outside / "secret.txt").read_bytes()).hexdigest()
    recorded["sha256"]["artifacts/home/dev-x/dana/.cursor/extra.json"] = digest
    freeze.write_text(json.dumps(recorded), encoding="utf-8")
    assert cmd_verify_freeze(corpus, artifacts, freeze) == 1
    assert cmd_validate(corpus, artifacts) == 1

    link.unlink()
    (artifacts / "code" / "linked-repo").symlink_to(outside, target_is_directory=True)
    assert cmd_freeze(corpus, artifacts, fresh) == 1 and not fresh.exists()
    assert "code/linked-repo" in capsys.readouterr().out


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs on this platform")
def test_freeze_rejects_special_files(tmp_path: Path) -> None:
    """A FIFO in the estate would block a freeze that opened it."""
    corpus, artifacts, _ = _make_estate(tmp_path)
    fifo = artifacts / "pipe"
    os.mkfifo(fifo)
    assert stat.S_ISFIFO(os.lstat(fifo).st_mode)
    assert cmd_freeze(corpus, artifacts, tmp_path / "F.json") == 1


def test_freeze_manifest_must_be_well_formed(tmp_path: Path) -> None:
    bad = tmp_path / "FREEZE.json"
    for payload in ("{", '{"schema": 1, "sha256": {}}', '{"schema": 2, "sha256": {"a": "' + "0" * 64 + '"}}'):
        bad.write_text(payload, encoding="utf-8")
        with pytest.raises(CorpusError):
            estate_corpus.load_freeze(bad)


# --- validate ---------------------------------------------------------------------------------------


def test_validate_checks_the_anchor_of_an_entity_whose_artifacts_are_empty(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An entity whose artifacts were all empty skipped the anchor check entirely."""
    entities = _entities()
    entities.append(
        {
            "id": "saas.empty",
            "surface": "saas",
            "class": "control",
            "difficulty": "easy",
            "anchors": ["ghost-anchor-q7"],
            "artifacts": ["saas/apps.json"],
        }
    )
    corpus, artifacts, _ = _make_estate(tmp_path, entities=entities)
    (artifacts / "saas").mkdir()
    (artifacts / "saas" / "apps.json").write_text("", encoding="utf-8")
    assert cmd_validate(corpus, artifacts) == 1
    assert "PROBLEM saas.empty: primary anchor 'ghost-anchor-q7' not found" in capsys.readouterr().out


def test_validate_warns_on_anchor_collisions_and_strict_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    corpus, artifacts, _ = _make_estate(tmp_path, app="import openai  # repo-a-marker freight-mcp-x1\n")
    assert cmd_validate(corpus, artifacts) == 0
    out = capsys.readouterr().out
    assert (
        "WARN endpoint.freight-mcp: anchor 'freight-mcp-x1' also occurs in code/repo-a/app.py "
        "(artifact of code.repo-a)"
    ) in out
    assert "1 anchor collision warnings" in out
    assert cmd_validate(corpus, artifacts, strict=True) == 1
    assert "PROBLEM 1 anchor collisions (--strict)" in capsys.readouterr().out


def test_validate_requires_the_unit_directory(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    entities = _entities()
    entities[1]["unit"] = "code:repo-gone"
    corpus, artifacts, _ = _make_estate(tmp_path, entities=entities)
    assert cmd_validate(corpus, artifacts) == 1
    assert "code.repo-a: unit code:repo-gone has no directory code/repo-gone" in capsys.readouterr().out


# --- corpus units and anchors -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "unit",
    ["code", "code:", "code:Repo", "code:../x", "code:-x", "code:a/b", "code:a\n", "host:x", "estate:x", ""],
)
def test_corpus_rejects_malformed_units(unit: str) -> None:
    entities = _entities()
    entities[1]["unit"] = unit
    with pytest.raises(CorpusError):
        corpus_from_dict({"schema": 1, "metadata": {}, "entities": entities})


@pytest.mark.parametrize("unit", ["estate", "code:repo-a", "home:dev-laptop-01", "code:a.b_c"])
def test_corpus_accepts_well_formed_units(unit: str) -> None:
    entities = _entities()
    entities[1]["unit"] = unit
    assert corpus_from_dict({"schema": 1, "metadata": {}, "entities": entities}).entities[1].unit == unit


def test_corpus_rejects_short_secondary_anchors() -> None:
    entities = _entities()
    entities[0]["anchors"] = ["freight-mcp-x1", "mcp"]
    with pytest.raises(CorpusError, match="secondary anchors must be at least 6"):
        corpus_from_dict({"schema": 1, "metadata": {}, "entities": entities})
