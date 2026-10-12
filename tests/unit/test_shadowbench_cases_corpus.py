"""Unit tests for the ShadowBench cases corpus: generation and verification."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tools.shadowbench.cases import generate, verify
from tools.shadowbench.cases.corpus import Corpus, load_corpus

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "benchmarks" / "shadowbench" / "cases" / "corpus.json"
CODE_CORPUS = ROOT / "benchmarks" / "shadow-ai-discovery" / "corpus.json"


@pytest.fixture(scope="module")
def stored() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(CORPUS.read_text(encoding="utf-8"))
    return data


def _small_corpus(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Path:
    out = tmp_path / "corpus.json"
    assert generate.main(["--seed", "1", "--per-surface", "4", "--output", str(out)]) == 0
    capsys.readouterr()
    return out


# --- the committed corpus -------------------------------------------------------------------------


def test_build_reproduces_the_committed_cases(stored: dict[str, Any]) -> None:
    rebuilt = json.loads(json.dumps([c.to_json() for c in generate.build(20261011, 40)]))
    assert rebuilt == stored["cases"]


def test_committed_corpus_verifies_with_regenerate(capsys: pytest.CaptureFixture[str]) -> None:
    """The committed corpus holds 40 cases per generated surface plus 26 code cases.

    verify guessed ``len(cases) // len(surfaces)`` = 346 // 9 = 38 per surface, rebuilt a
    different corpus and reported DIFFERS; and the digest recorded before the generator moved
    to ``tools/shadowbench/cases`` failed it even though the rebuilt cases were identical.
    """
    assert verify.main(["--corpus", str(CORPUS), "--regenerate"]) == 0
    out = capsys.readouterr().out
    assert "regenerated cases are identical (per-surface 40)" in out
    assert "produce the same cases" in out


def test_committed_corpus_per_surface_is_inferred() -> None:
    corpus = load_corpus(CORPUS)
    assert corpus.per_surface is None
    assert verify.per_surface(corpus) == 40


def test_digest_mismatch_without_regenerate_fails_with_a_hint(capsys: pytest.CaptureFixture[str]) -> None:
    corpus = load_corpus(CORPUS)
    assert corpus.generator_digest != generate.generator_digest()
    assert verify.main(["--corpus", str(CORPUS)]) == 1
    assert "rerun with --regenerate" in capsys.readouterr().out


# --- generation and the corpus header -------------------------------------------------------------


def test_new_corpora_record_per_surface_and_verify(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _small_corpus(tmp_path, capsys)
    header = json.loads(path.read_text(encoding="utf-8"))
    assert list(header)[:5] == ["benchmark", "version", "seed", "per_surface", "generator_digest"]
    assert header["per_surface"] == 4
    assert load_corpus(path).per_surface == 4
    assert verify.main(["--corpus", str(path)]) == 0
    assert verify.main(["--corpus", str(path), "--regenerate"]) == 0
    assert "regenerated cases are identical (per-surface 4)" in capsys.readouterr().out


def test_old_corpora_without_per_surface_still_load_and_verify(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _small_corpus(tmp_path, capsys)
    data = json.loads(path.read_text(encoding="utf-8"))
    del data["per_surface"]
    path.write_text(json.dumps(data), encoding="utf-8")
    corpus = load_corpus(path)
    assert corpus.per_surface is None
    assert "per_surface" not in corpus.to_json()
    assert verify.main(["--corpus", str(path), "--regenerate"]) == 0


@pytest.mark.parametrize("value", [-1, "4", True, 2.5])
def test_load_rejects_a_malformed_per_surface(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], value: object
) -> None:
    path = _small_corpus(tmp_path, capsys)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["per_surface"] = value
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="per_surface"):
        load_corpus(path)


def test_regenerate_fails_when_a_case_was_edited(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = _small_corpus(tmp_path, capsys)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["cases"][3]["rationale"] += " (edited)"
    path.write_text(json.dumps(data), encoding="utf-8")
    assert verify.main(["--corpus", str(path), "--regenerate"]) == 1
    out = capsys.readouterr().out
    assert "DIFFER" in out
    assert data["cases"][3]["id"] in out


def test_regenerate_passes_a_moved_generator_and_says_so(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _small_corpus(tmp_path, capsys)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["generator_digest"] = "0" * 64
    path.write_text(json.dumps(data), encoding="utf-8")
    assert verify.main(["--corpus", str(path)]) == 1
    assert verify.main(["--corpus", str(path), "--regenerate"]) == 0
    out = capsys.readouterr().out
    assert "sources changed since the corpus was written but produce the same cases" in out


def test_generator_digest_covers_the_code_corpus(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[Path] = []
    real = generate.digest_files

    def capture(paths: list[Path], root: Path) -> str:
        seen.extend(paths)
        return real(paths, root)

    monkeypatch.setattr(generate, "digest_files", capture)
    generate.generator_digest()
    assert CODE_CORPUS.resolve() in {p.resolve() for p in seen}


def test_build_and_digest_refuse_without_the_code_corpus(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A missing code corpus silently dropped all 26 code cases; it must stop the build instead."""
    monkeypatch.setattr(generate, "CODE_CORPUS", tmp_path / "missing.json")
    with pytest.raises(FileNotFoundError, match="code-surface corpus"):
        generate.build(1, 1)
    with pytest.raises(FileNotFoundError, match="code-surface corpus"):
        generate.generator_digest()


def test_code_cases_reject_a_pinned_repository_missing_from_the_code_corpus(tmp_path: Path) -> None:
    data = json.loads(CODE_CORPUS.read_text(encoding="utf-8"))
    data["repos"] = [r for r in data["repos"] if r["id"] != generate.CODE_REPOS[0]]
    path = tmp_path / "code.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match=generate.CODE_REPOS[0]):
        generate.code_cases(path)


def test_build_rejects_a_negative_per_surface() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        generate.build(1, -1)


def test_corpus_header_round_trips_per_surface() -> None:
    assert "per_surface" not in Corpus([], 1, "d", "now").to_json()
    assert Corpus([], 1, "d", "now", per_surface=7).to_json()["per_surface"] == 7
