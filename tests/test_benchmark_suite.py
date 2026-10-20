"""The companion remains optional locally and exact when initialized."""

from __future__ import annotations

import json

import pytest

from tools import benchmark_suite


def test_local_evidence_names_exact_source_bytes():
    evidence = json.loads(benchmark_suite.EVIDENCE.read_text())
    assert evidence["source_commit"] == "0792106b8d2cc09517f7f4ee2eeabf4f8eb8da2d"
    assert set(evidence["sources"]) == set(benchmark_suite.SOURCE_PATHS)
    assert all(len(source["sha256"]) == 64 for source in evidence["sources"].values())
    assert evidence["code"]["incomplete_negatives"] > 0


@pytest.mark.parametrize("mismatch", ["pin", "dirty", "untracked", "uninitialized", "url"])
def test_companion_identity_mismatch_is_rejected(tmp_path, monkeypatch, mismatch):
    suite = tmp_path / "benchmark-suite"
    suite.mkdir()
    sha = "a" * 40

    def git(root, *args):
        if args[0] == "config":
            return "https://example.invalid/other.git" if mismatch == "url" else benchmark_suite.COMPANION_URL
        if args[0] == "ls-files":
            return f"160000 {sha} 0\tbenchmark-suite"
        if args == ("rev-parse", "--show-toplevel"):
            return str(tmp_path if mismatch == "uninitialized" else suite)
        if args == ("rev-parse", "HEAD"):
            return "b" * 40 if mismatch == "pin" else sha
        assert args == ("status", "--porcelain", "--untracked-files=all")
        if mismatch == "untracked":
            return "?? tests/test_unreviewed.py"
        return " M corpus.json" if mismatch == "dirty" else ""

    monkeypatch.setattr(benchmark_suite, "_git", git)
    with pytest.raises(ValueError):
        benchmark_suite.verify_pin(tmp_path)


def test_changed_local_extract_is_rejected(tmp_path, monkeypatch):
    evidence = tmp_path / "evidence.json"
    evidence.write_text('{"count": 1}\n')
    monkeypatch.setattr(benchmark_suite, "extract", lambda suite: {"count": 2})
    with pytest.raises(ValueError, match="differs"):
        benchmark_suite.verify_evidence(tmp_path, evidence)
