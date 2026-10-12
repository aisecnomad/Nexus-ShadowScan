"""Unit tests for the ShadowBench track dispatcher (python -m tools.shadowbench)."""

from __future__ import annotations

import pytest

from tools.shadowbench import __main__ as shadowbench


@pytest.mark.parametrize("argv", [[], ["unknown"], ["--help"]])
def test_without_a_known_track_it_prints_usage_and_fails(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert shadowbench.main(argv) == 2
    err = capsys.readouterr().err
    assert "usage: python -m tools.shadowbench {cases|estate}" in err
    assert "benchmarks/shadowbench/README.md" in err


@pytest.mark.parametrize("track", ["cases", "estate"])
def test_a_track_receives_the_remaining_arguments_and_its_exit_code_is_returned(
    track: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[list[str] | None] = []

    def fake(argv: list[str] | None) -> int:
        seen.append(argv)
        return 7

    _, summary = shadowbench.TRACKS[track]
    monkeypatch.setitem(shadowbench.TRACKS, track, (fake, summary))
    assert shadowbench.main([track, "score", "--out", "m.json"]) == 7
    assert seen == [["score", "--out", "m.json"]]
