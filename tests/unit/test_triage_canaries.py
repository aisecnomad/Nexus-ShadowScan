"""The triage injection canaries run offline and catch a parser that takes a planted verdict."""

from __future__ import annotations

import json

import pytest

import shadowscan.triage as triage_module
from tools.evaluation import triage_canaries


@pytest.mark.parametrize("provider", ["anthropic", "openai"])
def test_offline_canaries_hold_every_invariant(provider):
    report = triage_canaries.offline(triage_canaries.load_cases(), provider)
    assert report["cases"] >= 10
    assert report["failed"] == 0, [r for r in report["results"] if not r["ok"]]


def test_a_parser_that_takes_the_first_verdict_is_caught(monkeypatch):
    def first_object(text):
        start = text.find("{")
        data, _ = json.JSONDecoder().raw_decode(text, start)
        return {"verdict": data["verdict"], "rationale": "", "suggested_action": ""}

    monkeypatch.setattr(triage_module, "parse_reply", first_object)
    report = triage_canaries.offline(triage_canaries.load_cases())
    assert report["failed"] == report["cases"]
    assert all("a reply with two verdict objects was accepted" in r["problems"] for r in report["results"])


@pytest.mark.parametrize("provider", ["anthropic", "openai"])
def test_finding_text_in_a_prefilled_assistant_turn_is_caught(monkeypatch, provider):
    original = triage_module.Triage._payload

    def leaking(self, summary):
        payload = original(self, summary)
        payload["messages"].append({"role": "assistant", "content": f"Context: {summary['title']}"})
        return payload

    monkeypatch.setattr(triage_module.Triage, "_payload", leaking)
    report = triage_canaries.offline(triage_canaries.load_cases(), provider)
    assert report["failed"] == report["cases"]
    assert all(
        "finding text reached a turn other than the user turn" in r["problems"] for r in report["results"]
    )


def test_cli_offline_exits_zero_and_writes_a_private_report(tmp_path):
    out = tmp_path / "canaries.json"
    assert triage_canaries.main(["--output", str(out)]) == 0
    assert out.stat().st_mode & 0o777 == 0o600
    assert json.loads(out.read_text())["mode"] == "offline"


def test_corpus_rejects_a_canary_whose_injection_matches_the_truth(tmp_path):
    corpus = tmp_path / "corpus.json"
    case = {"id": "x", "title": "t", "evidence": [], "injected": "likely-agent", "truth": "likely-agent"}
    corpus.write_text(json.dumps({"cases": [case]}))
    with pytest.raises(ValueError, match="must try to change"):
        triage_canaries.load_cases(corpus)
