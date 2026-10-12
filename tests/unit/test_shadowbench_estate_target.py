"""Regression tests for estate scan-target attribution, the AI-Infra-Guard port offset and
relative `run` paths (tools/shadowbench/estate/score.py, report.py, __main__.py and
adapters/ai_infra_guard.py).

The 2026-10-11 AI-Infra-Guard adapter appended each mock service's answer-key anchor
to its prediction text, so its attribution came from the harness. Without the append,
a re-run scored the scanner's correct fingerprints as unattributed false positives.
The adapter now records which staged service each prediction scanned, and the scorer
maps that service to its estate host as explicit, counted harness attribution.
"""

from __future__ import annotations

import json
import socket
import stat
import sys
from pathlib import Path
from typing import Any

import pytest

from tools.discovery_benchmark.runner import RunPolicy
from tools.shadowbench.estate import __main__ as estate_cli
from tools.shadowbench.estate import report, score
from tools.shadowbench.estate.__main__ import cmd_freeze, main
from tools.shadowbench.estate.adapters import Command, Normalized, ToolConfig, ToolSpec
from tools.shadowbench.estate.adapters.ai_infra_guard import AiInfraGuardAdapter
from tools.shadowbench.estate.corpus import CorpusError, EstateCorpus, corpus_from_dict, load_corpus
from tools.shadowbench.estate.runner import run_unit

ROOT = Path(__file__).resolve().parents[2]
TRACK = ROOT / "benchmarks" / "shadowbench" / "estate"
RESULTS = TRACK / "results" / "2026-10-11"
RUNTIME = frozenset({"runtime"})

OLLAMA_ANCHOR = "dev-laptop-02:marcus:ollama"
VLLM_ANCHOR = "build-runner-3:ci:vllm"
SERVICES = {
    "ollama-dev-laptop-02": OLLAMA_ANCHOR,
    "vllm-build-runner-3": VLLM_ANCHOR,
    # A service whose anchor no entity carries.
    "orphan": "no-such-host:ci:ollama",
}


def _entity(entity_id: str, klass: str, anchor: str, fact: str | None = None) -> dict[str, Any]:
    artifact = "runtime/processes.jsonl"
    return {
        "id": entity_id,
        "surface": "runtime",
        "class": klass,
        "difficulty": "easy",
        "unit": "estate",
        "expected": [{"fact": fact, "evidence": [artifact]}] if fact else [],
        "anchors": [anchor],
        "artifacts": [artifact],
    }


def _corpus() -> EstateCorpus:
    entities = [
        _entity("runtime.ollama-marcus", "positive", OLLAMA_ANCHOR, "agent-process:ollama"),
        _entity("runtime.vllm-runner", "positive", VLLM_ANCHOR, "agent-process:vllm"),
        _entity("runtime.nginx-control", "control", "build-runner-3:root:nginx"),
    ]
    return corpus_from_dict({"schema": 1, "metadata": {}, "entities": entities})


def _pred(fact: str, text: str) -> dict[str, Any]:
    return {"fact": fact, "text": text, "surface": "runtime", "shadow": None}


OLLAMA = _pred("agent-process:ollama", "http://127.0.0.1:11434 ollama:0.3.9")
VLLM = _pred("agent-process:vllm", "http://127.0.0.1:8000 openai-compatible vllm:0.6.3")


def _row(predictions: list[dict[str, Any]], targets: Any = None, *, record: bool = True) -> dict[str, Any]:
    detail: dict[str, Any] = {score.SCAN_TARGETS: targets} if record else {}
    return {
        "tool": "ai_infra_guard",
        "unit": "sim",
        "status": "ok",
        "seconds": 1.0,
        "predictions": predictions,
        "raw_count": len(predictions),
        "commands": [{"argv": ["simhost"], "exit_code": 0, "ok": True, "timed_out": False}],
        "error": None,
        "detail": detail,
        "incomplete": False,
    }


def _score(row: dict[str, Any], services: dict[str, str] | None = None) -> dict[str, Any]:
    return score.score_tool(
        _corpus(), "ai_infra_guard", RUNTIME, [row], SERVICES if services is None else services
    )


def _render(result: dict[str, Any]) -> str:
    metrics = {
        "corpus": {
            "entities": 3,
            "positive": 2,
            "control": 1,
            "nearmiss": 0,
            "registered": 0,
            "expected_facts": 2,
            "expected_by_surface": {"runtime": 2},
        },
        "run": {},
        "tools": {
            "ai_infra_guard": {"name": "AI-Infra-Guard", "version": "t", "surfaces": ["runtime"], **result}
        },
    }
    return report.render(metrics, _corpus(), title="t")


# --- the scorer -----------------------------------------------------------------------------------


def test_scan_target_prediction_is_attributed_by_the_harness_and_counted() -> None:
    result = _score(_row([OLLAMA, VLLM], ["ollama-dev-laptop-02", "vllm-build-runner-3"]))

    assert result["per_entity"]["runtime.ollama-marcus"]["tp"] == 1
    assert result["per_entity"]["runtime.vllm-runner"]["tp"] == 1
    # No mock service stands in for the control, so the live-sim never reaches it.
    assert result["entity_level"]["positives_detected"] == 2 and result["entity_level"]["tn"] == 0
    assert result["entity_level"]["negatives_not_reached"] == 1
    assert result["value_level"]["in_scope"]["fp"] == 0
    counts = result["predictions"]
    assert counts["attributed"] == counts["harness_attributed"] == 2
    assert counts["unknown_scan_target"] == 0 and counts["unattributed"] == 0
    rendered = _render(result)
    assert "Harness-attributed predictions: AI-Infra-Guard 2." in rendered
    assert "the harness mapped a scanned loopback port to the estate host it stands in for" in rendered


@pytest.mark.parametrize(
    "target",
    [
        "http://127.0.0.1:9999",  # the adapter's record of a port no staged service listens on
        "not-a-service",  # an id the estate's services.json does not list
        "orphan",  # a service whose anchor is no entity's primary anchor
    ],
)
def test_unknown_scan_target_is_a_counted_false_positive(target: str) -> None:
    # Text that names an anchor does not rescue it: a scan target is never attributed by text.
    prediction = _pred("agent-process:ollama", f"http://127.0.0.1:9999 ollama:0.3.9 {OLLAMA_ANCHOR}")
    result = _score(_row([prediction], [target]))

    assert result["per_entity"]["runtime.ollama-marcus"]["tp"] == 0
    assert result["value_level"]["in_scope"]["fp"] == 1
    counts = result["predictions"]
    assert counts["unattributed"] == counts["unknown_scan_target"] == 1
    assert counts["harness_attributed"] == 0 and counts["attributed"] == 0
    assert result["unattributed"][0][score.SCAN_TARGET] == target
    rendered = _render(result)
    assert "AI-Infra-Guard 0 (plus 1 whose scan target maps to no estate host" in rendered
    assert f"(scan target `{target}` maps to no estate host)" in rendered


def test_scan_target_without_a_services_file_is_unattributed() -> None:
    result = _score(_row([OLLAMA], ["ollama-dev-laptop-02"]), services={})
    assert result["predictions"]["unknown_scan_target"] == 1 and result["value_level"]["in_scope"]["fp"] == 1


def test_prediction_without_a_scan_target_is_scored_as_before() -> None:
    """The committed 2026-10-11 predictions carry the anchor in their text and no target."""
    texted = _pred("agent-process:ollama", f"http://127.0.0.1:11434 ollama:0.3.9 {OLLAMA_ANCHOR}")
    old = _row([texted, OLLAMA], record=False)
    result = _score(old)

    assert result["per_entity"]["runtime.ollama-marcus"]["tp"] == 1
    assert result["predictions"]["attributed"] == 1 and result["predictions"]["unattributed"] == 1
    assert "harness_attributed" not in result["predictions"]
    assert "unknown_scan_target" not in result["predictions"]
    assert all(score.SCAN_TARGET not in item for item in result["unattributed"])
    assert "Harness-attributed" not in _render(result)
    # A target written straight onto a prediction is ignored: only the run's record sets one.
    assert _score(_row([{**OLLAMA, score.SCAN_TARGET: "ollama-dev-laptop-02"}], record=False)) == _score(
        _row([OLLAMA], record=False)
    )
    # A null entry in the record leaves that prediction to text attribution.
    assert _score(_row([texted], [None]))["predictions"]["attributed"] == 1


@pytest.mark.parametrize(
    "targets",
    [
        ["ollama-dev-laptop-02"],  # fewer targets than predictions
        "ollama-dev-laptop-02",  # not a list
        ["ollama-dev-laptop-02", 7],  # not a string
        ["ollama-dev-laptop-02", ""],  # empty
    ],
)
def test_malformed_scan_targets_make_the_run_incomplete(targets: Any) -> None:
    row = _row([OLLAMA, VLLM], targets)
    assert score.incomplete_reason(row) == score.MALFORMED_TARGETS
    result = _score(row)
    assert result["complete"] is False
    assert result["predictions"]["unknown_scan_target"] == 2 and result["predictions"]["attributed"] == 0
    # The failed run leaves the two mirrored positives unscored; it never reached the control.
    assert result["entity_level"]["tn"] == 0 and result["entity_level"]["positives_unscored"] == 2
    assert result["entity_level"]["negatives_not_reached"] == 1


def test_load_services_reads_ids_and_anchors_and_refuses_bad_files(tmp_path: Path) -> None:
    assert score.load_services(tmp_path / "missing.json") == {}
    assert score.load_services(TRACK / "artifacts" / "services" / "services.json") == {
        "ollama-dev-laptop-02": OLLAMA_ANCHOR,
        "vllm-build-runner-3": VLLM_ANCHOR,
    }
    path = tmp_path / "services.json"
    for payload in (
        "{",
        "[]",
        '{"services": [{"id": "a"}]}',
        '{"services": [{"id": "http://127.0.0.1:1", "anchor": "x"}]}',
        '{"services": [{"id": "a", "anchor": "x"}, {"id": "a", "anchor": "y"}]}',
    ):
        path.write_text(payload, encoding="utf-8")
        with pytest.raises(CorpusError):
            score.load_services(path)
    link = tmp_path / "link.json"
    link.symlink_to(TRACK / "artifacts" / "services" / "services.json")
    with pytest.raises(CorpusError):
        score.load_services(link)


# --- the committed run ----------------------------------------------------------------------------


def test_committed_run_rescores_byte_for_byte(tmp_path: Path) -> None:
    corpus = str(TRACK / "corpus.json")
    metrics, rendered = tmp_path / "metrics.json", tmp_path / "REPORT.md"
    estate = str(TRACK / "artifacts")
    argv = ["score", "--corpus", corpus, "--estate", estate, "--runs", str(RESULTS / "runs.json")]
    assert main([*argv, "--out", str(metrics)]) == 0
    assert metrics.read_bytes() == (RESULTS / "metrics.json").read_bytes()
    assert main(["report", "--corpus", corpus, "--metrics", str(metrics), "--out", str(rendered)]) == 0
    assert rendered.read_bytes() == (RESULTS / "REPORT.md").read_bytes()


def test_scan_targets_recover_the_committed_result_without_the_anchor_in_the_text() -> None:
    corpus = load_corpus(TRACK / "corpus.json")
    services = score.load_services(TRACK / "artifacts" / "services" / "services.json")
    rows = json.loads((RESULTS / "runs.json").read_text(encoding="utf-8"))["results"]
    [aig] = [row for row in rows if row["tool"] == "ai_infra_guard"]
    committed = score.score_tool(corpus, "ai_infra_guard", RUNTIME, [aig], services)

    stripped = [
        {**p, "text": p["text"].replace(f" {OLLAMA_ANCHOR}", "").replace(f" {VLLM_ANCHOR}", "")}
        for p in aig["predictions"]
    ]
    assert not any(anchor in p["text"] for p in stripped for anchor in (OLLAMA_ANCHOR, VLLM_ANCHOR))
    without = score.score_tool(
        corpus, "ai_infra_guard", RUNTIME, [{**aig, "predictions": stripped}], services
    )
    assert without["entity_level"]["positives_detected"] == 0

    targeted = {**aig, "predictions": stripped, "detail": {score.SCAN_TARGETS: sorted(services)}}
    rerun = score.score_tool(corpus, "ai_infra_guard", RUNTIME, [targeted], services)
    assert rerun["entity_level"] == committed["entity_level"]
    assert rerun["value_level"] == committed["value_level"]
    assert rerun["predictions"]["harness_attributed"] == 2


# --- the adapter ----------------------------------------------------------------------------------


def _staged(out_dir: Path, offset: int | None = None) -> None:
    payload: dict[str, Any] = {
        "services": [
            {"id": "ollama-dev-laptop-02", "kind": "ollama", "port": 11434, "anchor": OLLAMA_ANCHOR},
            {"id": "vllm-build-runner-3", "kind": "vllm", "port": 8000, "anchor": VLLM_ANCHOR},
        ]
    }
    if offset is not None:
        payload["port_offset"] = offset
    (out_dir / "services.json").write_text(json.dumps(payload), encoding="utf-8")


def test_adapter_records_the_scanned_service_of_each_prediction(tmp_path: Path) -> None:
    _staged(tmp_path)
    (tmp_path / "scan.txt").write_text(
        "\x1b[32mhttp://127.0.0.1:11434 [200] [ollama:0.3.9]\x1b[0m\n"
        "http://127.0.0.1:8000 [200] [openai-compatible] [vllm:0.6.3]\n"
        "http://127.0.0.1:9999 [200] [ollama:0.3.9]\n"
        "http://127.0.0.1:7000 [404]\n",
        encoding="utf-8",
    )
    normalized = AiInfraGuardAdapter().normalize("sim", tmp_path)

    assert normalized.error is None and normalized.raw_count == 4
    assert [p.text for p in normalized.predictions] == [
        "http://127.0.0.1:11434 ollama:0.3.9",
        "http://127.0.0.1:8000 openai-compatible vllm:0.6.3",
        "http://127.0.0.1:9999 ollama:0.3.9",
    ]
    assert normalized.detail[score.SCAN_TARGETS] == [
        "ollama-dev-laptop-02",
        "vllm-build-runner-3",
        "http://127.0.0.1:9999",
    ]
    assert normalized.detail["port_offset"] == 0


def test_adapter_without_a_readable_staged_services_file_fails_closed(tmp_path: Path) -> None:
    (tmp_path / "scan.txt").write_text("http://127.0.0.1:11434 [200] [ollama:0.3.9]\n", encoding="utf-8")
    normalized = AiInfraGuardAdapter().normalize("sim", tmp_path)
    assert normalized.error is not None and normalized.error.startswith("cannot map scanned targets")
    assert normalized.detail[score.SCAN_TARGETS] == ["http://127.0.0.1:11434"]


def _cfg(tmp_path: Path, **extra: Any) -> ToolConfig:
    tool = {"bin": str(tmp_path / "aig"), "fps": str(tmp_path / "fps"), "vul": str(tmp_path / "vul"), **extra}
    return ToolConfig({"tools": {"ai_infra_guard": tool}})


def _estate(tmp_path: Path, services: list[dict[str, Any]] | None = None) -> Path:
    estate = tmp_path / "artifacts"
    (estate / "services").mkdir(parents=True)
    listed = (
        services or json.loads((TRACK / "artifacts" / "services" / "services.json").read_text())["services"]
    )
    (estate / "services" / "services.json").write_text(json.dumps({"services": listed}), encoding="utf-8")
    return estate


def test_port_offset_moves_simhost_and_every_target_and_maps_back(tmp_path: Path) -> None:
    estate, out_dir = _estate(tmp_path), tmp_path / "out"
    out_dir.mkdir()
    [command] = AiInfraGuardAdapter().commands(_cfg(tmp_path, port_offset=100), "sim", estate, out_dir)

    argv = list(command.argv)
    assert argv[argv.index("--port-offset") + 1] == "100"
    assert argv.index("--port-offset") < argv.index("--")
    targets = [argv[i + 1] for i, word in enumerate(argv) if word == "--target"]
    assert targets == ["http://127.0.0.1:11534", "http://127.0.0.1:8100"]
    staged = json.loads((out_dir / "services.json").read_text(encoding="utf-8"))
    assert staged["port_offset"] == 100 and staged["services"][0]["port"] == 11434

    (out_dir / "scan.txt").write_text(
        "http://127.0.0.1:11534 [200] [ollama:0.3.9]\n"
        "http://127.0.0.1:8100 [200] [vllm:0.6.3]\n"
        # The unshifted port is not a staged target once the offset applies.
        "http://127.0.0.1:11434 [200] [ollama:0.3.9]\n",
        encoding="utf-8",
    )
    normalized = AiInfraGuardAdapter().normalize("sim", out_dir)
    assert normalized.error is None and normalized.detail["port_offset"] == 100
    assert normalized.detail[score.SCAN_TARGETS] == [
        "ollama-dev-laptop-02",
        "vllm-build-runner-3",
        "http://127.0.0.1:11434",
    ]


def test_default_port_offset_is_zero(tmp_path: Path) -> None:
    estate, out_dir = _estate(tmp_path), tmp_path / "out"
    out_dir.mkdir()
    [command] = AiInfraGuardAdapter().commands(_cfg(tmp_path), "sim", estate, out_dir)
    argv = list(command.argv)
    assert argv[argv.index("--port-offset") + 1] == "0"
    assert [argv[i + 1] for i, word in enumerate(argv) if word == "--target"] == [
        "http://127.0.0.1:11434",
        "http://127.0.0.1:8000",
    ]


@pytest.mark.parametrize("offset", ["100", True, 1.5, None])
def test_port_offset_must_be_an_integer(tmp_path: Path, offset: Any) -> None:
    cfg = _cfg(tmp_path, port_offset=offset)
    reason = AiInfraGuardAdapter().unavailable_reason(cfg)
    assert reason is not None and "port_offset must be an integer" in reason
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    with pytest.raises(ValueError, match="port_offset"):
        AiInfraGuardAdapter().commands(cfg, "sim", _estate(tmp_path), out_dir)


def test_port_offset_outside_the_port_range_is_refused(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    with pytest.raises(ValueError, match="outside 1-65535"):
        AiInfraGuardAdapter().commands(_cfg(tmp_path, port_offset=60000), "sim", _estate(tmp_path), out_dir)


# --- through the runner ---------------------------------------------------------------------------

_SCANNER = """\
import http.client
import json
import sys

args = sys.argv[1:]
targets = [args[i + 1] for i, word in enumerate(args) if word == "--target"]
lines = []
for url in targets:
    port = int(url.rsplit(":", 1)[1])
    for path, name in (("/api/version", "ollama"), ("/version", "vllm")):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request("GET", path)
        response = conn.getresponse()
        body = response.read()
        if response.status == 200:
            lines.append(f"{url} [200] [{name}:{json.loads(body)['version']}]")
            break
with open(args[args.index("-o") + 1], "w", encoding="utf-8") as handle:
    handle.write("\\n".join(lines) + "\\n")
"""


def _free_ports(count: int) -> list[int]:
    sockets = [socket.socket() for _ in range(count)]
    try:
        for sock in sockets:
            sock.bind(("127.0.0.1", 0))
        return [sock.getsockname()[1] for sock in sockets]
    finally:
        for sock in sockets:
            sock.close()


@pytest.mark.skipif(
    not Path("/usr/bin/python3").exists(), reason="the adapter starts simhost with /usr/bin/python3"
)
def test_scan_targets_round_trip_through_the_runner_into_the_score(tmp_path: Path) -> None:
    offset = 3
    ollama_port, vllm_port = _free_ports(2)
    services = [
        {"id": "ollama-h", "kind": "ollama", "port": ollama_port - offset, "anchor": OLLAMA_ANCHOR},
        {"id": "vllm-h", "kind": "vllm", "port": vllm_port - offset, "anchor": VLLM_ANCHOR},
    ]
    estate = _estate(tmp_path, services)
    scanner = tmp_path / "aig"
    scanner.write_text(f"#!{sys.executable}\n{_SCANNER}", encoding="utf-8")
    scanner.chmod(scanner.stat().st_mode | stat.S_IXUSR)
    cfg = _cfg(tmp_path, port_offset=offset)

    row = run_unit(
        AiInfraGuardAdapter(), cfg, "sim", estate, tmp_path / "runs" / "sim", RunPolicy(timeout=60)
    )
    assert row.status == "ok", row.error
    recorded = json.loads(json.dumps({"results": [row.to_dict()]}))["results"]
    assert recorded[0]["detail"][score.SCAN_TARGETS] == ["ollama-h", "vllm-h"]
    assert all(
        anchor not in p["text"] for p in recorded[0]["predictions"] for anchor in (OLLAMA_ANCHOR, VLLM_ANCHOR)
    )

    result = score.score_tool(
        _corpus(),
        "ai_infra_guard",
        RUNTIME,
        recorded,
        score.load_services(estate / "services" / "services.json"),
    )
    assert result["complete"] is True
    assert result["entity_level"]["positives_detected"] == 2
    assert result["predictions"]["harness_attributed"] == 2


# --- `run` with relative paths --------------------------------------------------------------------


class _PathEcho:
    """Writes its report to an output path it puts in argv, as argv-based adapters do."""

    spec = ToolSpec(
        id="path_echo",
        name="Path echo",
        vendor="tests",
        surfaces=frozenset({"code"}),
        categories=frozenset({"provider"}),
    )

    def __init__(self) -> None:
        self.out_dirs: list[Path] = []

    def unavailable_reason(self, cfg: ToolConfig) -> str | None:
        return None

    def version(self, cfg: ToolConfig) -> str:
        return "1"

    def units(self, cfg: ToolConfig, estate: Path, corpus: EstateCorpus) -> list[str]:
        return ["code:repo-a"]

    def commands(self, cfg: ToolConfig, unit: str, estate: Path, out_dir: Path) -> list[Command]:
        self.out_dirs.append(out_dir)
        code = "import sys; open(sys.argv[1], 'w').write('ok')"
        return [Command((sys.executable, "-c", code, str(out_dir / "report.txt")))]

    def normalize(self, unit: str, out_dir: Path) -> Normalized:
        if not (out_dir / "report.txt").is_file():
            return Normalized(error="report.txt missing")
        return Normalized(raw_count=1)


def test_run_resolves_relative_out_estate_and_tools_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A relative --out put the adapter's argv paths under the command's own cwd."""
    track = tmp_path / "track"
    repo = track / "artifacts" / "code" / "repo-a"
    repo.mkdir(parents=True)
    (repo / "app.py").write_text("import openai  # repo-a-marker\n", encoding="utf-8")
    entity = {
        "id": "code.repo-a",
        "surface": "code",
        "class": "positive",
        "difficulty": "easy",
        "expected": [{"fact": "provider:openai", "evidence": ["code/repo-a/app.py"]}],
        "anchors": ["repo-a-marker"],
        "artifacts": ["code/repo-a"],
        "unit": "code:repo-a",
    }
    (track / "corpus.json").write_text(json.dumps({"schema": 1, "metadata": {}, "entities": [entity]}))
    assert cmd_freeze(track / "corpus.json", track / "artifacts", track / "FREEZE.json") == 0
    (tmp_path / "tools.json").write_text('{"tools": {}}', encoding="utf-8")
    adapter = _PathEcho()
    monkeypatch.setattr(estate_cli, "_adapters", lambda: [adapter])
    monkeypatch.chdir(tmp_path)

    paths = ["--corpus", "track/corpus.json", "--estate", "track/artifacts", "--freeze", "track/FREEZE.json"]
    assert main(["run", *paths, "--tools", "tools.json", "--out", "out", "--workers", "1"]) == 0

    [out_dir] = adapter.out_dirs
    assert out_dir.is_absolute() and out_dir == (tmp_path / "out").resolve() / "path_echo" / "code__repo-a"
    [row] = json.loads((tmp_path / "out" / "runs.json").read_text(encoding="utf-8"))["results"]
    assert row["status"] == "ok" and not row["incomplete"], row
    assert (out_dir / "report.txt").read_text(encoding="utf-8") == "ok"
