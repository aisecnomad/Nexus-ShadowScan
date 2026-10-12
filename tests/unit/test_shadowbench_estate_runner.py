"""Regression tests for the ShadowBench estate runner, freeze, validation and live-sim host."""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import pwd
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from tools.discovery_benchmark.runner import RunPolicy
from tools.shadowbench.estate import __main__ as estate_cli
from tools.shadowbench.estate import corpus as estate_corpus
from tools.shadowbench.estate import runner, simhost
from tools.shadowbench.estate.__main__ import cmd_freeze, cmd_validate, cmd_verify_freeze, main
from tools.shadowbench.estate.adapters import (
    Command,
    Normalized,
    Prediction,
    ToolConfig,
    ToolSpec,
    home_units,
    unit_path,
)
from tools.shadowbench.estate.corpus import CorpusError, EstateCorpus, corpus_from_dict, load_corpus

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


# --- runner: a scripted adapter ---------------------------------------------------------------------

REPO = Path(__file__).resolve().parents[2]
CFG = ToolConfig({"tools": {}})


class _Scripted:
    """An estate adapter whose commands and normalization are supplied by the test."""

    def __init__(
        self,
        make: Callable[[str, Path, Path], list[Command]],
        normalize: Callable[[str, Path], Normalized] | None = None,
    ) -> None:
        self.spec = ToolSpec(
            id="fake_tool",
            name="Fake tool",
            vendor="tests",
            surfaces=frozenset({"endpoint"}),
            categories=frozenset({"mcp"}),
        )
        self._make = make
        self._normalize = normalize or (lambda unit, out_dir: Normalized())
        self.estates: list[Path] = []

    def unavailable_reason(self, cfg: ToolConfig) -> str | None:
        return None

    def version(self, cfg: ToolConfig) -> str:
        return "0.0.0"

    def units(self, cfg: ToolConfig, estate: Path, corpus: EstateCorpus) -> list[str]:
        return home_units(estate)

    def commands(self, cfg: ToolConfig, unit: str, estate: Path, out_dir: Path) -> list[Command]:
        self.estates.append(estate)
        return self._make(unit, estate, out_dir)

    def normalize(self, unit: str, out_dir: Path) -> Normalized:
        return self._normalize(unit, out_dir)


# A tool that keeps state in HOME: a new cache file and an edit to a frozen config.
_WRITE_HOME = (
    "import json, os, pathlib, sys\n"
    "home = pathlib.Path(os.environ['HOME'])\n"
    "(home / '.cache' / 'tool').mkdir(parents=True, exist_ok=True)\n"
    "(home / '.cache' / 'tool' / 'state.db').write_text('cache')\n"
    "with open(home / '.cursor' / 'mcp.json', 'a') as handle:\n"
    "    handle.write(' ')\n"
    "pathlib.Path(sys.argv[1]).write_text(json.dumps({'home': str(home)}))\n"
)


def _home_writer() -> _Scripted:
    def make(unit: str, estate: Path, out_dir: Path) -> list[Command]:
        home = unit_path(unit, estate)
        argv = (sys.executable, "-c", _WRITE_HOME, str(out_dir / "seen.json"))
        return [Command(argv, env={"HOME": str(home)})]

    def normalize(unit: str, out_dir: Path) -> Normalized:
        seen = out_dir / "seen.json"
        if not seen.exists():
            return Normalized(error="seen.json missing")
        home = json.loads(seen.read_text(encoding="utf-8"))["home"]
        return Normalized(predictions=[Prediction("mcp:server", f"freight-mcp-x1 {home}", "endpoint")])

    return _Scripted(make, normalize)


def _run_cli(tmp_path: Path, corpus: Path, artifacts: Path, freeze: Path) -> int:
    tools = tmp_path / "tools.json"
    tools.write_text('{"tools": {}}', encoding="utf-8")
    argv = ["run", "--corpus", str(corpus), "--estate", str(artifacts), "--freeze", str(freeze)]
    return main([*argv, "--tools", str(tools), "--out", str(tmp_path / "cli")])


# --- private estate copies and the freeze around a run ---------------------------------------------


def test_each_unit_runs_on_a_private_copy_and_leaves_the_frozen_estate_alone(tmp_path: Path) -> None:
    """A tool writing into HOME used to write into the committed home tree.

    Five adapters point HOME at the estate's home trees while other tools scan
    the same trees, so a cache written there changed the frozen corpus under
    every concurrent run. Each unit now gets its own copy.
    """
    corpus, artifacts, freeze = _make_estate(tmp_path)
    manifest = runner.run_matrix(
        load_corpus(corpus),
        [_home_writer()],
        CFG,
        artifacts,
        tmp_path / "runs",
        RunPolicy(timeout=60),
        freeze=freeze,
        corpus_path=corpus,
        workers=2,
    )

    assert cmd_verify_freeze(corpus, artifacts, freeze) == 0
    assert not (artifacts / "home" / "dev-x" / "dana" / ".cache").exists()
    [row] = manifest["results"]
    assert row["status"] == "ok" and not row["incomplete"]
    seen = Path(
        json.loads((tmp_path / "runs" / "fake_tool" / "home__dev-x" / "seen.json").read_text())["home"]
    )
    assert artifacts.resolve() not in seen.resolve().parents
    assert seen.parts[-4:] == ("artifacts", "home", "dev-x", "dana")
    assert not seen.exists(), "the private copy is removed after the unit"
    assert row["estate_changes"] == [
        "artifacts/home/dev-x/dana/.cache/tool/state.db",
        "artifacts/home/dev-x/dana/.cursor/mcp.json",
    ]
    assert manifest["freeze"] == {
        "sha256": hashlib.sha256(freeze.read_bytes()).hexdigest(),
        "files": 3,
        "drift_after": [],
    }
    assert "harness_commit" in manifest and "harness_dirty" in manifest
    assert json.loads((tmp_path / "runs" / "runs.json").read_text())["freeze"] == manifest["freeze"]


def test_a_drifted_estate_is_refused_before_anything_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    corpus, artifacts, freeze = _make_estate(tmp_path)
    (artifacts / "code" / "repo-a" / "app.py").write_text("import anthropic\n", encoding="utf-8")
    adapter = _home_writer()
    monkeypatch.setattr(estate_cli, "_adapters", lambda: [adapter])
    assert _run_cli(tmp_path, corpus, artifacts, freeze) == 1
    captured = capsys.readouterr()
    assert "DRIFT artifacts/code/repo-a/app.py" in captured.out and "refusing to run" in captured.err
    assert adapter.estates == [] and not (tmp_path / "cli" / "runs.json").exists()


def test_cli_run_records_the_freeze_digest(tmp_path: Path) -> None:
    corpus, artifacts, freeze = _make_estate(tmp_path)
    assert _run_cli(tmp_path, corpus, artifacts, freeze) == 0
    manifest = json.loads((tmp_path / "cli" / "runs.json").read_text())
    assert manifest["freeze"]["sha256"] == hashlib.sha256(freeze.read_bytes()).hexdigest()
    assert manifest["results"] == [] and manifest["tools_skipped"]


def test_drift_during_the_run_is_recorded_and_fails_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A tool that writes to the source estate by absolute path cannot hide it."""
    corpus, artifacts, freeze = _make_estate(tmp_path)
    source = artifacts / "code" / "repo-a" / "app.py"

    def escape(unit: str, estate: Path, out_dir: Path) -> list[Command]:
        code = f"open({str(source)!r}, 'a').write('# touched')"
        return [Command((sys.executable, "-c", code))]

    monkeypatch.setattr(estate_cli, "_adapters", lambda: [_Scripted(escape)])
    assert _run_cli(tmp_path, corpus, artifacts, freeze) == 1
    manifest = json.loads((tmp_path / "cli" / "runs.json").read_text())
    assert manifest["freeze"]["drift_after"] == ["artifacts/code/repo-a/app.py"]
    assert "DRIFT artifacts/code/repo-a/app.py" in capsys.readouterr().out


# --- incomplete runs ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("argv_code", "ok_codes", "timeout", "status", "incomplete"),
    [
        ("import time; time.sleep(30)", frozenset({0}), 1, "timeout", True),
        ("raise SystemExit(5)", frozenset({0}), None, "failed", True),
        ("raise SystemExit(3)", frozenset({0, 3}), None, "ok", False),
        ("pass", frozenset({0}), None, "ok", False),
    ],
)
def test_timeouts_and_undeclared_exit_codes_mark_the_unit_incomplete(
    tmp_path: Path,
    argv_code: str,
    ok_codes: frozenset[int],
    timeout: int | None,
    status: str,
    incomplete: bool,
) -> None:
    """A timed-out unit kept `incomplete: false`, so its empty output scored as clean negatives."""
    _, artifacts, _ = _make_estate(tmp_path)

    def make(unit: str, estate: Path, out_dir: Path) -> list[Command]:
        return [Command((sys.executable, "-c", argv_code), ok_exit_codes=ok_codes, timeout=timeout)]

    row = runner.run_unit(
        _Scripted(make),
        CFG,
        "home:dev-x",
        artifacts,
        tmp_path / "out",
        RunPolicy(timeout=60),
    )
    assert (row.status, row.incomplete) == (status, incomplete)
    assert json.loads((tmp_path / "out" / "result.json").read_text())["incomplete"] is incomplete


@pytest.mark.parametrize("broken", ["commands", "normalize"])
def test_adapter_errors_mark_the_unit_incomplete(tmp_path: Path, broken: str) -> None:
    _, artifacts, _ = _make_estate(tmp_path)

    def make(unit: str, estate: Path, out_dir: Path) -> list[Command]:
        if broken == "commands":
            raise RuntimeError("adapter bug")
        return [Command((sys.executable, "-c", "pass"))]

    def normalize(unit: str, out_dir: Path) -> Normalized:
        if broken == "normalize":
            raise RuntimeError("adapter bug")
        return Normalized()

    row = runner.run_unit(
        _Scripted(make, normalize),
        CFG,
        "home:dev-x",
        artifacts,
        tmp_path / "out",
        RunPolicy(timeout=60),
    )
    assert row.status == "error" and row.incomplete and row.error == f"{broken}: adapter bug"


def test_stdout_name_stores_a_report_without_a_shell_wrapper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, artifacts, _ = _make_estate(tmp_path)
    names = ["report.json", "../escape.json", "report.json"]

    def make(unit: str, estate: Path, out_dir: Path) -> list[Command]:
        return [Command((sys.executable, "-c", "print('[1, 2, 3]')"), stdout_name=names.pop(0))]

    adapter = _Scripted(make)
    row = runner.run_unit(adapter, CFG, "home:dev-x", artifacts, tmp_path / "a", RunPolicy())
    assert row.status == "ok" and row.commands[0].stdout_file == "report.json"
    assert (tmp_path / "a" / "report.json").read_text() == "[1, 2, 3]\n"
    refused = runner.run_unit(adapter, CFG, "home:dev-x", artifacts, tmp_path / "b", RunPolicy())
    assert refused.status == "failed" and refused.incomplete
    assert not (tmp_path / "escape.json").exists()
    # A report cut at the capture limit is partial output, never a short complete one.
    monkeypatch.setattr(runner, "MAX_CAPTURE_BYTES", 4)
    cut = runner.run_unit(adapter, CFG, "home:dev-x", artifacts, tmp_path / "c", RunPolicy())
    assert cut.status == "failed" and cut.incomplete
    assert (tmp_path / "c" / "report.json").read_text() == "[1, "


# --- --as-user ------------------------------------------------------------------------------------


def test_as_user_hands_the_output_dir_and_the_estate_copy_to_the_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """--as-user ran tools that could not write their own output directory or HOME."""
    _, artifacts, _ = _make_estate(tmp_path)
    chowned: list[tuple[Path, str | None, bool]] = []
    monkeypatch.setattr(
        runner, "_chown_tree", lambda path, user: chowned.append((path, user, (path / "tmp").is_dir()))
    )
    monkeypatch.setattr(runner, "_wrap", lambda policy, argv, env: list(argv))
    adapter = _Scripted(lambda unit, estate, out_dir: [Command((sys.executable, "-c", "pass"))])
    row = runner.run_unit(
        adapter,
        CFG,
        "home:dev-x",
        artifacts,
        tmp_path / "out",
        RunPolicy(as_user="svc-bench"),
        workdir=tmp_path / "work",
    )
    assert row.status == "ok"
    assert chowned == [(tmp_path / "out", "svc-bench", True), (tmp_path / "work", "svc-bench", False)]
    assert adapter.estates == [tmp_path / "work" / "artifacts"]


def _nobody() -> pwd.struct_passwd | None:
    try:
        return pwd.getpwnam("nobody")
    except KeyError:
        return None


@pytest.mark.skipif(
    not hasattr(os, "geteuid")
    or os.geteuid() != 0
    or not shutil.which("setpriv")
    or not Path("/usr/bin/python3").exists()
    or _nobody() is None,
    reason="needs root, setpriv, /usr/bin/python3 and a 'nobody' account",
)
def test_as_user_tools_can_write_their_output_and_home(tmp_path: Path) -> None:
    _, artifacts, _ = _make_estate(tmp_path)
    user = _nobody()
    assert user is not None
    out_root = Path(tempfile.mkdtemp(prefix="estate-as-user-"))
    try:
        out_root.chmod(0o755)

        def make(unit: str, estate: Path, out_dir: Path) -> list[Command]:
            home = unit_path(unit, estate)
            argv = ("/usr/bin/python3", "-c", _WRITE_HOME, str(out_dir / "seen.json"))
            return [Command(argv, env={"HOME": str(home)})]

        row = runner.run_unit(
            _Scripted(make),
            CFG,
            "home:dev-x",
            artifacts,
            out_root / "out",
            RunPolicy(as_user="nobody", timeout=60),
        )
        assert row.status == "ok", (out_root / "out" / "0.stderr.txt").read_text()
        assert (out_root / "out" / "seen.json").stat().st_uid == user.pw_uid
        assert "artifacts/home/dev-x/dana/.cache/tool/state.db" in row.estate_changes
    finally:
        shutil.rmtree(out_root, ignore_errors=True)


# --- harness revision -------------------------------------------------------------------------------


def test_harness_revision_is_null_outside_the_harness_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(runner, "ROOT", tmp_path)
    assert runner.harness_revision() == {"commit": None, "dirty": None}


@pytest.mark.skipif(not shutil.which("git") or not (REPO / ".git").exists(), reason="needs a git checkout")
def test_harness_revision_names_the_checkout_commit() -> None:
    head = subprocess.run(
        ["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    revision = runner.harness_revision()
    assert revision["commit"] == head and isinstance(revision["dirty"], bool)


# --- simhost --------------------------------------------------------------------------------------


def test_simhost_names_a_busy_port_and_never_runs_the_command(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A real Ollama on 11434 made the mock host die with a bare OSError traceback."""
    marker = tmp_path / "ran"
    services = tmp_path / "services.json"
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        port = busy.getsockname()[1]
        services.write_text(json.dumps({"services": [{"kind": "ollama", "port": port}]}), encoding="utf-8")
        code = simhost.main(
            ["--services", str(services), "--", sys.executable, "-c", f"open({str(marker)!r}, 'w')"]
        )
    assert code == simhost.EXIT_SETUP and not marker.exists()
    err = capsys.readouterr().err
    assert f"127.0.0.1:{port} is already in use" in err and "--port-offset" in err


def test_simhost_port_offset_moves_every_service(tmp_path: Path) -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        free = probe.getsockname()[1]
    services = tmp_path / "services.json"
    services.write_text(json.dumps({"services": [{"kind": "ollama", "port": free - 7}]}), encoding="utf-8")
    out = tmp_path / "version.json"
    fetch = (
        "import http.client\n"
        f"conn = http.client.HTTPConnection('127.0.0.1', {free}, timeout=10)\n"
        "conn.request('GET', '/api/version')\n"
        f"open({str(out)!r}, 'wb').write(conn.getresponse().read())\n"
    )
    code = simhost.main(
        ["--services", str(services), "--port-offset", "7", "--", sys.executable, "-c", fetch]
    )
    assert code == 0 and json.loads(out.read_text()) == {"version": "0.3.9"}
    # Nothing is left listening once the command has finished.
    with pytest.raises(OSError):
        http.client.HTTPConnection("127.0.0.1", free, timeout=2).request("GET", "/")


def test_simhost_rejects_duplicate_ports(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    services = tmp_path / "services.json"
    twins = [{"kind": "ollama", "port": 40000}, {"kind": "vllm", "port": 40000}]
    services.write_text(json.dumps({"services": twins}), encoding="utf-8")
    code = simhost.main(["--services", str(services), "--", sys.executable, "-c", "pass"])
    assert code == simhost.EXIT_SETUP
    assert "both use port 40000" in capsys.readouterr().err
