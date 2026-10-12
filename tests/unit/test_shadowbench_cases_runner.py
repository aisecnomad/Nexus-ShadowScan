"""Unit tests for the ShadowBench cases runner, stage and mock services (tools/shadowbench/cases).

Most tests run unprivileged. The ``needs_namespaces`` tests run the real stage
under ``unshare`` and only run as root on a host that allows network, PID and
mount namespaces.
"""

from __future__ import annotations

import functools
import json
import os
import shutil
import signal
import socket
import stat
import subprocess
import tempfile
import threading
import time
import urllib.request
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import Any

import pytest

from tools.shadowbench.cases import runner, stage
from tools.shadowbench.cases.adapters.registry import load_adapters
from tools.shadowbench.cases.contract import (
    AdapterResult,
    Entity,
    Invocation,
    MaterializedCase,
    RunResult,
    ToolEnv,
    base_env,
    supports,
)
from tools.shadowbench.cases.corpus import Case, load_corpus
from tools.shadowbench.cases.mockserv import Services, checked_service

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "benchmarks" / "shadowbench" / "cases" / "corpus.json"
SENTINEL = "sb-operator-sentinel-6f1c"
"""Planted in the test process's environment; it must never reach a tool or an inert process."""
TOOL_PATH = "/usr/bin:/bin"


def _case(
    case_id: str = "okta-1",
    files: dict[str, str] | None = None,
    checkout: dict[str, Any] | None = None,
    surface: str = "identity",
    modality: str = "okta-export",
) -> Case:
    return Case(
        case_id=case_id,
        surface=surface,
        modality=modality,
        family="test",
        difficulty="easy",
        rationale="test",
        files=dict(files or {}),
        checkout=checkout,
    )


def _git_repo(path: Path, files: dict[str, str], links: dict[str, str] | None = None) -> str:
    path.mkdir(parents=True)

    def git(*args: str) -> str:
        cmd = ["git", "-C", str(path), "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
        cmd += ["-c", "commit.gpgsign=false", *args]
        return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout.strip()

    git("init", "-q")
    for rel, content in files.items():
        (path / rel).parent.mkdir(parents=True, exist_ok=True)
        (path / rel).write_text(content, encoding="utf-8")
    for rel, target in (links or {}).items():
        os.symlink(target, path / rel)
    git("add", "-A")
    git("commit", "-q", "-m", "fixture")
    return git("rev-parse", "HEAD")


needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")


class FakeAdapter:
    """An adapter whose invocation and normalized result the test decides."""

    name = "fake"
    display = "Fake"
    surfaces: Mapping[str, frozenset[str]] = {"identity": frozenset({"okta-export"})}

    def __init__(
        self,
        result: AdapterResult | None = None,
        script: str = "true",
        normalize: Callable[[Path, list[RunResult]], AdapterResult] | None = None,
    ) -> None:
        self.result = result or AdapterResult("ok")
        self.script = script
        self._normalize = normalize
        self.work: Path | None = None

    def unavailable_reason(self, env: ToolEnv) -> str | None:
        return None

    def version(self, env: ToolEnv) -> str:
        return "0"

    def invocations(self, case: MaterializedCase, env: ToolEnv, work: Path) -> list[Invocation]:
        self.work = work
        return [Invocation(argv=("sh", "-c", self.script), cwd=work, env=base_env(work, work), timeout=30)]

    def normalize(self, case: MaterializedCase, work: Path, runs: list[RunResult]) -> AdapterResult:
        return self._normalize(work, runs) if self._normalize else self.result


def _run(code: int = 0, stdout: str = "", stderr: str = "") -> dict[str, Any]:
    return {"code": code, "stdout": stdout, "stderr": stderr, "seconds": 0.1, "timed_out": False}


def _fake_stage(runs: list[dict[str, Any]], seen: dict[str, Any]) -> Callable[..., dict[str, Any]]:
    """Stand in for the stage: record what it was given and return ``runs``."""

    def fake(spec: dict[str, Any], control: Path, repo: Path, timeout: float) -> dict[str, Any]:
        control = Path(control)
        seen.update(
            spec=spec,
            control=control,
            control_mode=stat.S_IMODE(control.stat().st_mode),
            run_dir_mode=stat.S_IMODE(Path(spec["work"]).parent.stat().st_mode),
        )
        return {"runs": runs, "processes": [], "error": None}

    return fake


def _run_one(adapter: FakeAdapter, tmp_path: Path, case: Case | None = None) -> dict[str, Any]:
    case = case or _case(files={"okta/apps.json": "[]"})
    return runner.run_one(adapter, case, ToolEnv(tmp_path), tmp_path, ROOT, tmp_path / "fakeproc", None)


@pytest.fixture
def no_chown(monkeypatch: pytest.MonkeyPatch) -> None:
    """Handing the work tree to uid 65534 needs root; the run_one unit tests do not."""
    monkeypatch.setattr(runner, "_chown_tree", lambda *args: None, raising=False)


# --- a failed exit that still reports entities is incomplete --------------------------------------


def test_run_one_flags_entities_from_a_failed_exit_as_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_chown: None
) -> None:
    monkeypatch.setattr(runner, "_stage", _fake_stage([_run(code=1, stderr="crashed half way")], {}))
    adapter = FakeAdapter(AdapterResult("ok", [Entity("app", "app:0oa1", "agent")]))
    row = _run_one(adapter, tmp_path)
    assert row["status"] == "ok"
    assert row["entities"] == [{"kind": "app", "key": "app:0oa1", "label": "agent"}]
    assert row["incomplete"] is True
    assert "exit 1" in row["note"]


def test_run_one_keeps_a_clean_run_complete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_chown: None
) -> None:
    monkeypatch.setattr(runner, "_stage", _fake_stage([_run()], {}))
    row = _run_one(FakeAdapter(AdapterResult("ok", [Entity("app", "app:0oa1", "agent")])), tmp_path)
    assert (row["status"], row["incomplete"], row["note"]) == ("ok", False, "")


def test_run_one_still_errors_a_failed_exit_without_entities(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_chown: None
) -> None:
    monkeypatch.setattr(runner, "_stage", _fake_stage([_run(code=2, stderr="no such file")], {}))
    row = _run_one(FakeAdapter(AdapterResult("ok")), tmp_path)
    assert row["status"] == "error"
    assert row["note"].startswith("exit 2")


# --- the stage spec stays out of the tool's tree --------------------------------------------------


def test_stage_spec_and_result_live_outside_the_tool_visible_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_chown: None
) -> None:
    seen: dict[str, Any] = {}
    monkeypatch.setattr(runner, "_stage", _fake_stage([_run()], seen))
    adapter = FakeAdapter()
    _run_one(adapter, tmp_path)
    assert adapter.work is not None
    assert Path(seen["spec"]["work"]) == adapter.work
    assert not seen["control"].is_relative_to(adapter.work)
    assert seen["control_mode"] == 0o700
    assert seen["run_dir_mode"] == 0o711


# --- how the runner starts and stops the stage ----------------------------------------------------


class FakePopen:
    """Stands in for unshare: records the call, writes an empty stage result, or times out."""

    calls: list[dict[str, Any]] = []
    hang = False

    def __init__(self, args: list[str], **kwargs: Any) -> None:
        self.args = list(args)
        self.kwargs = kwargs
        self.pid = 424242
        self.returncode: int | None = 0
        self.timeouts = 1 if FakePopen.hang else 0
        FakePopen.calls.append({"args": self.args, **kwargs})
        if not FakePopen.hang:
            Path(self.args[-1]).write_text(json.dumps({"runs": [], "processes": [], "error": None}))

    def communicate(self, input: Any = None, timeout: float | None = None) -> tuple[Any, Any]:
        if self.timeouts:
            self.timeouts -= 1
            raise subprocess.TimeoutExpired(self.args, timeout or 0)
        empty = "" if self.kwargs.get("text") else b""
        return empty, empty

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int | None:
        return self.returncode

    def kill(self) -> None:
        pass

    def __enter__(self) -> FakePopen:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


@pytest.fixture
def fake_popen(monkeypatch: pytest.MonkeyPatch) -> type[FakePopen]:
    FakePopen.calls = []
    FakePopen.hang = False
    monkeypatch.setattr(subprocess, "Popen", FakePopen)
    return FakePopen


def test_stage_is_started_with_an_environment_built_from_scratch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_popen: type[FakePopen]
) -> None:
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", SENTINEL)
    monkeypatch.setenv("PATH", f"/{SENTINEL}/bin:{os.environ.get('PATH', '')}")
    control = tmp_path / "control"
    control.mkdir()
    staged = runner._stage({"work": str(tmp_path / "work"), "invocations": []}, control, ROOT, 30)
    assert staged["error"] is None
    (call,) = fake_popen.calls
    env = call["env"]
    assert set(env) <= {"PATH", "PYTHONPATH", "LANG", "PYTHONDONTWRITEBYTECODE"}
    assert not [v for v in env.values() if SENTINEL in v]
    assert call["stdin"] == subprocess.DEVNULL
    spec = json.loads((control / "stage_spec.json").read_text(encoding="utf-8"))
    assert spec["run_as"] == [65534, 65534]
    assert spec["host_mnt_ns"] == os.readlink("/proc/self/ns/mnt")


def test_stage_runs_in_its_own_process_group_and_dies_with_unshare(
    tmp_path: Path, fake_popen: type[FakePopen]
) -> None:
    runner._stage({"work": str(tmp_path), "invocations": []}, tmp_path, ROOT, 30)
    (call,) = fake_popen.calls
    assert {"--net", "--pid", "--fork", "--kill-child", "--mount", "--mount-proc"} <= set(call["args"])
    assert call["start_new_session"] is True


def test_stage_timeout_kills_the_whole_process_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_popen: type[FakePopen]
) -> None:
    killed: list[tuple[int, int]] = []
    monkeypatch.setattr(os, "killpg", lambda pgid, sig: killed.append((pgid, sig)))
    fake_popen.hang = True
    staged = runner._stage({"work": str(tmp_path), "invocations": []}, tmp_path, ROOT, 1)
    assert "timed out" in staged["error"]
    assert killed == [(424242, signal.SIGKILL)]


# --- a killed invocation cannot stall the stage ---------------------------------------------------


def _kill_pidfile(path: Path) -> None:
    try:
        pid = int(path.read_text().strip())
        if b"sleep" in Path(f"/proc/{pid}/cmdline").read_bytes():
            os.kill(pid, signal.SIGKILL)
    except (OSError, ValueError):
        pass


def test_stage_run_timeout_is_bounded_when_a_setsid_grandchild_holds_the_pipes(tmp_path: Path) -> None:
    script = "setsid sh -c 'echo $$ > grandchild.pid; exec sleep 60' & exec sleep 60"
    inv = {"argv": ["sh", "-c", script], "cwd": str(tmp_path), "env": {"PATH": TOOL_PATH}, "timeout": 1}
    box: dict[str, Any] = {}
    started = time.monotonic()
    worker = threading.Thread(target=lambda: box.update(run=stage._run(inv)), daemon=True)
    worker.start()
    try:
        worker.join(25)
        assert not worker.is_alive(), "the stage waited on a setsid grandchild after the timeout"
        assert box["run"]["timed_out"] is True
        assert box["run"]["code"] == 124
        assert time.monotonic() - started < 20
    finally:
        _kill_pidfile(tmp_path / "grandchild.pid")


# --- mock services only ever listen on loopback ---------------------------------------------------


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.mark.parametrize(
    ("spec", "message"),
    [
        ({"ip": "0.0.0.0", "product": "ollama"}, "127.0.0.1"),
        ({"ip": "10.1.2.3", "product": "ollama"}, "127.0.0.1"),
        ({"ip": "localhost", "product": "ollama"}, "127.0.0.1"),
        ({"ip": "127.0.0.1", "port": 0, "product": "ollama"}, "port"),
        ({"ip": "127.0.0.1", "port": 70000, "product": "ollama"}, "port"),
        ({"ip": "127.0.0.1", "port": "as-text", "product": "ollama"}, "port"),
        ({"ip": "127.0.0.1", "port": True, "product": "ollama"}, "port"),
        ({"ip": "127.0.0.1", "product": "no-such-product"}, "product"),
    ],
)
def test_services_refuse_anything_but_a_known_product_on_loopback(spec: dict[str, Any], message: str) -> None:
    # A spec without a port gets a free one, so a wrongly accepted spec binds nothing already in use.
    port = _free_port()
    spec = {"port": port, **spec}
    if spec["port"] == "as-text":
        spec["port"] = str(port)  # "8080" is a string, not a port number
    services = Services([spec])
    try:
        with pytest.raises(ValueError, match=message):
            services.start(timeout=0.5)
        assert services.servers == []
    finally:
        services.stop()


@pytest.mark.parametrize("port", [1, 80, 443, 1023])
def test_services_refuse_privileged_ports(port: int) -> None:
    with pytest.raises(ValueError, match="invalid port"):
        checked_service({"ip": "127.0.0.1", "port": port, "product": "ollama"})


def test_services_accept_every_committed_service() -> None:
    specs = [s for case in load_corpus(CORPUS).cases for s in case.services]
    assert specs
    assert min(checked_service(s)[1] for s in specs) >= 1024


def test_services_validate_every_spec_before_binding_any() -> None:
    good = {"ip": "127.0.0.1", "port": _free_port(), "product": "ollama"}
    services = Services([good, {"ip": "0.0.0.0", "port": _free_port(), "product": "vllm"}])
    try:
        with pytest.raises(ValueError):
            services.start(timeout=0.5)
        assert services.servers == []
    finally:
        services.stop()


def test_services_answer_on_loopback() -> None:
    port = _free_port()
    services = Services([{"ip": "127.0.0.1", "port": port, "product": "ollama"}])
    try:
        services.start(timeout=5)
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/version", timeout=5) as resp:
            assert json.loads(resp.read()) == {"version": "0.12.3"}
    finally:
        services.stop()


# --- corpus ids and files never write outside the case --------------------------------------------


@pytest.mark.parametrize("bad", ["../escape", "a/b", ".", "..", "", "with space", "/abs", "x\0y"])
def test_materialize_rejects_unsafe_checkout_ids(tmp_path: Path, bad: str) -> None:
    (tmp_path / "checkouts").mkdir()
    case = _case(surface="code", modality="checkout", checkout={"id": bad, "commit": "0" * 40})
    with pytest.raises(ValueError, match="unsafe checkout id"):
        runner.materialize(case, tmp_path / "case", tmp_path / "checkouts")


@needs_git
def test_materialize_rejects_a_checkout_that_resolves_outside_the_checkouts_dir(tmp_path: Path) -> None:
    commit = _git_repo(tmp_path / "elsewhere", {"README.md": "x\n"})
    (tmp_path / "checkouts").mkdir()
    os.symlink(tmp_path / "elsewhere", tmp_path / "checkouts" / "pinned")
    case = _case(surface="code", modality="checkout", checkout={"id": "pinned", "commit": commit})
    with pytest.raises(ValueError, match="outside"):
        runner.materialize(case, tmp_path / "case", tmp_path / "checkouts")
    assert not (tmp_path / "case" / "inputs" / "repo").exists()


@needs_git
def test_materialize_refuses_files_beside_a_checkout(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    commit = _git_repo(tmp_path / "checkouts" / "pinned", {"README.md": "x\n"}, links={"docs": str(outside)})
    case = _case(
        surface="code",
        modality="checkout",
        checkout={"id": "pinned", "commit": commit},
        files={"repo/docs/planted.txt": "planted"},
    )
    with pytest.raises(ValueError, match="beside its checkout"):
        runner.materialize(case, tmp_path / "case", tmp_path / "checkouts")
    assert not (outside / "planted.txt").exists()


def test_materialize_never_writes_through_a_symlink(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / "case" / "inputs").mkdir(parents=True)
    os.symlink(outside, tmp_path / "case" / "inputs" / "okta")
    with pytest.raises(ValueError, match="symlink"):
        runner.materialize(_case(files={"okta/apps.json": "[]"}), tmp_path / "case")
    assert not (outside / "apps.json").exists()


@pytest.mark.parametrize("rel", ["../escape.txt", "okta/../../escape.txt", "/escape.txt", "okta//apps.json"])
def test_materialize_rejects_input_paths_that_leave_inputs(tmp_path: Path, rel: str) -> None:
    with pytest.raises(ValueError, match="unsafe input path"):
        runner.materialize(_case(files={rel: "x"}), tmp_path / "case")
    assert not (tmp_path / "case" / "escape.txt").exists()
    assert not (tmp_path / "escape.txt").exists()


def test_materialize_writes_nested_inputs(tmp_path: Path) -> None:
    mat = runner.materialize(
        _case(files={"okta/apps.json": "[]", "okta/grants/0oa1.json": "{}"}), tmp_path / "case"
    )
    assert (mat.inputs / "okta" / "apps.json").read_text(encoding="utf-8") == "[]"
    assert (mat.inputs / "okta" / "grants" / "0oa1.json").read_text(encoding="utf-8") == "{}"


@pytest.mark.parametrize("bad", ["../../etc/x", "a/b", "..", ""])
def test_runner_rejects_unsafe_case_ids(tmp_path: Path, bad: str) -> None:
    assert runner.unsafe_ids([_case(case_id=bad)])
    with pytest.raises(ValueError, match="unsafe case id"):
        runner.run_one(FakeAdapter(), _case(case_id=bad), ToolEnv(tmp_path), tmp_path, ROOT, tmp_path, None)


# --- what the runner checks and cleans around the isolated tool -----------------------------------


def test_isolation_problems_refuse_hidden_paths() -> None:
    config = {"tools": {"shadowscan": {"bin": "/opt/nsb/venv/bin/python", "repo": "/home/op/Project-Nexus"}}}
    problems = runner.isolation_problems(Path("/root/shadowbench-scratch"), ToolEnv(Path("/opt/nsb"), config))
    assert any("scratch directory /root/shadowbench-scratch" in p for p in problems)
    assert any("tools.shadowscan.repo = /home/op/Project-Nexus" in p for p in problems)
    assert not any("tools.shadowscan.bin" in p for p in problems)


def _private_scratch() -> Path:
    """A 0711 scratch directory under a 0711 parent that uid 65534 can reach (unless /tmp is closed)."""
    top = Path(tempfile.mkdtemp(prefix="shadowbench-test-"))
    top.chmod(0o711)
    (top / "scratch").mkdir(mode=0o711)
    (top / "scratch").chmod(0o711)
    return top


def test_isolation_problems_refuse_a_scratch_dir_the_tool_cannot_reach() -> None:
    top = _private_scratch()
    try:
        top.chmod(0o700)
        env = ToolEnv(Path("/opt/nsb/tools"))
        assert any("cannot traverse" in p for p in runner.isolation_problems(top / "scratch", env))
        top.chmod(0o711)
        assert runner.isolation_problems(top / "scratch", env) == []
    finally:
        shutil.rmtree(top, ignore_errors=True)


def test_isolation_problems_check_the_tool_root_tools_json_implies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Adapters build data paths from env.tool_root, which defaults to the directory of tools.json.
    monkeypatch.setattr(runner, "HIDDEN", (str(tmp_path / "home"),))
    tools_json = tmp_path / "home" / "op" / "nsb" / "tools.json"
    tools_json.parent.mkdir(parents=True)
    tools_json.write_text(json.dumps({"tools": {"ai-infra-guard": {"bin": "/opt/nsb/bin/aig"}}}))
    env = ToolEnv.load(tools_json)
    assert env.tool_root == tools_json.parent
    top = _private_scratch()
    try:
        problems = runner.isolation_problems(top / "scratch", env)
    finally:
        shutil.rmtree(top, ignore_errors=True)
    assert problems == [
        f"tool_root = {tools_json.parent} lies under {tmp_path / 'home'}, which the stage hides from tools"
    ]


def test_isolation_problems_check_an_implied_tool_root_under_root() -> None:
    env = ToolEnv(Path("/root/nsb"), {"tools": {"ai-infra-guard": {"bin": "/opt/nsb/bin/ai-infra-guard"}}})
    top = _private_scratch()
    try:
        problems = runner.isolation_problems(top / "scratch", env)
    finally:
        shutil.rmtree(top, ignore_errors=True)
    assert problems == ["tool_root = /root/nsb lies under /root, which the stage hides from tools"]


@pytest.mark.parametrize("mode", [0o755, 0o750, 0o733, 0o1777])
def test_isolation_problems_refuse_a_scratch_dir_others_can_list_or_write(mode: int) -> None:
    top = _private_scratch()
    try:
        (top / "scratch").chmod(mode)
        problems = runner.isolation_problems(top / "scratch", ToolEnv(Path("/opt/nsb")))
    finally:
        shutil.rmtree(top, ignore_errors=True)
    assert any("another run's work tree" in p for p in problems), problems


def test_isolation_problems_refuse_a_scratch_dir_the_runner_does_not_own(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    top = _private_scratch()
    try:
        owner = os.stat(top / "scratch").st_uid
        monkeypatch.setattr(os, "geteuid", lambda: owner + 1)
        problems = runner.isolation_problems(top / "scratch", ToolEnv(Path("/opt/nsb")))
    finally:
        monkeypatch.undo()
        shutil.rmtree(top, ignore_errors=True)
    assert any(f"owned by uid {owner}" in p for p in problems), problems


def test_prepare_scratch_creates_a_private_dir_and_leaves_an_existing_one_alone(tmp_path: Path) -> None:
    made = runner.prepare_scratch(tmp_path / "new" / "scratch")
    assert stat.S_IMODE(made.stat().st_mode) == 0o711
    existing = tmp_path / "existing"
    existing.mkdir()
    existing.chmod(0o755)
    assert runner.prepare_scratch(existing) == existing.resolve()
    assert stat.S_IMODE(existing.stat().st_mode) == 0o755  # refused later, never chmodded behind the back
    default = runner.prepare_scratch(None)
    try:
        assert stat.S_IMODE(default.stat().st_mode) == 0o711
    finally:
        default.rmdir()


def test_drop_unsafe_entries_removes_escaping_links_and_special_files(tmp_path: Path) -> None:
    work = tmp_path / "work"
    (work / "out").mkdir(parents=True)
    (work / "out" / "report.json").write_text("{}", encoding="utf-8")
    os.symlink("out/report.json", work / "latest.json")
    os.symlink("/root/.aws/credentials", work / "out" / "credentials")
    os.symlink("..", work / "up")
    os.mkfifo(work / "out" / "pipe")
    assert runner._drop_unsafe_entries(work) == 3
    assert sorted(p.relative_to(work).as_posix() for p in work.rglob("*")) == [
        "latest.json",
        "out",
        "out/report.json",
    ]


@pytest.mark.skipif(os.geteuid() != 0, reason="chown to another uid needs root")
def test_chown_tree_hands_over_the_tree_without_following_links(tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("x", encoding="utf-8")
    work = tmp_path / "work"
    (work / "case" / "inputs").mkdir(parents=True)
    (work / "case" / "inputs" / "f.json").write_text("{}", encoding="utf-8")
    os.symlink(outside, work / "case" / "link")
    runner._chown_tree(work, 65534, 65534)
    for path in (work, work / "case", work / "case" / "inputs" / "f.json", work / "case" / "link"):
        assert os.lstat(path).st_uid == 65534
    assert outside.stat().st_uid == 0


def _no_new_privs() -> str:
    status = Path("/proc/self/status").read_text(encoding="utf-8")
    return next((line for line in status.splitlines() if line.startswith("NoNewPrivs")), "")


def _stage_main(tmp_path: Path, spec: dict[str, Any]) -> dict[str, Any]:
    (tmp_path / "spec.json").write_text(json.dumps(spec), encoding="utf-8")
    stage.main([str(tmp_path / "spec.json"), str(tmp_path / "out.json")])
    result: dict[str, Any] = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
    return result


def _touch_spec(tmp_path: Path) -> dict[str, Any]:
    inv = {"argv": ["sh", "-c", "touch ran"], "cwd": str(tmp_path), "env": {"PATH": TOOL_PATH}, "timeout": 30}
    return {"work": str(tmp_path), "invocations": [inv]}


def test_stage_refuses_to_run_tools_without_an_unprivileged_identity(tmp_path: Path) -> None:
    for run_as in (None, [0, 0], [65534], [True, 65534]):
        spec = _touch_spec(tmp_path)
        if run_as is not None:
            spec["run_as"] = run_as
        result = _stage_main(tmp_path, spec)
        assert "identity" in result["error"]
        assert result["runs"] == []
        assert not (tmp_path / "ran").exists()


def test_stage_refuses_to_set_up_outside_a_fresh_namespace(tmp_path: Path) -> None:
    before = _no_new_privs()
    spec = {
        **_touch_spec(tmp_path),
        "run_as": [65534, 65534],
        "host_mnt_ns": os.readlink("/proc/self/ns/mnt"),
    }
    result = _stage_main(tmp_path, spec)
    assert "namespace" in result["error"]
    assert result["runs"] == []
    assert not (tmp_path / "ran").exists()
    assert _no_new_privs() == before


# --- tools and inert processes see only the environment they are given ----------------------------


def test_tool_environment_is_exactly_the_invocation_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", SENTINEL)
    monkeypatch.setenv("GITHUB_TOKEN", SENTINEL)
    inv = {"argv": ["env"], "cwd": str(tmp_path), "env": {"PATH": TOOL_PATH, "ONLY": "1"}, "timeout": 30}
    run = stage._run(inv)
    assert run["code"] == 0
    assert sorted(run["stdout"].splitlines()) == ["ONLY=1", f"PATH={TOOL_PATH}"]


def _coreutils_sleep() -> str | None:
    found = shutil.which("sleep")
    return found if found and os.path.basename(os.path.realpath(found)) == "sleep" else None


@pytest.mark.skipif(_coreutils_sleep() is None, reason="needs a standalone sleep binary")
def test_inert_processes_get_a_fixed_minimal_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", SENTINEL)
    sleep = _coreutils_sleep()
    assert sleep is not None
    (child,) = stage._spawn(
        [{"index": 0, "name": "inert", "argv": ["inert", "60"]}], Path(sleep), tmp_path / "bin"
    )
    try:
        raw = Path(f"/proc/{child['pid']}/environ").read_bytes()
    finally:
        os.kill(child["pid"], signal.SIGKILL)
        os.waitpid(child["pid"], 0)
    environ = dict(item.split("=", 1) for item in raw.decode().split("\0") if item)
    assert set(environ) == {"PATH", "LANG"}
    assert SENTINEL not in raw.decode()


class _AnyToolEnv(ToolEnv):
    """Every tool is configured, under a path outside any home."""

    def tool(self, name: str) -> dict[str, Any]:
        return {"bin": f"/opt/shadowbench-test/bin/{name}", "repo": "/opt/shadowbench-test/repo"}


def test_no_adapter_hands_the_operator_environment_to_a_tool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "OPENAI_API_KEY", "HTTPS_PROXY", "SSH_AUTH_SOCK"):
        monkeypatch.setenv(name, SENTINEL)
    adapters, _ = load_adapters()
    assert adapters
    first: dict[tuple[str, str], Case] = {}
    for case in load_corpus(CORPUS).cases:
        if case.checkout is None:
            first.setdefault((case.surface, case.modality), case)
    checked = 0
    for adapter in adapters.values():
        for (surface, modality), case in sorted(first.items()):
            if not supports(adapter, surface, modality):
                continue
            work = tmp_path / f"{adapter.name}-{case.case_id}"
            work.mkdir()
            mat = runner.materialize(case, work / "case")
            for inv in adapter.invocations(mat, _AnyToolEnv(tmp_path), work):
                leaked = {k: v for k, v in inv.env.items() if SENTINEL in k or SENTINEL in v}
                assert not leaked, (adapter.name, case.case_id, leaked)
                checked += 1
    assert checked


# --- the real stage, as root in fresh namespaces ----------------------------------------------


@functools.cache
def _namespaces_available() -> bool:
    if os.geteuid() != 0 or shutil.which("unshare") is None:
        return False
    probe = ["unshare", "--net", "--pid", "--fork", "--kill-child", "--mount", "--propagation", "private"]
    try:
        done = subprocess.run([*probe, "--mount-proc", "--", "true"], capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return False
    return done.returncode == 0


needs_namespaces = pytest.mark.skipif(
    not _namespaces_available(), reason="needs root and unshare with network, PID and mount namespaces"
)


def _kill_leftovers(scratch: Path) -> None:
    """Kill host processes a failed stage left running in the scratch tree."""
    mark = str(scratch)
    for entry in os.listdir("/proc"):
        if not entry.isdigit() or int(entry) == os.getpid():
            continue
        try:
            cmdline = Path(f"/proc/{entry}/cmdline").read_bytes().decode("utf-8", "replace")
            cwd = os.readlink(f"/proc/{entry}/cwd")
        except OSError:
            continue
        if mark in cmdline or cwd.startswith(mark):
            try:
                os.kill(int(entry), signal.SIGKILL)
            except ProcessLookupError:
                pass


@pytest.fixture
def scratch() -> Iterator[Path]:
    """A scratch directory uid 65534 can traverse, laid out like ``run_one``'s run directory."""
    path = Path(tempfile.mkdtemp(prefix="shadowbench-test-"))
    path.chmod(0o711)
    if any(not os.stat(p).st_mode & stat.S_IXOTH for p in path.parents):
        shutil.rmtree(path)
        pytest.skip(f"uid 65534 cannot traverse {path.parent}")
    try:
        yield path
    finally:
        _kill_leftovers(path)
        shutil.rmtree(path, ignore_errors=True)


def _dirs(scratch: Path) -> tuple[Path, Path]:
    run_dir = scratch / "run"
    run_dir.mkdir(mode=0o711)
    run_dir.chmod(0o711)
    work, control = run_dir / "work", run_dir / "control"
    work.mkdir(mode=0o700)
    control.mkdir(mode=0o700)
    os.chown(work, 65534, 65534)
    return work, control


def _inv(work: Path, script: str, timeout: int = 30) -> dict[str, Any]:
    env = {"PATH": TOOL_PATH, "HOME": str(work), "LANG": "C.UTF-8"}
    return {"argv": ["sh", "-c", script], "cwd": str(work), "env": env, "timeout": timeout, "stdin": None}


def _spec(work: Path, invocations: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
    base = {"services": [], "processes": [], "fakeproc": "/nonexistent", "work": str(work)}
    return {**base, "invocations": invocations, **extra}


HEARTBEAT = "setsid sh -c 'while :; do echo . >> beat; sleep 0.1; done' & exec sleep 600"
"""A tool whose detached grandchild keeps the pipes open and keeps writing ``beat``."""


def _assert_stopped(beat: Path) -> None:
    assert beat.stat().st_size > 0, "the heartbeat never started"
    time.sleep(0.3)  # let the kernel finish tearing the namespace down
    size = beat.stat().st_size
    time.sleep(0.6)
    assert beat.stat().st_size == size, "a tool process outlived the stage"


@needs_namespaces
def test_stage_runs_tools_as_nobody_with_operator_homes_hidden(scratch: Path) -> None:
    work, control = _dirs(scratch)
    script = (
        "id -u; id -G; ls -A /root | wc -l; ls -A /home | wc -l; grep NoNewPrivs /proc/self/status;"
        " touch made; stat -c %u made;"
        " if cat ../control/stage_spec.json >/dev/null 2>&1; then echo spec-readable; else echo spec-hidden; fi"
    )
    staged = runner._stage(_spec(work, [_inv(work, script)]), control, ROOT, 60)
    assert staged["error"] is None, staged
    lines = [line.strip() for line in staged["runs"][0]["stdout"].splitlines()]
    assert lines == ["65534", "65534", "0", "0", "NoNewPrivs:\t1", "65534", "spec-hidden"]
    assert (work / "made").exists()


@needs_namespaces
def test_stage_timeout_kills_a_setsid_grandchild_holding_the_pipes(scratch: Path) -> None:
    work, control = _dirs(scratch)
    later = "a=$(stat -c %s beat); sleep 1; b=$(stat -c %s beat); echo $a $b"
    started = time.monotonic()
    staged = runner._stage(
        _spec(work, [_inv(work, HEARTBEAT, timeout=1), _inv(work, later)]), control, ROOT, 60
    )
    assert staged["error"] is None, staged
    first, second = staged["runs"]
    assert (first["timed_out"], first["code"]) == (True, 124)
    before, after = second["stdout"].split()
    assert int(before) > 0 and before == after, "the grandchild survived into the next invocation"
    assert time.monotonic() - started < 30
    _assert_stopped(work / "beat")


@needs_namespaces
def test_stage_outer_timeout_takes_down_every_process_in_the_namespace(scratch: Path) -> None:
    work, control = _dirs(scratch)
    started = time.monotonic()
    staged = runner._stage(_spec(work, [_inv(work, HEARTBEAT, timeout=600)]), control, ROOT, 3)
    assert "timed out" in staged["error"]
    assert time.monotonic() - started < 20
    _assert_stopped(work / "beat")


@needs_namespaces
@pytest.mark.skipif(_coreutils_sleep() is None, reason="needs a standalone sleep binary")
def test_stage_inert_processes_are_visible_to_the_tool_under_their_names(scratch: Path) -> None:
    work, control = _dirs(scratch)
    sleep = _coreutils_sleep()
    assert sleep is not None
    script = (
        'for d in /proc/[0-9]*; do if [ "$(cat $d/comm 2>/dev/null)" = inert-agent ]; then'
        ' echo "${d#/proc/} $(stat -c %u $d) $(readlink $d/exe)"; tr "\\0" " " < $d/cmdline; echo; fi; done'
    )
    processes = [{"index": 7, "name": "inert-agent", "argv": ["inert-agent", "600"], "username": "op"}]
    spec = _spec(work, [_inv(work, script)], processes=processes, fakeproc=sleep)
    staged = runner._stage(spec, control, ROOT, 60)
    assert staged["error"] is None, staged
    (proc,) = staged["processes"]
    pid, uid, exe = staged["runs"][0]["stdout"].splitlines()[0].split()
    assert (int(pid), int(uid)) == (proc["pid"], 65534)
    assert exe == str(work / "procbin" / "inert-agent")
    assert staged["runs"][0]["stdout"].splitlines()[1].strip() == "inert-agent 600"


@needs_namespaces
def test_run_one_reads_tool_output_only_after_removing_planted_links(scratch: Path) -> None:
    seen: dict[str, Any] = {}

    def normalize(work: Path, runs: list[RunResult]) -> AdapterResult:
        seen["leak"] = os.path.lexists(work / "leak")
        seen["fifo"] = os.path.lexists(work / "pipe")
        uid = (work / "out.txt").read_text(encoding="utf-8").strip()
        return AdapterResult("ok", [Entity("app", f"app:{uid}", "agent")])

    script = "id -u > out.txt; ln -s /root/.bashrc leak; mkfifo pipe"
    row = _run_one(FakeAdapter(script=script, normalize=normalize), scratch)
    assert row["status"] == "ok", row
    assert row["entities"] == [{"kind": "app", "key": "app:65534", "label": "agent"}]
    assert seen == {"leak": False, "fifo": False}
    assert "2 unsafe" in row["note"]
    assert list(scratch.glob("fake-*")) == []
