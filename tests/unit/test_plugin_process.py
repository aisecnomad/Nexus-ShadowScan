"""Real spawned-plugin regressions: import, completion, forced exit and IPC boundaries."""

from __future__ import annotations

import json
import multiprocessing
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

import shadowscan
from shadowscan import engine as engine_module
from shadowscan.cli import main
from shadowscan.config import ConfigValidationError, ConnectorSpec, ScanConfig
from shadowscan.coverage import CoverageGap, CoverageLedger, CoveragePolicy
from shadowscan.engine import Engine
from shadowscan.models import DERIVED_METADATA_KEYS, ScanStats
from shadowscan.plugin_process import (
    _decode_result,
    _descriptor_limit,
    _encode_result,
    _keep_descriptors_from_programs,
    _receive,
    _worker,
    _WorkerHandle,
    is_credential_name,
    is_credential_variable,
    scrub_credential_environment,
)
from shadowscan.signatures import SignatureIndex

ENTRY = "platform.process-probe"
MODULE = "shadowscan_process_probe"

PLUGIN = """
import os
import signal
import time
from pathlib import Path
from shadowscan.connectors.base import BaseConnector
from shadowscan.models import Finding, Kind, Surface

mode = os.environ.get("SHADOWSCAN_PROCESS_PROBE", "ok")
Path(os.environ["SHADOWSCAN_PROCESS_PID"]).write_text(str(os.getpid()))

def hang():
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    while True:
        time.sleep(1)

if mode == "import-hang":
    hang()
if mode == "oversized":
    import shadowscan.plugin_process as transport
    transport._encode_result = lambda data: b"x" * (transport.MAX_RESULT_BYTES + 1)
if mode == "malformed":
    import shadowscan.plugin_process as transport
    transport._encode_result = lambda data: b'{"stats": "untrusted"}'

class Connector(BaseConnector):
    name = "platform.process-probe"
    surface = Surface.LOWCODE
    description = "spawned-process test connector"
    config_keys = {}

    def collect(self):
        if self.ctx.config.get("mode", mode) == "hang":
            hang()
        if mode == "crash":
            os._exit(7)
        if mode == "nondaemon-thread":
            # For example an SDK helper still waiting when collection returns.
            import threading
            threading.Thread(target=threading.Event().wait, daemon=False).start()
        if mode == "background-helper":
            # A helper program that keeps every inheritable descriptor open.
            import subprocess
            import sys
            helper = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], close_fds=False)
            Path(os.environ["SHADOWSCAN_PROCESS_PID"] + ".helper").write_text(str(helper.pid))
        if mode == "origin":
            from shadowscan.utils import http
            return [{
                "pid": os.getpid(),
                "policy": http._allow_private_origin.get(),
                "configured": self.ctx.config.get("allow_private_origin"),
            }]
        return [{"pid": os.getpid()}]

    def analyze(self, records):
        for record in records:
            metadata = {"pid": record["pid"]}
            if mode == "origin":
                metadata.update(policy=record["policy"], configured=record["configured"])
            if mode == "metadata-types":
                import datetime
                metadata.update(seen=datetime.datetime(2026, 1, 1), scopes={"read"}, raw=b"ab")
            if mode == "identity-env":
                metadata.update(
                    env_has_identity_key="SHADOWSCAN_IDENTITY_KEY" in os.environ,
                    ctx_has_identity_key=self.ctx.gateway_identity_key is not None,
                )
            if mode == "credential-env":
                metadata.update(
                    seen=sorted(
                        name for name in os.environ
                        if name.startswith("SHADOWSCAN_PROBE_") or name in ("PATH", "HOME")
                    ),
                )
            if mode == "initial-env":
                # The environment the worker was started with, which removing a variable from
                # os.environ does not change. Darwin has no /proc: the worker's current
                # environment stands in, which the start-up scrub has already cleaned, so the
                # strict started-with check is the /proc-gated test only.
                try:
                    with open("/proc/self/environ", "rb") as initial:
                        entries = initial.read().split(b"\\0")
                    names = [entry.partition(b"=")[0].decode() for entry in entries if entry]
                except FileNotFoundError:
                    names = list(os.environ)
                metadata.update(
                    initial=sorted(
                        name for name in names
                        if name.startswith("SHADOWSCAN_PROBE_")
                        or name in ("PATH", "HOME", "SHADOWSCAN_IDENTITY_KEY")
                    ),
                )
            # "forge" builds the finding under a built-in connector's name; "forge-id" gives a
            # finding under its own name that finding's id, and "forge-replace" re-labels a copy.
            shape = dict(
                surface=self.surface, kind=Kind.AGENT, title="process probe", resource="probe",
                resource_type="test", metadata=metadata,
            )
            if not mode.startswith("forge"):
                yield Finding(connector=self.name, **shape)
                continue
            claimed = Finding(connector="code.filesystem", **shape)
            if mode == "forge":
                yield claimed
            elif mode == "forge-id":
                yield Finding(connector=self.name, id=claimed.id, **shape)
            else:
                import dataclasses
                yield dataclasses.replace(claimed, connector=self.name)
"""


@pytest.fixture
def installed_probe(tmp_path, monkeypatch):
    (tmp_path / f"{MODULE}.py").write_text(PLUGIN, encoding="utf-8")
    distribution = tmp_path / "shadowscan_process_probe-1.0.dist-info"
    distribution.mkdir()
    (distribution / "METADATA").write_text("Name: shadowscan-process-probe\nVersion: 1.0\n")
    (distribution / "entry_points.txt").write_text(f"[shadowscan.connectors]\n{ENTRY} = {MODULE}:Connector\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    marker = tmp_path / "pid.txt"
    monkeypatch.setenv("SHADOWSCAN_PROCESS_PID", str(marker))
    monkeypatch.setenv("SHADOWSCAN_PROCESS_PROBE", "ok")
    return marker


# A spawned plugin re-imports the scanner and unpickles the signature index
# before it runs; on a loaded macOS runner that start-up alone can pass several
# seconds. The deadline leaves it room and the wall-clock bound scales with it.
TIMEOUT_SECONDS = 10


def _engine(**options):
    return Engine(
        ScanConfig(connectors=[ConnectorSpec(ENTRY)], plugins=[ENTRY], plugin_execution="process", **options),
        SignatureIndex([]),
    )


def _assert_reaped(marker):
    pid = int(marker.read_text())
    assert pid != os.getpid()
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def _plugin_pid(marker, limit=30.0):
    """Wait (bounded) until the plugin has been imported in its worker."""
    end = time.monotonic() + limit
    while time.monotonic() < end:
        try:
            return int(marker.read_text())
        except (OSError, ValueError):
            time.sleep(0.05)
    raise AssertionError("plugin worker did not start")


def _exited(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    try:
        # An orphan that init has not reaped yet is a zombie: it no longer runs.
        with open(f"/proc/{pid}/stat") as status:
            return status.read().rsplit(")", 1)[1].split()[0] == "Z"
    except OSError:
        return False


def _wait_exited(pid, limit):
    end = time.monotonic() + limit
    while not _exited(pid):
        if time.monotonic() >= end:
            return False
        time.sleep(0.05)
    return True


def _kill_leftover(pid):
    if not _exited(pid):
        os.kill(pid, signal.SIGKILL)


def test_spawned_plugin_result_and_export_without_parent_import(installed_probe, tmp_path):
    directory = tmp_path / "exports"
    engine = _engine(dump_records=str(directory))
    result = engine.run()
    assert result.complete, result.stats
    assert result.findings[0].metadata["pid"] != os.getpid()
    assert MODULE not in sys.modules
    assert engine.abandoned_workers == []
    _assert_reaped(installed_probe)
    manifest = json.loads((directory / "manifest.json").read_text())
    assert manifest["complete"] and manifest["exports"][0]["exported"]
    assert engine.run().complete


def test_worker_exports_only_into_the_prepared_private_directory(installed_probe, tmp_path, monkeypatch):
    """The child must not re-derive the export directory from raw configuration."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    # A literal "~" survives `--dump-records=~/exports` and embedding callers.
    # In this working directory "./~" is a symlink the parent never validated.
    work = tmp_path / "work"
    (work / "elsewhere" / "exports").mkdir(parents=True)
    (work / "~").symlink_to(work / "elsewhere", target_is_directory=True)
    monkeypatch.chdir(work)
    result = _engine(dump_records="~/exports").run()
    assert result.complete, result.stats
    directory = home / "exports"
    manifest = json.loads((directory / "manifest.json").read_text())
    [entry] = manifest["exports"]
    assert entry["exported"] and (directory / entry["filename"]).is_file()
    assert list((work / "elsewhere" / "exports").iterdir()) == []


@pytest.mark.parametrize("mode", ["hang", "import-hang"])
def test_timeout_kills_sigterm_ignoring_plugin_and_preserves_worker_capacity(
    installed_probe, monkeypatch, mode, tmp_path
):
    monkeypatch.setenv("SHADOWSCAN_PROCESS_PROBE", mode)
    directory = tmp_path / "exports"
    engine = _engine(connector_timeout_seconds=TIMEOUT_SECONDS, dump_records=str(directory), parallel=1)
    start = time.monotonic()
    result = engine.run()
    assert time.monotonic() - start < TIMEOUT_SECONDS * 3
    assert not result.complete and result.findings == []
    assert "connector_timeout" in result.stats[0].errors[0]
    assert engine.abandoned_workers == []
    assert MODULE not in sys.modules
    _assert_reaped(installed_probe)
    manifest = json.loads((directory / "manifest.json").read_text())
    assert not manifest["complete"]
    assert manifest["exports"] == [
        {
            "config_ordinal": 1,
            "part": "0001",
            "connector": ENTRY,
            "label": None,
            "filename": None,
            "complete": False,
            "exported": False,
        }
    ]
    # Unlike an abandoned thread, a terminated plugin permits safe reuse.
    monkeypatch.setenv("SHADOWSCAN_PROCESS_PROBE", "ok")
    assert engine.run().complete


def test_lingering_non_daemon_thread_cannot_hold_result_hostage(installed_probe, monkeypatch):
    monkeypatch.setenv("SHADOWSCAN_PROCESS_PROBE", "nondaemon-thread")
    start = time.monotonic()
    result = _engine(connector_timeout_seconds=8).run()
    assert result.complete, result.stats
    assert len(result.findings) == 1
    assert time.monotonic() - start < 8
    _assert_reaped(installed_probe)


def test_helper_program_started_by_the_plugin_cannot_hold_the_result(installed_probe, monkeypatch):
    monkeypatch.setenv("SHADOWSCAN_PROCESS_PROBE", "background-helper")
    start = time.monotonic()
    try:
        result = _engine(connector_timeout_seconds=TIMEOUT_SECONDS).run()
        assert result.complete, result.stats
        assert len(result.findings) == 1
        assert time.monotonic() - start < TIMEOUT_SECONDS
        _assert_reaped(installed_probe)
    finally:
        helper = Path(str(installed_probe) + ".helper")
        if helper.exists():
            _kill_leftover(int(helper.read_text()))


def test_very_large_connector_timeout_still_runs_process_plugins(installed_probe):
    # Waits of more than about 24.8 days overflow; they are taken in slices.
    result = _engine(connector_timeout_seconds=3e6).run()
    assert result.complete, result.stats
    assert len(result.findings) == 1
    _assert_reaped(installed_probe)


def test_terminated_plugin_releases_capacity_for_queued_sibling(installed_probe):
    engine = Engine(
        ScanConfig(
            connectors=[
                ConnectorSpec(ENTRY, {"mode": "hang"}, label="slow"),
                ConnectorSpec(ENTRY, {"mode": "ok"}, label="queued"),
            ],
            plugins=[ENTRY],
            plugin_execution="process",
            parallel=1,
            connector_timeout_seconds=TIMEOUT_SECONDS,
        ),
        SignatureIndex([]),
    )
    result = engine.run()
    assert not result.complete
    stats = {item.connector: item for item in result.stats}
    assert stats["slow"].incomplete and not stats["queued"].incomplete
    assert len(result.findings) == 1
    assert engine.abandoned_workers == []
    _assert_reaped(installed_probe)


@pytest.mark.parametrize("mode", ["crash", "oversized", "malformed"])
def test_child_crash_or_bad_wire_result_fails_closed(installed_probe, monkeypatch, mode):
    monkeypatch.setenv("SHADOWSCAN_PROCESS_PROBE", mode)
    result = _engine().run()
    assert not result.complete and result.findings == []
    assert result.stats[0].incomplete and result.stats[0].errors
    assert MODULE not in sys.modules
    _assert_reaped(installed_probe)


# Run as `python -c`: spawn then has no main module to re-import in the worker.
_DYING_SCANNER = """
import os, sys, threading, time
from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.engine import Engine
from shadowscan.signatures import SignatureIndex

marker, entry = sys.argv[1:]

def exit_without_cleanup():
    while True:
        try:
            int(open(marker).read())
            break
        except (OSError, ValueError):
            time.sleep(0.05)
    os._exit(0)  # like the job-deadline watchdog or SIGKILL: no finally/atexit

threading.Thread(target=exit_without_cleanup, daemon=True).start()
config = ScanConfig(
    connectors=[ConnectorSpec(entry)], plugins=[entry], plugin_execution="process",
    connector_timeout_seconds=120,
)
Engine(config, SignatureIndex([])).run()
"""


def test_worker_exits_when_scanner_process_dies(installed_probe, monkeypatch, tmp_path):
    monkeypatch.setenv("SHADOWSCAN_PROCESS_PROBE", "hang")
    checkout = Path(shadowscan.__file__).resolve().parents[1]
    environment = {**os.environ, "PYTHONPATH": os.pathsep.join([str(tmp_path), str(checkout)])}
    command = [sys.executable, "-c", _DYING_SCANNER, str(installed_probe), ENTRY]
    subprocess.run(command, env=environment, timeout=60, check=True)
    pid = _plugin_pid(installed_probe)
    try:
        # The connector deadline is 120 s: only parent-death detection can stop it.
        assert _wait_exited(pid, 10), "orphaned plugin worker kept running"
    finally:
        _kill_leftover(pid)


def test_interrupted_collection_kills_worker_promptly(installed_probe, monkeypatch):
    monkeypatch.setenv("SHADOWSCAN_PROCESS_PROBE", "hang")

    def interrupted(self):
        _plugin_pid(installed_probe)
        raise KeyboardInterrupt

    monkeypatch.setattr(engine_module._Supervisor, "run", interrupted)
    with pytest.raises(KeyboardInterrupt):
        _engine(connector_timeout_seconds=120).run()
    pid = _plugin_pid(installed_probe)
    try:
        assert _wait_exited(pid, 10), "interrupted scan left its plugin worker running"
    finally:
        _kill_leftover(pid)


def test_worker_enforces_its_own_deadline_without_parent_supervision(installed_probe, monkeypatch):
    monkeypatch.setenv("SHADOWSCAN_PROCESS_PROBE", "hang")
    parent, child = socket.socketpair()
    config = ScanConfig(connectors=[ConnectorSpec(ENTRY)], plugins=[ENTRY])
    # Leave time for spawn start-up and plugin import before the deadline.
    deadline = time.monotonic() + 4
    process = multiprocessing.get_context("spawn").Process(
        target=_worker, args=(child, config, [], 1, deadline, b"k" * 32, None), daemon=True
    )
    try:
        process.start()
        child.close()
        _plugin_pid(installed_probe)
        assert time.monotonic() < deadline, "worker started too late to reach the plugin"
        # The parent neither reads nor kills: the worker must stop by itself
        # shortly after its deadline (two seconds of cleanup grace, plus slack).
        process.join(deadline + 12 - time.monotonic())
        assert process.exitcode == 1
    finally:
        if process.is_alive():
            process.kill()
            process.join(5)
        parent.close()
        child.close()


def test_non_json_metadata_round_trips_like_thread_mode(installed_probe, monkeypatch):
    """Transport serialization matches the JSON report for datetime, set and bytes metadata."""
    from shadowscan import connectors as registry

    monkeypatch.setenv("SHADOWSCAN_PROCESS_PROBE", "metadata-types")
    reported = {}
    try:
        for backend in ("thread", "process"):
            config = ScanConfig(connectors=[ConnectorSpec(ENTRY)], plugins=[ENTRY], plugin_execution=backend)
            result = Engine(config, SignatureIndex([])).run()
            assert result.complete, (backend, result.stats)
            [finding] = json.loads(result.to_json())["findings"]
            finding["metadata"].pop("pid")
            reported[backend] = finding["metadata"]
    finally:
        # The thread backend imported the probe here; keep later tests honest.
        sys.modules.pop(MODULE, None)
        registry._cache.pop(ENTRY, None)
    assert reported["process"] == reported["thread"]
    # The engine derives the autonomy block after collection, for either backend alike.
    assert reported["thread"].pop("autonomy")["schema"] == "shadowscan.autonomy/v1"
    # Threat and control references are derived from the finding at export,
    # not carried by the plugin (tests/unit/test_mappings.py covers them).
    connector_metadata = {k: v for k, v in reported["thread"].items() if k not in DERIVED_METADATA_KEYS}
    # The report renders a datetime as text and reads a set as a list and
    # bytes as text; the transport must not change that rendering.
    assert connector_metadata == {"seen": "2026-01-01 00:00:00", "scopes": ["read"], "raw": "ab"}


@pytest.mark.parametrize("deny", [True, False])
def test_spawned_plugin_sees_the_scan_wide_private_origin_refusal(installed_probe, monkeypatch, deny):
    """--deny-private-origin reaches the worker's transport policy and the plugin's own ctx.config."""
    monkeypatch.setenv("SHADOWSCAN_PROCESS_PROBE", "origin")
    config = ScanConfig(
        connectors=[ConnectorSpec(ENTRY, {"allow_private_origin": True})],
        plugins=[ENTRY],
        plugin_execution="process",
        deny_private_origin=deny,
    )
    result = Engine(config, SignatureIndex([])).run()
    assert result.complete, result.stats
    [finding] = result.findings
    assert finding.metadata["pid"] != os.getpid()
    assert finding.metadata["policy"] is (not deny)
    assert finding.metadata["configured"] is (not deny)
    assert MODULE not in sys.modules
    _assert_reaped(installed_probe)


def test_plugin_allowlist_still_required_without_parent_import(installed_probe):
    engine = Engine(
        ScanConfig(connectors=[ConnectorSpec(ENTRY)], plugin_execution="process"), SignatureIndex([])
    )
    result = engine.run()
    assert not result.complete and result.findings == []
    assert not installed_probe.exists()
    assert MODULE not in sys.modules


def test_process_resource_failure_is_incomplete(installed_probe, monkeypatch):
    import shadowscan.plugin_process as transport

    def exhausted():
        raise OSError("sensitive resource diagnostic")

    monkeypatch.setattr(transport.socket, "socketpair", exhausted)
    result = _engine().run()
    assert not result.complete and result.findings == []
    assert "setup or supervision failed" in result.stats[0].errors[0]
    assert "sensitive" not in str(result.stats)


def test_partial_ipc_is_deadline_bounded():
    parent, child = socket.socketpair()
    try:
        child.sendall((100).to_bytes(8, "big") + b'{"partial":')
        with pytest.raises(TimeoutError):
            _receive(parent, time.monotonic() + 0.05)
    finally:
        parent.close()
        child.close()


def test_declared_length_ends_the_result_while_the_channel_stays_open():
    parent, child = socket.socketpair()
    try:
        payload = b'{"findings":[]}'
        child.sendall(len(payload).to_bytes(8, "big") + payload)
        start = time.monotonic()
        assert _receive(parent, time.monotonic() + 5) == payload
        assert time.monotonic() - start < 1
    finally:
        parent.close()
        child.close()


@pytest.mark.parametrize("declared,sent", [(100, b'{"truncated":'), (17 * 1024 * 1024, b"")])
def test_truncated_or_oversized_declared_result_fails_closed(declared, sent):
    parent, child = socket.socketpair()
    try:
        child.sendall(declared.to_bytes(8, "big") + sent)
        child.close()
        with pytest.raises(ValueError):
            _receive(parent, time.monotonic() + 5)
    finally:
        parent.close()


class _ClosingProcess:
    """Mimics Process.close(): the handle is cleared before the object is marked closed."""

    pid = 4242

    def __init__(self):
        self._popen = SimpleNamespace(poll=lambda: 0)
        self._closed = False
        self.closing = threading.Event()

    def is_alive(self):
        if self._closed:
            raise ValueError("process object is closed")
        return self._popen.poll() is None

    def close(self):
        self._popen = None
        self.closing.set()
        time.sleep(0.2)
        self._closed = True


def test_kill_during_worker_cleanup_waits_instead_of_failing_the_scan():
    process = _ClosingProcess()
    handle = _WorkerHandle(process)
    failures = []

    def kill_when_closing():
        process.closing.wait(5)
        try:
            handle.kill()
        except Exception as exc:  # noqa: BLE001 - recorded for the assertion below
            failures.append(exc)

    killer = threading.Thread(target=kill_when_closing)
    killer.start()
    handle.stop()
    killer.join(5)
    assert not killer.is_alive() and failures == []


def test_descriptor_listing_failure_covers_high_descriptors(monkeypatch):
    resource = pytest.importorskip("resource")
    visited = {}
    listings = []

    def unavailable(path):
        listings.append(path)
        raise OSError("descriptor listing unavailable")

    monkeypatch.setattr(os, "listdir", unavailable)
    monkeypatch.setattr(resource, "getrlimit", lambda kind: (5002, 6000))
    monkeypatch.setattr(os, "set_inheritable", lambda fd, inheritable: visited.update({fd: inheritable}))
    _keep_descriptors_from_programs()
    assert listings == ["/proc/self/fd", "/dev/fd"]
    assert visited[5001] is False
    assert min(visited) == 3 and max(visited) == 5001
    assert not any(visited.values())


@pytest.mark.parametrize("soft", [1 << 22, "infinity"])
def test_descriptor_resource_limit_is_capped(monkeypatch, soft):
    resource = pytest.importorskip("resource")
    # RLIM_INFINITY is -1 on Linux and 2**63 - 1 on macOS: use the platform's own value.
    limit = resource.RLIM_INFINITY if soft == "infinity" else soft
    monkeypatch.setattr(resource, "getrlimit", lambda kind: (limit, resource.RLIM_INFINITY))
    assert _descriptor_limit() == 1 << 20


def test_descriptor_limit_without_resource_uses_sysconf(monkeypatch):
    monkeypatch.setitem(sys.modules, "resource", None)
    names = []

    def limit(name):
        names.append(name)
        return 8192

    monkeypatch.setattr(os, "sysconf", limit, raising=False)
    assert _descriptor_limit() == 8192
    assert names == ["SC_OPEN_MAX"]


def test_descriptor_resource_failure_uses_sysconf(monkeypatch):
    resource = pytest.importorskip("resource")

    def unavailable(kind):
        raise OSError("resource limit unavailable")

    monkeypatch.setattr(resource, "getrlimit", unavailable)
    monkeypatch.setattr(os, "sysconf", lambda name: 9000, raising=False)
    assert _descriptor_limit() == 9000


@pytest.mark.parametrize("limit", [-1, 1 << 22])
def test_descriptor_sysconf_limit_is_capped_or_unknown(monkeypatch, limit):
    monkeypatch.setitem(sys.modules, "resource", None)
    monkeypatch.setattr(os, "sysconf", lambda name: limit, raising=False)
    assert _descriptor_limit() == 1 << 20


def test_descriptor_limit_without_platform_limits_uses_cap(monkeypatch):
    monkeypatch.setitem(sys.modules, "resource", None)
    monkeypatch.delattr(os, "sysconf", raising=False)
    assert _descriptor_limit() == 1 << 20


def test_result_encoder_enforces_limit(monkeypatch):
    import shadowscan.plugin_process as transport

    monkeypatch.setattr(transport, "MAX_RESULT_BYTES", 16)
    with pytest.raises(ValueError, match="transport limit"):
        _encode_result({"result": "x" * 20})


def test_result_encoder_still_rejects_nan():
    with pytest.raises(ValueError):
        _encode_result({"findings": [{"confidence": float("nan")}]})


@pytest.mark.parametrize(
    "field,value",
    [
        ("incomplete", "false"),
        ("findings", True),
        ("objects_examined", -1),
        ("errors", [42]),
        ("warnings", "ok"),
        ("started_at", []),
        ("skip_reason", {}),
        ("name", ["code.filesystem"]),
        ("declared_paths", "tests/a.json"),
        ("declared_paths", [3]),
        # The coverage ledger (#254) is checked like every other statistic.
        ("coverage", "within budget"),
        ("coverage", []),
        ("coverage", {"within_budget": True}),
    ],
)
def test_result_stats_schema_is_not_trusted(field, value):
    stats = asdict(ScanStats(ENTRY, "now"))
    stats[field] = value
    payload = json.dumps({"stats": stats, "findings": [], "exports": []}).encode()
    with pytest.raises(ValueError):
        _decode_result(payload, 1, ConnectorSpec(ENTRY))


def test_result_stats_count_an_unknown_incomplete_reason_as_other():
    # The plugin process writes its own reason keys; the scanner prints them in the
    # table banner and the exit-3 line, so only the fixed categories pass.
    stats = {
        **asdict(ScanStats(ENTRY, "now")),
        "incomplete": True,
        "warnings": ["connector timed out"],
        "incomplete_reasons": {"\x1b]0;pwned\x07\x1b[2J": 2, "src/app.py": 1, "timeout": 1},
    }
    payload = json.dumps({"stats": stats, "findings": [], "exports": []}).encode()
    _, decoded, _ = _decode_result(payload, 1, ConnectorSpec(ENTRY))
    assert decoded.incomplete_reasons == {"other": 3, "timeout": 1}


def test_result_stats_keep_a_coverage_ledger_the_worker_computed():
    ledger = CoverageLedger()
    ledger.add_examined(40)
    ledger.record(CoverageGap(detail="code.filesystem: tests/a.bin: unreadable", path="tests/a.bin"))
    _, summary = ledger.evaluate(CoveragePolicy())
    stats = {**asdict(ScanStats(ENTRY, "now")), "coverage": summary}
    payload = json.dumps({"stats": stats, "findings": [], "exports": []}).encode()
    _, decoded, _ = _decode_result(payload, 1, ConnectorSpec(ENTRY))
    assert decoded.coverage == summary


@pytest.mark.parametrize("value", [None, True, 1, [], "fork", "Process", ""])
def test_execution_backend_configuration_rejects_invalid_values(value):
    with pytest.raises(ConfigValidationError, match="plugin_execution"):
        ScanConfig.from_dict({"options": {"plugin_execution": value}})


def test_execution_backend_defaults_and_mutation_validation():
    assert ScanConfig().plugin_execution == "process"
    config = ScanConfig.from_dict({"options": {"plugin_execution": "process"}})
    engine = Engine(config, SignatureIndex([]))
    config.plugin_execution = "fork"
    with pytest.raises(ConfigValidationError, match="plugin_execution"):
        engine.run()


def test_plugin_execution_cli_option():
    result = CliRunner().invoke(main, ["scan", "--help"])
    assert result.exit_code == 0 and "--plugin-execution" in result.output


@pytest.mark.parametrize("previous", [None, "keep"])
def test_process_plugin_spawn_leaves_the_scanner_environment_unchanged(
    installed_probe, monkeypatch, previous
):
    """Regression: PYTHONSAFEPATH was set in os.environ for the spawn and never restored, so every
    later child of the scanner (or of an embedding program) lost its script directory on sys.path."""
    # setenv then delenv: monkeypatch restores the original state even if the code leaks a value.
    monkeypatch.setenv("PYTHONSAFEPATH", "sentinel")
    if previous is None:
        monkeypatch.delenv("PYTHONSAFEPATH")
    else:
        monkeypatch.setenv("PYTHONSAFEPATH", previous)
    before = dict(os.environ)
    result = _engine().run()
    assert result.complete, result.stats
    assert dict(os.environ) == before
    assert os.environ.get("PYTHONSAFEPATH") == previous


def test_planted_module_in_the_working_directory_does_not_run_in_the_worker(
    installed_probe, monkeypatch, tmp_path
):
    """The spawned worker runs ``python -c``; the scan's working directory (possibly the scanned
    checkout) must not be on its sys.path when it first imports multiprocessing."""
    work = tmp_path / "checkout"
    (work / "multiprocessing").mkdir(parents=True)
    marker = tmp_path / "planted-ran"
    (work / "multiprocessing" / "__init__.py").write_text(f"open({str(marker)!r}, 'w').close()\n")
    monkeypatch.chdir(work)
    result = _engine().run()
    assert result.complete, result.stats
    assert not marker.exists()


@pytest.mark.parametrize("mode", ["forge", "forge-id", "forge-replace"])
def test_process_plugin_finding_built_under_a_builtin_name_gets_the_plugin_id(
    installed_probe, monkeypatch, mode
):
    """A finding a plugin builds under a built-in connector's name, or gives that finding's id
    (``id=``, ``dataclasses.replace``), is attributed to the plugin with the id the plugin's name
    gives, never the built-in finding's id (as in thread mode)."""
    from shadowscan.models import Finding, Kind

    monkeypatch.setenv("SHADOWSCAN_PROCESS_PROBE", mode)
    result = _engine().run()
    assert result.complete, result.stats
    [finding] = result.findings
    shape = {"kind": Kind.AGENT, "title": "t", "resource": "probe", "resource_type": "test"}
    # The id the claimed name gives, which the finding kept before it was recomputed.
    claimed = Finding(
        surface=finding.surface, connector="code.filesystem", provider=finding.provider, **shape
    )
    plugin = Finding(surface=finding.surface, connector=ENTRY, provider=finding.provider, **shape)
    assert finding.connector == ENTRY
    assert finding.id == plugin.id != claimed.id


def test_a_decoded_plugin_finding_never_keeps_the_id_it_carries():
    """The worker's engine derives each plugin finding's id, but the parent reads what the plugin
    process wrote: a payload carrying a built-in finding's id under the plugin's name gets the id
    the plugin's name derives."""
    from shadowscan.models import Finding, Kind, Surface

    shape = {
        "surface": Surface.CODE,
        "kind": Kind.AGENT,
        "title": "t",
        "resource": "r",
        "resource_type": "repo",
    }
    builtin = Finding(connector="code.filesystem", **shape)
    forged = {**Finding(connector=ENTRY, **shape).to_dict(), "id": builtin.id}
    stats = {**asdict(ScanStats(ENTRY, "now")), "findings": 1}
    payload = json.dumps({"stats": stats, "findings": [forged], "exports": []}).encode()
    [finding], _, _ = _decode_result(payload, 1, ConnectorSpec(ENTRY))
    assert finding.connector == ENTRY
    assert finding.id == Finding(connector=ENTRY, **shape).id != builtin.id


def test_spawned_plugin_does_not_inherit_credential_environment(installed_probe, monkeypatch):
    """A process-mode worker inherited the whole environment, so an approved plugin could read the
    GITHUB_TOKEN, cloud credentials and every other secret exported for the built-in connectors."""
    monkeypatch.setenv("SHADOWSCAN_PROBE_GITHUB_TOKEN", "synthetic")
    monkeypatch.setenv("SHADOWSCAN_PROBE_AWS_SECRET_ACCESS_KEY", "synthetic")
    monkeypatch.setenv("SHADOWSCAN_PROBE_OPENAI_API_KEY", "synthetic")
    monkeypatch.setenv("SHADOWSCAN_PROBE_DB_PASSWORD", "synthetic")
    monkeypatch.setenv("SHADOWSCAN_PROBE_AZURE_DEVOPS_EXT_PAT", "synthetic")
    monkeypatch.setenv("SHADOWSCAN_PROBE_REDIS_URL", "redis://:synthetic@cache:6379/0")
    monkeypatch.setenv("SHADOWSCAN_PROBE_SERVER_URL", "https://api.example")  # no password: stays
    monkeypatch.setenv("SHADOWSCAN_PROBE_VENDOR_TOKEN", "synthetic")  # the plugin's own, allowlisted
    monkeypatch.setenv("SHADOWSCAN_PROBE_REGION", "eu-west-1")  # not credential-shaped: stays
    monkeypatch.setenv("SHADOWSCAN_PROCESS_PROBE", "credential-env")
    result = _engine(plugin_env=["SHADOWSCAN_PROBE_VENDOR_TOKEN"]).run()
    assert result.complete, result.stats
    assert result.findings[0].metadata["seen"] == [
        "HOME",
        "PATH",
        "SHADOWSCAN_PROBE_REGION",
        "SHADOWSCAN_PROBE_SERVER_URL",
        "SHADOWSCAN_PROBE_VENDOR_TOKEN",
    ]
    # The scanner's own environment is untouched.
    assert os.environ["SHADOWSCAN_PROBE_GITHUB_TOKEN"] == "synthetic"
    _assert_reaped(installed_probe)


@pytest.mark.skipif(not os.path.exists("/proc/self/environ"), reason="reads /proc/<pid>/environ")
def test_spawned_plugin_initial_environment_holds_no_withheld_variable(installed_probe, monkeypatch):
    """Regression: the worker removed the credentials from os.environ, but spawn had already
    started it with the scanner's whole environment, so a plugin still read every withheld value
    from /proc/self/environ, which removing a variable does not change. The identity key is
    withheld even when ``plugin_env`` names it."""
    monkeypatch.setenv("SHADOWSCAN_PROBE_GITHUB_TOKEN", "synthetic")
    monkeypatch.setenv("SHADOWSCAN_PROBE_DB_PASSWORD", "synthetic")
    monkeypatch.setenv("SHADOWSCAN_PROBE_VENDOR_TOKEN", "synthetic")  # the plugin's own, allowlisted
    monkeypatch.setenv("SHADOWSCAN_PROBE_REGION", "eu-west-1")  # not credential-shaped: stays
    monkeypatch.setenv("SHADOWSCAN_IDENTITY_KEY", "hex:" + bytes(range(32)).hex())
    monkeypatch.setenv("SHADOWSCAN_PROCESS_PROBE", "initial-env")
    before = dict(os.environ)
    result = _engine(plugin_env=["SHADOWSCAN_PROBE_VENDOR_TOKEN", "SHADOWSCAN_IDENTITY_KEY"]).run()
    assert result.complete, result.stats
    assert result.findings[0].metadata["initial"] == [
        "HOME",
        "PATH",
        "SHADOWSCAN_PROBE_REGION",
        "SHADOWSCAN_PROBE_VENDOR_TOKEN",
    ]
    _assert_reaped(installed_probe)
    # The scanner's environment, and the one its later programs inherit, are unchanged.
    assert dict(os.environ) == before
    later = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            "import os; print(' '.join(sorted(n for n in os.environ if n.startswith('SHADOWSCAN_P'))))",
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    assert later.stdout.split() == sorted(name for name in before if name.startswith("SHADOWSCAN_P"))


def test_program_another_thread_starts_during_a_plugin_spawn_keeps_its_environment(
    installed_probe, monkeypatch
):
    """Regression: the spawn took the withheld variables out of the whole process's environment
    (``os.unsetenv``) and set PYTHONSAFEPATH for as long as ``Process.start()`` ran. A program a
    built-in connector's thread started meanwhile with the inherited environment (botocore's
    ``credential_process``, a thread-mode plugin's helper) started without the credentials it
    needed, and with PYTHONSAFEPATH set. The concurrent launch runs while the spawn pickles the
    worker, inside ``Process.start()``."""
    import multiprocessing.reduction
    from multiprocessing.process import BaseProcess

    monkeypatch.setenv("SHADOWSCAN_PROBE_GITHUB_TOKEN", "synthetic")
    monkeypatch.setenv("SHADOWSCAN_IDENTITY_KEY", "hex:" + bytes(range(32)).hex())
    monkeypatch.setenv("PYTHONSAFEPATH", "sentinel")
    monkeypatch.delenv("PYTHONSAFEPATH")
    monkeypatch.setenv("SHADOWSCAN_PROCESS_PROBE", "initial-env")
    script = 'printf %s "${SHADOWSCAN_PROBE_GITHUB_TOKEN-unset} ${SHADOWSCAN_IDENTITY_KEY:+key} ${PYTHONSAFEPATH-unset}"'
    seen: list[str] = []
    original = multiprocessing.reduction.dump

    def launch() -> None:
        # Inherits the process environment (env=None), as subprocess users on other threads do.
        seen.append(subprocess.run(["sh", "-c", script], capture_output=True, text=True, timeout=60).stdout)

    def dump(obj, file, protocol=None):
        if isinstance(obj, BaseProcess):
            other = threading.Thread(target=launch)
            other.start()
            other.join(60)
        return original(obj, file, protocol)

    monkeypatch.setattr(multiprocessing.reduction, "dump", dump)
    result = _engine().run()
    assert result.complete, result.stats
    assert seen == ["synthetic key unset"]
    # The worker itself still starts without them.
    assert result.findings[0].metadata["initial"] == ["HOME", "PATH"]
    _assert_reaped(installed_probe)


@pytest.mark.parametrize(
    "value",
    ["GITHUB_TOKEN", ["GITHUB_TOKEN", "GITHUB_TOKEN"], ["not a name"], ["X=1"], [1], ["A" * 129]],
)
def test_plugin_env_option_is_validated(value):
    with pytest.raises(ConfigValidationError, match="plugin_env"):
        ScanConfig(connectors=[ConnectorSpec(ENTRY)], plugins=[ENTRY], plugin_env=value)


@pytest.mark.parametrize(
    ("name", "withheld"),
    [
        ("GITHUB_TOKEN", True),
        ("token", True),
        ("AWS_SECRET_ACCESS_KEY", True),
        ("AWS_ACCESS_KEY_ID", True),
        ("GOOGLE_APPLICATION_CREDENTIALS", True),
        ("AZURE_CLIENT_SECRET", True),
        ("OCI_CLI_PASSPHRASE", True),
        ("DOCKER_PASSWD", True),
        ("DATABASE_URL", True),
        ("SHADOWSCAN_IDENTITY_KEY", True),
        # CI and cloud credentials the first list missed (#258 review).
        ("SYSTEM_ACCESSTOKEN", True),  # Azure Pipelines job token
        ("AZURE_DEVOPS_EXT_PAT", True),
        ("GITHUB_PAT", True),
        ("SENDGRID_APIKEY", True),
        ("AZURE_STORAGE_CONNECTION_STRING", True),
        ("APPLICATIONINSIGHTS_CONNECTION_STRING", True),
        ("CI_JOB_JWT", True),
        ("CI_JOB_JWT_V2", True),
        ("IDENTITY_HEADER", True),  # Azure managed-identity endpoint secret
        ("CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE", True),
        ("CLOUDSDK_AUTH_ACCESS_TOKEN_FILE", True),
        ("GOOGLE_GHA_CREDS_PATH", True),
        ("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", True),
        ("BW_SESSION", True),
        ("OP_SESSION_my", True),
        # Tooling credentials the second list missed (#258 review): the credential word is a
        # prefix, has no underscore before it, or the name says nothing about a credential.
        ("TF_TOKEN_app_terraform_io", True),  # Terraform's TF_TOKEN_<host>
        ("npm_config__authToken", True),
        ("NPM_CONFIG__AUTH", True),
        ("npm_config_//registry.example/:_authToken", True),  # npm's per-registry token
        ("NGROK_AUTHTOKEN", True),
        ("DOCKER_AUTH_CONFIG", True),  # GitLab's registry credentials
        ("COMPOSER_AUTH", True),
        ("BUNDLE_GITHUB__COM", True),  # Bundler's credentials for github.com
        ("BUNDLE_GEMS__CONTRIBSYS__COM", True),
        ("CUSTOMCONNSTR_db", True),  # Azure App Service connection strings
        ("SQLAZURECONNSTR_db", True),
        ("SQLCONNSTR_db", True),
        ("MYSQLCONNSTR_db", True),
        ("POSTGRESQLCONNSTR_db", True),
        ("SERVICEBUSCONNSTR_bus", True),
        ("ConnectionStrings__Default", True),  # .NET configuration
        ("SLACK_WEBHOOK_URL", True),  # the secret is in the URL path
        ("SLACK_WEBHOOK_URL_V2", True),
        ("DISCORD_WEBHOOK", True),
        ("WEBHOOK_URL", True),
        ("PATH", False),
        ("HOME", False),
        ("LANG", False),
        ("LC_ALL", False),
        ("HTTPS_PROXY", False),
        ("SSL_CERT_FILE", False),
        ("KUBECONFIG", False),
        ("AWS_PROFILE", False),
        ("AWS_REGION", False),
        ("AWS_ROLE_SESSION_NAME", False),
        ("IDENTITY_ENDPOINT", False),
        ("DESKTOP_SESSION", False),
        ("XDG_SESSION_TYPE", False),
        ("GIT_CONFIG_KEY_0", False),  # names a Git setting; GIT_CONFIG_COUNT needs it
        ("CLASSPATH", False),
        ("LD_LIBRARY_PATH", False),
        ("GITHUB_SERVER_URL", False),
        ("MAX_TOKENS", False),
        ("TURKEY", False),
        ("PYTHONHASHSEED", False),
        # Neighbours of the tooling credentials, which programs in a plugin need.
        ("TF_LOG", False),
        ("TF_CLI_ARGS", False),
        ("TF_TOKENS_DIR", False),
        ("NPM_CONFIG_REGISTRY", False),
        ("npm_config_cache", False),
        ("NPM_CONFIG_USERCONFIG", False),
        ("NGROK_REGION", False),
        ("DOCKER_CONFIG", False),
        ("DOCKER_HOST", False),
        ("COMPOSER_HOME", False),
        ("COMPOSER_AUTHOR", False),
        ("BUNDLE_GEMFILE", False),
        ("BUNDLE_PATH", False),
        ("BUNDLE_WITHOUT", False),
        ("CONNSTR", False),
        ("MY_CONNECTION_STRINGS_DIR", False),
        ("WEBHOOK_EVENTS", False),
        ("XDG_CONFIG_HOME", False),
        ("TMPDIR", False),
        ("SHELL", False),
    ],
)
def test_credential_environment_names(name, withheld):
    assert is_credential_name(name) is withheld
    environ = {name: "x", "PATH": "/usr/bin"}
    removed = scrub_credential_environment(environ)
    assert (name in removed) is withheld and "PATH" in environ
    assert scrub_credential_environment({name: "x"}, keep=[name]) == []


@pytest.mark.parametrize(
    ("name", "value", "withheld"),
    [
        # The values carry no user and password pair, which tools/check_secrets.py reports;
        # any user information is withheld.
        ("REDIS_URL", "redis://:synthetic@cache:6379/0", True),
        ("MONGODB_URI", "mongodb+srv://synthetic@cluster.example/db", True),
        ("SQLALCHEMY_DATABASE_URI", "postgresql://user:syn/thetic@db.example/app", True),  # unescaped /
        ("SENTRY_DSN", "https://synthetic@o0.ingest.example/1", True),
        ("CI_REPOSITORY_URL", "https://synthetic@gitlab.example/group/project.git", True),
        ("PIP_INDEX_URL", "https://synthetic@pypi.example/simple", True),
        ("url", "amqp://:synthetic@queue.example", True),
        ("REDIS_URL", "redis://cache:6379/0", False),
        ("GITHUB_SERVER_URL", "https://github.com", False),
        ("CI_API_V4_URL", "https://gitlab.example/api/v4", False),
        ("SSH_REMOTE_URL", "git@github.com:org/repo.git", False),  # not scheme://, a user name only
        ("HTTPS_PROXY", "http://synthetic@proxy.example:3128", False),  # proxy settings stay
        ("CONTACT", "https://synthetic@host.example", False),  # not a URL name
    ],
)
def test_credential_environment_url_values(name, value, withheld):
    """A connection URL carries its password or token as user information, under a name
    (``REDIS_URL``, ``MONGODB_URI``) that says nothing about a credential."""
    assert is_credential_variable(name, value) is withheld
    environ = {name: value, "PATH": "/usr/bin"}
    assert (name in scrub_credential_environment(environ)) is withheld and "PATH" in environ
    assert scrub_credential_environment({name: value}, keep=[name]) == []


def test_spawned_plugin_scrubs_identity_key_from_worker_environment(installed_probe, monkeypatch):
    """Regression: the spawned worker inherited SHADOWSCAN_IDENTITY_KEY in os.environ, so a plugin
    that does not declare uses_run_identity_key (or any child it starts) could read the raw key."""
    monkeypatch.setenv("SHADOWSCAN_IDENTITY_KEY", "hex:" + bytes(range(32)).hex())
    monkeypatch.setenv("SHADOWSCAN_PROCESS_PROBE", "identity-env")
    result = _engine().run()
    assert result.complete, result.stats
    assert result.findings[0].metadata["env_has_identity_key"] is False
    assert result.findings[0].metadata["ctx_has_identity_key"] is False
    _assert_reaped(installed_probe)


def _worker_ledger(gaps: int) -> dict:
    ledger = CoverageLedger()
    ledger.add_examined(40)
    for number in range(gaps):
        ledger.record(
            CoverageGap(detail=f"code.filesystem: tests/{number}.bin: unreadable", path=f"tests/{number}.bin")
        )
    return ledger.evaluate(CoveragePolicy())[1]


def test_result_stats_refuse_a_ledger_within_budget_that_lost_more_than_it_was_allowed():
    summary = {**_worker_ledger(1), "weighted_gap_entries": 9.0}
    stats = {**asdict(ScanStats(ENTRY, "now")), "coverage": summary}
    payload = json.dumps({"stats": stats, "findings": [], "exports": []}).encode()
    with pytest.raises(ValueError):
        _decode_result(payload, 1, ConnectorSpec(ENTRY))


def test_result_stats_over_budget_are_incomplete_whatever_the_worker_says():
    summary = _worker_ledger(10)
    assert summary["within_budget"] is False
    stats = {**asdict(ScanStats(ENTRY, "now")), "coverage": summary, "incomplete": False}
    payload = json.dumps({"stats": stats, "findings": [], "exports": []}).encode()
    _, decoded, _ = _decode_result(payload, 1, ConnectorSpec(ENTRY))
    assert decoded.incomplete


def test_result_stats_accept_a_combined_ledger_and_check_its_part_counts():
    from shadowscan.coverage import combine_coverage_summaries

    combined = combine_coverage_summaries([_worker_ledger(1), _worker_ledger(10)])
    assert combined is not None and (combined["parts"], combined["parts_over_budget"]) == (2, 1)
    stats = {**asdict(ScanStats(ENTRY, "now")), "coverage": combined, "incomplete": False}
    payload = json.dumps({"stats": stats, "findings": [], "exports": []}).encode()
    _, decoded, _ = _decode_result(payload, 1, ConnectorSpec(ENTRY))
    assert decoded.incomplete and decoded.coverage["tolerated_gap_entries"] == 1
    forged = {**stats, "coverage": {**combined, "tolerated_gap_entries": 11}}
    payload = json.dumps({"stats": forged, "findings": [], "exports": []}).encode()
    with pytest.raises(ValueError):
        _decode_result(payload, 1, ConnectorSpec(ENTRY))
