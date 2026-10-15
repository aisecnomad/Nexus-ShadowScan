"""Real spawned-plugin regressions: import, completion, forced exit and IPC boundaries."""

from __future__ import annotations

import base64
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
from shadowscan.engine import Engine
from shadowscan.models import DERIVED_METADATA_KEYS, ScanStats
from shadowscan.plugin_process import (
    _decode_result,
    _descriptor_limit,
    _encode_result,
    _keep_descriptors_from_programs,
    _receive,
    _rekey_result,
    _rewrite_identity_values,
    _worker,
    _WorkerHandle,
)
from shadowscan.signatures import SignatureIndex
from shadowscan.utils.crypto import (
    capture_identity_material,
    hkdf_sha256,
    identity_hmac_digest,
    plugin_identity_key,
)

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
    uses_run_identity_key = True

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
        return [{"pid": os.getpid()}]

    def analyze(self, records):
        for record in records:
            metadata = {"pid": record["pid"]}
            if mode == "metadata-types":
                import datetime
                metadata.update(seen=datetime.datetime(2026, 1, 1), scopes={"read"}, raw=b"ab")
            if mode == "identity-key":
                from shadowscan.comparison import IDENTITY_KEY_ENV
                from shadowscan.utils.credential_identity import keyed_credential_digest
                metadata.update(
                    key_marker=keyed_credential_digest("plugin-key-probe"),
                    inherited_key=IDENTITY_KEY_ENV in os.environ,
                )
            resource = self.ctx.config.get("resource", "probe")
            if mode in ("credential-resource", "mixed-resource"):
                from shadowscan.utils.redaction import credential_id
                resource = credential_id("plugin-identity-probe")
                if mode == "mixed-resource":
                    resource += "?pass" + "word" + "=" + "probe-value"
            if mode == "gateway-resource":
                from shadowscan.connectors.gateway.logs import _restore_scope
                resource = _restore_scope(
                    {"tenant": "plugin-identity-probe"}, [("[REDACTED]",)],
                    self.ctx.gateway_identity_key,
                )[0]["tenant"]
            finding = Finding(
                surface=self.surface, connector=self.name, kind=Kind.AGENT,
                title="process probe", resource=resource, resource_type="test",
                metadata=metadata,
            )
            if mode in ("credential-resource", "gateway-resource", "mixed-resource"):
                from shadowscan.utils.crypto import identity_hmac_digest
                finding.metadata.update(
                    identity=finding.resource, own_id=finding.id,
                    nested_digest=identity_hmac_digest(
                        self.ctx.gateway_identity_key, finding.id.encode()
                    ).hex(),
                )
                yield finding
                yield Finding(
                    surface=self.surface, connector=self.name, kind=Kind.AGENT,
                    title="linked probe", resource="peer", resource_type="test",
                    metadata={"linked_id": finding.id, "identity": finding.resource},
                )
            else:
                yield finding
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


def test_hkdf_sha256_rfc5869_case_one():
    assert hkdf_sha256(
        b"\x0b" * 22,
        salt=bytes(range(13)),
        info=bytes(range(0xF0, 0xFA)),
        length=42,
    ).hex() == ("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")


def test_hkdf_sha256_rfc5869_without_salt_or_info():
    assert hkdf_sha256(b"\x0b" * 22, info=b"", length=42).hex() == (
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
    )


@pytest.mark.parametrize("length", [0, -1, 255 * 32 + 1])
def test_hkdf_sha256_rejects_invalid_lengths(length):
    with pytest.raises(ValueError, match="invalid derived key length"):
        hkdf_sha256(bytes(range(32)), info=b"probe", length=length)


@pytest.mark.parametrize("ordinal", [0, -1])
def test_plugin_identity_rejects_invalid_ordinal(ordinal):
    with pytest.raises(ValueError, match="invalid plugin configuration ordinal"):
        plugin_identity_key(bytes(range(32)), ENTRY, ordinal)


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


@pytest.mark.parametrize("soft", [1 << 22, -1])
def test_descriptor_resource_limit_is_capped(monkeypatch, soft):
    resource = pytest.importorskip("resource")
    monkeypatch.setattr(resource, "getrlimit", lambda kind: (soft, resource.RLIM_INFINITY))
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


def test_plugin_keys_are_domain_separated_and_unambiguous():
    key = bytes(range(32))
    derived = plugin_identity_key(key, ENTRY, 1)
    assert len(derived) == 32 and derived != key
    assert derived == plugin_identity_key(key, ENTRY, 1)
    assert (
        len(
            {
                derived,
                plugin_identity_key(key, ENTRY, 2),
                plugin_identity_key(key, ENTRY + "2", 1),
                plugin_identity_key(key, ENTRY + "1", 2),
                plugin_identity_key(key, ENTRY, 12),
                plugin_identity_key(bytes(reversed(key)), ENTRY, 1),
            }
        )
        == 6
    )


def test_spawn_arguments_never_contain_the_run_identity_key(installed_probe, monkeypatch):
    import shadowscan.plugin_process as transport
    from shadowscan.comparison import IDENTITY_KEY_ENV

    key = bytes(range(32))
    monkeypatch.setenv(IDENTITY_KEY_ENV, "hex:" + key.hex())
    arguments = []

    def capture(**kwargs):
        arguments.append(kwargs["args"])
        raise OSError("process unavailable")

    monkeypatch.setattr(
        transport.multiprocessing, "get_context", lambda mode: SimpleNamespace(Process=capture)
    )
    result = _engine().run()
    assert not result.complete and not result.findings
    [args] = arguments
    assert args[5] == plugin_identity_key(key, ENTRY, 1) and key not in args
    assert MODULE not in sys.modules


def test_spawned_worker_uses_only_the_derived_key(installed_probe, monkeypatch):
    import hmac

    from shadowscan.comparison import IDENTITY_KEY_ENV

    key = bytes(range(32))
    monkeypatch.setenv(IDENTITY_KEY_ENV, "hex:" + key.hex())
    monkeypatch.setenv("SHADOWSCAN_PROCESS_PROBE", "identity-key")
    result = _engine().run()
    assert result.complete, result.stats
    [finding] = result.findings
    expected = hmac.digest(
        key,
        b"shadowscan.credential-identity.v1\0plugin-key-probe",
        "sha256",
    ).hex()
    assert finding.metadata["key_marker"] == expected
    assert finding.metadata["inherited_key"] is False
    assert os.environ[IDENTITY_KEY_ENV] == "hex:" + key.hex()


@pytest.mark.parametrize("mode", ["credential-resource", "gateway-resource", "mixed-resource"])
@pytest.mark.parametrize("stable", [False, True])
def test_keyed_resources_metadata_and_linked_ids_match_thread_mode(
    installed_probe, monkeypatch, tmp_path, mode, stable
):
    from shadowscan import connectors as registry
    from shadowscan.comparison import IDENTITY_KEY_ENV

    if stable:
        monkeypatch.setenv(IDENTITY_KEY_ENV, "hex:" + bytes(range(32)).hex())
    else:
        monkeypatch.delenv(IDENTITY_KEY_ENV, raising=False)
        # Compare two executions of the same synthetic run-key scope.
        monkeypatch.setattr(engine_module.secrets, "token_bytes", lambda size: bytes(range(size)))
    monkeypatch.setenv("SHADOWSCAN_PROCESS_PROBE", mode)
    reported = {}
    try:
        for backend in ("thread", "process"):
            directory = tmp_path / ("exports-" + backend)
            config = ScanConfig(
                connectors=[ConnectorSpec(ENTRY)],
                plugins=[ENTRY],
                plugin_execution=backend,
                dump_records=str(directory),
            )
            result = Engine(config, SignatureIndex([])).run()
            assert result.complete, result.stats
            findings = sorted(result.findings, key=lambda finding: finding.title)
            reported[backend] = [
                (
                    finding.id,
                    finding.compute_id(),
                    finding.resource,
                    {key: value for key, value in finding.metadata.items() if key != "pid"},
                )
                for finding in findings
            ]
            peer, primary = findings
            assert primary.metadata["own_id"] == primary.id
            assert peer.metadata["linked_id"] == primary.id
            assert primary.resource == peer.metadata["identity"]
            assert "plugin-identity-probe" not in result.to_json()
            assert "identity_material" not in result.to_json()
            assert "probe-value" not in result.to_json()
            for path in directory.iterdir():
                assert b"identity_material" not in path.read_bytes()
                assert b"plugin-identity-probe" not in path.read_bytes()
    finally:
        sys.modules.pop(MODULE, None)
        registry._cache.pop(ENTRY, None)
    assert reported["process"] == reported["thread"]


def test_identity_material_capture_is_scoped_deduplicated_and_key_specific():
    key = bytes(range(32))
    message = b"ephemeral-input"
    with capture_identity_material(key) as material:
        digest = identity_hmac_digest(key, message)
        assert identity_hmac_digest(key, message) == digest
        identity_hmac_digest(bytes(reversed(key)), b"other-key-input")
    assert material == {digest.hex(): message}
    identity_hmac_digest(key, b"outside-capture")
    assert len(material) == 1


def test_identity_material_size_limit_fails_closed(monkeypatch):
    import shadowscan.utils.crypto as crypto

    monkeypatch.setattr(crypto, "MAX_IDENTITY_MATERIAL_BYTES", 64)
    with capture_identity_material(bytes(range(32))), pytest.raises(ValueError, match="transport limit"):
        identity_hmac_digest(bytes(range(32)), b"ephemeral-input")


def test_identity_material_count_limit_fails_closed(monkeypatch):
    import shadowscan.utils.crypto as crypto

    key = bytes(range(32))
    monkeypatch.setattr(crypto, "MAX_IDENTITY_MATERIAL_ENTRIES", 1)
    with capture_identity_material(key), pytest.raises(ValueError, match="transport limit"):
        identity_hmac_digest(key, b"first")
        identity_hmac_digest(key, b"second")


def _identity_envelope(material):
    return {
        "findings": [],
        "stats": asdict(ScanStats(ENTRY, "now")),
        "exports": [],
        "identity_material": material,
    }


@pytest.mark.parametrize(
    "material",
    [
        None,
        {},
        [{"digest": "0" * 64, "message": "not-base64"}],
        [{"digest": "0" * 64, "message": ""}],
        [{"digest": "invalid", "message": ""}],
        [{"digest": "ss-" + "0" * 16, "message": ""}],
        [{"digest": "0" * 64, "message": "", "extra": True}],
        [{"digest": "0" * 64, "message": []}],
    ],
)
def test_untrusted_identity_material_is_rejected(material):
    with pytest.raises(ValueError):
        _decode_result(
            _encode_result(_identity_envelope(material)),
            1,
            ConnectorSpec(ENTRY),
            identity_keys=(bytes(range(32)), bytes(reversed(range(32)))),
        )


@pytest.mark.parametrize("binary", [False, True])
def test_nested_identity_material_is_rekeyed_in_generation_order(binary):
    import hmac

    parent_key, worker_key = bytes(range(32)), bytes(reversed(range(32)))
    with capture_identity_material(worker_key) as material:
        first = identity_hmac_digest(worker_key, b"first")
        second = identity_hmac_digest(worker_key, b"nested:" + (first if binary else first.hex().encode()))
    data = _identity_envelope(
        [
            {"digest": digest, "message": base64.b64encode(message).decode()}
            for digest, message in material.items()
        ]
    )
    data["stats"]["warnings"] = [first.hex(), second.hex()]
    restored = _rekey_result(data, parent_key, worker_key)
    expected_first = hmac.digest(parent_key, b"first", "sha256").hex()
    nested_input = bytes.fromhex(expected_first) if binary else expected_first.encode()
    expected_second = hmac.digest(parent_key, b"nested:" + nested_input, "sha256").hex()
    assert restored["stats"]["warnings"] == [expected_first, expected_second]
    assert "identity_material" not in restored


def test_identity_rewrite_matches_embedded_digest_without_rewriting_it_twice():
    original, restored, other = "a" * 64, "b" * 64, "c" * 64
    assert _rewrite_identity_values(
        {"value": "face" + original + "suffix"}, {original: restored, restored: other}
    ) == {"value": "face" + restored + "suffix"}


def test_identity_rewrite_rejects_ambiguous_keys_and_excessive_depth():
    original, restored = "a" * 64, "b" * 64
    with pytest.raises(ValueError, match="duplicate fields"):
        _rewrite_identity_values({original: True, restored: False}, {original: restored})
    nested = "value"
    for _ in range(130):
        nested = [nested]
    with pytest.raises(ValueError, match="nesting exceeds safety limit"):
        _rewrite_identity_values(nested, {original: restored})


def test_duplicate_identity_material_is_rejected():
    worker_key = bytes(reversed(range(32)))
    with capture_identity_material(worker_key) as material:
        identity_hmac_digest(worker_key, b"probe")
    entries = [
        {"digest": digest, "message": base64.b64encode(message).decode()}
        for digest, message in material.items()
    ]
    with pytest.raises(ValueError, match="identity material fields"):
        _rekey_result(_identity_envelope(entries * 2), bytes(range(32)), worker_key)


def test_parent_identity_material_limits_are_enforced(monkeypatch):
    import shadowscan.plugin_process as transport

    worker_key = bytes(reversed(range(32)))
    with capture_identity_material(worker_key) as material:
        identity_hmac_digest(worker_key, b"probe")
    entries = [
        {"digest": digest, "message": base64.b64encode(message).decode()}
        for digest, message in material.items()
    ]
    monkeypatch.setattr(transport, "MAX_IDENTITY_MATERIAL_ENTRIES", 0)
    with pytest.raises(ValueError, match="identity material"):
        _rekey_result(_identity_envelope(entries), bytes(range(32)), worker_key)
    monkeypatch.setattr(transport, "MAX_IDENTITY_MATERIAL_ENTRIES", 4096)
    monkeypatch.setattr(transport, "MAX_IDENTITY_MATERIAL_BYTES", 64)
    with pytest.raises(ValueError, match="transport limit"):
        _rekey_result(_identity_envelope(entries), bytes(range(32)), worker_key)


@pytest.mark.parametrize("stable", [False, True])
@pytest.mark.parametrize("redacted_resource", [False, True])
def test_finding_identity_matches_thread_mode(installed_probe, monkeypatch, stable, redacted_resource):
    from shadowscan import connectors as registry
    from shadowscan.comparison import IDENTITY_KEY_ENV

    if stable:
        monkeypatch.setenv(IDENTITY_KEY_ENV, "hex:" + bytes(range(32)).hex())
    else:
        monkeypatch.delenv(IDENTITY_KEY_ENV, raising=False)
    identities = {}
    resource = "probe?" + "pass" + "word" + "=" + "probe-value" if redacted_resource else "probe"
    try:
        for backend in ("thread", "process"):
            config = ScanConfig(
                connectors=[ConnectorSpec(ENTRY, {"resource": resource}, label="probe-instance")],
                plugins=[ENTRY],
                plugin_execution=backend,
            )
            result = Engine(config, SignatureIndex([])).run()
            assert result.complete, result.stats
            [finding] = result.findings
            identities[backend] = (
                finding.id,
                finding.compute_id(),
                finding.identity_schema,
                finding.resource,
            )
            if redacted_resource:
                assert "probe-value" not in finding.resource
    finally:
        sys.modules.pop(MODULE, None)
        registry._cache.pop(ENTRY, None)
    assert identities["process"] == identities["thread"]


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
    ],
)
def test_result_stats_schema_is_not_trusted(field, value):
    stats = asdict(ScanStats(ENTRY, "now"))
    stats[field] = value
    payload = json.dumps({"stats": stats, "findings": [], "exports": []}).encode()
    with pytest.raises(ValueError):
        _decode_result(payload, 1, ConnectorSpec(ENTRY))


@pytest.mark.parametrize("value", [None, True, 1, [], "fork", "Process", ""])
def test_execution_backend_configuration_rejects_invalid_values(value):
    with pytest.raises(ConfigValidationError, match="plugin_execution"):
        ScanConfig.from_dict({"options": {"plugin_execution": value}})


def test_execution_backend_defaults_and_mutation_validation():
    assert ScanConfig().plugin_execution == "thread"
    config = ScanConfig.from_dict({"options": {"plugin_execution": "process"}})
    engine = Engine(config, SignatureIndex([]))
    config.plugin_execution = "fork"
    with pytest.raises(ConfigValidationError, match="plugin_execution"):
        engine.run()


def test_plugin_execution_cli_option():
    result = CliRunner().invoke(main, ["scan", "--help"])
    assert result.exit_code == 0 and "--plugin-execution" in result.output
