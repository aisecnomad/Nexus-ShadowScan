"""Killable plugin workers; lifecycle isolation, never a security sandbox.

Only trusted first-party configuration and signature objects travel through
``spawn``. Plugin results use one length-prefixed, size-bounded JSON message
on a socket, never pickle.
Dedicated processes allow individual timeouts on Python 3.11, where cancelling
a ProcessPoolExecutor future cannot stop a running worker.
"""

from __future__ import annotations

import io
import json
import multiprocessing
import multiprocessing.connection
import multiprocessing.context
import multiprocessing.util
import os
import re
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Iterable, Mapping, MutableMapping
from dataclasses import asdict, replace
from multiprocessing import popen_spawn_posix, reduction, spawn
from multiprocessing.process import BaseProcess
from pathlib import Path
from typing import TYPE_CHECKING, Any

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors.base import known_incomplete_reasons
from shadowscan.coverage import validate_coverage_summary
from shadowscan.models import Finding, ScanStats, now_iso
from shadowscan.signatures import Signature, SignatureIndex
from shadowscan.utils.redaction import sanitize
from shadowscan.utils.safe_json import strict_json_loads

if TYPE_CHECKING:
    from shadowscan.engine import _ConnectorRunner, _JobResult, _JobState

MAX_RESULT_BYTES = 16 * 1024 * 1024
_LENGTH_BYTES = 8
_CLEANUP_SECONDS = 0.5
# Socket and multiprocessing waits overflow beyond about 24.8 days. Waits use
# slices of at most a day, so a very large connector timeout still works.
_MAX_WAIT_SECONDS = 86_400.0
# A worker stops itself this long after its deadline, matching the parent's
# supervision guard, in case nothing in the scanner is left to terminate it.
_WORKER_GRACE_SECONDS = 2.0
# Without a descriptor listing, descriptors up to the open-file limit are
# visited, but never more than this many.
_MAX_DESCRIPTOR_LIMIT = 1 << 20
# A process-mode worker does not inherit the credentials the operator exported
# for the built-in connectors: a variable whose name ends in one of these words
# (after ``_``, or the whole name; a version after the word, as in
# ``CI_JOB_JWT_V2``, is ignored, a bare number is not: Git's
# ``GIT_CONFIG_KEY_0`` names a setting), starts with one of the prefixes (a
# token or connection string whose name ends in a host or connection name:
# Terraform's ``TF_TOKEN_<host>``, npm's ``npm_config__auth*``, .NET's
# ``ConnectionStrings__<name>``, Azure App Service's ``<type>CONNSTR_<name>``),
# is a Bundler host credential (``BUNDLE_<HOST>__COM``: any ``BUNDLE_`` name
# with ``__``, which also takes the gem-scoped ``BUNDLE_BUILD__<gem>`` and
# ``BUNDLE_LOCAL__<gem>``), or is one of the CI and cloud SDK variables that
# carry a credential, the file holding one or a session without such a word at
# the end of their names. A ``*_URL``, ``*_URI`` or ``*_DSN`` variable is
# withheld when its value carries a user or password
# (``redis://:password@host``, ``https://token@host``); a webhook URL
# (``*_WEBHOOK``, ``*_WEBHOOK_URL``) carries its secret in the path and is
# always withheld. Configuration selectors (``AWS_PROFILE``, ``KUBECONFIG``,
# ``CLOUDSDK_CONFIG``, ``DOCKER_CONFIG``, ``BUNDLE_GEMFILE``) and endpoints
# (``IDENTITY_ENDPOINT``, ``NPM_CONFIG_REGISTRY``) stay, as does everything
# else a program needs: PATH, HOME, locale, temporary directory, proxy and CA
# settings. ``SESSION`` is not a suffix: it would also take the desktop's
# DESKTOP_SESSION.
CREDENTIAL_NAME_SUFFIXES: tuple[str, ...] = (
    "TOKEN",
    "ACCESSTOKEN",
    "SECRET",
    "KEY",
    "APIKEY",
    "PASSWORD",
    "PASSWD",
    "PASSPHRASE",
    "CREDENTIALS",
    "CREDENTIAL",
    "PAT",
    "JWT",
    "CONNECTION_STRING",
    "AUTHTOKEN",
    "WEBHOOK",
    "WEBHOOK_URL",
)
CREDENTIAL_NAME_PREFIXES: tuple[str, ...] = (
    "OP_SESSION_",
    "TF_TOKEN_",
    "NPM_CONFIG__AUTH",
    "CONNECTIONSTRINGS__",
    # Azure App Service connection strings, one prefix per connection type.
    "CUSTOMCONNSTR_",
    "SQLAZURECONNSTR_",
    "SQLCONNSTR_",
    "MYSQLCONNSTR_",
    "POSTGRESQLCONNSTR_",
    "APIHUBCONNSTR_",
    "DOCDBCONNSTR_",
    "EVENTHUBCONNSTR_",
    "NOTIFICATIONHUBCONNSTR_",
    "REDISCACHECONNSTR_",
    "SERVICEBUSCONNSTR_",
)
CREDENTIAL_NAMES: frozenset[str] = frozenset(
    {
        "AWS_ACCESS_KEY_ID",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AZURE_CLIENT_CERTIFICATE_PATH",
        "AZURE_FEDERATED_TOKEN_FILE",
        "BW_SESSION",
        "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE",
        "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE",
        "COMPOSER_AUTH",
        "DOCKER_AUTH_CONFIG",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GOOGLE_GHA_CREDS_PATH",
        "IDENTITY_HEADER",
        "OCI_CLI_KEY_FILE",
        "OCI_CLI_KEY_CONTENT",
        "OCI_CLI_SECURITY_TOKEN_FILE",
        "DATABASE_URL",
        "DATABASE_DSN",
    }
)
CREDENTIAL_URL_SUFFIXES: tuple[str, ...] = ("URL", "URI", "DSN")
_NAME_VERSION = re.compile(r"_V[0-9]+$")
# Bundler reads a host's credentials from BUNDLE_ and the host, ``.`` written ``__``.
_BUNDLER_HOST = re.compile(r"BUNDLE_.+__")


def _ends_in(upper: str, suffixes: tuple[str, ...]) -> bool:
    return any(upper == suffix or upper.endswith("_" + suffix) for suffix in suffixes)


def is_credential_name(name: str) -> bool:
    """Whether an environment variable named ``name`` is withheld from a plugin worker, whatever its value."""
    upper = name.upper()
    if upper in CREDENTIAL_NAMES or upper.startswith(CREDENTIAL_NAME_PREFIXES) or _BUNDLER_HOST.match(upper):
        return True
    return _ends_in(_NAME_VERSION.sub("", upper), CREDENTIAL_NAME_SUFFIXES)


def is_credential_variable(name: str, value: str) -> bool:
    """Whether the environment variable ``name=value`` is withheld from a plugin worker.

    The names :func:`is_credential_name` withholds, and a ``*_URL``, ``*_URI`` or ``*_DSN``
    whose value has an ``@`` after ``://``: a user and password, or a token, as the URL's
    user information. Any ``@`` after the scheme counts, so a password that leaves ``/``,
    ``?`` or ``#`` unescaped is withheld too.
    """
    if is_credential_name(name):
        return True
    _, separator, rest = value.partition("://")
    return bool(separator) and "@" in rest and _ends_in(name.upper(), CREDENTIAL_URL_SUFFIXES)


def _withheld_names(environ: Mapping[str, str], keep: Iterable[str]) -> list[str]:
    """The names of the credential-shaped variables in ``environ``, except ``keep``."""
    kept = set(keep)
    return sorted(
        name for name in environ if name not in kept and is_credential_variable(name, environ.get(name) or "")
    )


def scrub_credential_environment(environ: MutableMapping[str, str], keep: Iterable[str] = ()) -> list[str]:
    """Remove the credential-shaped variables from ``environ``, except ``keep``; return the names removed.

    Called in the worker before the plugin is imported, on the worker's own
    copy of the environment: the scanner's environment is not changed, and
    thread-mode plugins, which share the scanner's process, are unaffected.
    ``keep`` is ``options.plugin_env``: the variables an approved plugin reads
    itself, by exact name. The worker was already started without these
    variables (see _worker_environment); this is the second line.
    """
    removed = _withheld_names(environ, keep)
    for name in removed:
        del environ[name]
    return removed


def _worker_environment(environ: Mapping[str, str], keep: Iterable[str]) -> dict[str, str]:
    """The environment a worker starts with: ``environ`` without the withheld credentials.

    The credential-shaped variables (except ``keep``) and the identity key, even when ``keep``
    names it, are left out, so the worker never holds them: removing a variable inside the
    worker would not change the environment it was started with, which it can still read
    (``/proc/self/environ`` on Linux). PYTHONSAFEPATH=1 keeps the working directory (possibly
    an untrusted checkout) off the worker's sys.path before its first ``import
    multiprocessing``, since spawn runs ``python -c``.
    """
    from shadowscan.comparison import IDENTITY_KEY_ENV

    snapshot = {name: value for name in list(environ) if (value := environ.get(name)) is not None}
    withheld = {IDENTITY_KEY_ENV, *_withheld_names(snapshot, keep)}
    environment = {name: value for name, value in snapshot.items() if name not in withheld}
    environment["PYTHONSAFEPATH"] = "1"
    return environment


def _close_descriptors(*descriptors: int) -> None:
    for descriptor in descriptors:
        os.close(descriptor)


class _WorkerPopen(popen_spawn_posix.Popen):
    """multiprocessing's spawn launcher, handing the worker its own environment.

    The stdlib launcher starts the child with the process environment, so the only way to
    change what the child receives would be to change the whole process's environment while
    it starts, which a program another thread starts meanwhile would inherit. This launcher
    passes the environment :func:`_worker_environment` builds to ``subprocess.Popen``
    instead; nothing in the scanner's environment changes. It mirrors CPython 3.13's
    ``popen_spawn_posix.Popen._launch`` otherwise, except that the worker gets no descriptor
    of the scanner's resource tracker: that tracker would start with the scanner's
    environment and working directory, and a plugin that needs one starts its own.
    """

    # The descriptors the child inherits: the stdlib launcher's list, which pickling the
    # worker's socket (duplicate_for_child) adds to.
    _fds: list[int]

    def __init__(self, process_obj: BaseProcess) -> None:
        self._child: subprocess.Popen[bytes] | None = None
        super().__init__(process_obj)

    def _launch(self, process_obj: BaseProcess) -> None:
        if not isinstance(process_obj, _WorkerProcess):
            raise TypeError("only a plugin worker process starts through this launcher")
        environment = _worker_environment(os.environ, process_obj.credential_keep)
        preparation = spawn.get_preparation_data(process_obj.name)
        data = io.BytesIO()
        multiprocessing.context.set_spawning_popen(self)
        try:
            reduction.dump(preparation, data)
            reduction.dump(process_obj, data)
        finally:
            multiprocessing.context.set_spawning_popen(None)
        parent_r: int | None = None
        parent_w: int | None = None
        child_r: int | None = None
        child_w: int | None = None
        try:
            parent_r, child_w = os.pipe()
            child_r, parent_w = os.pipe()
            command = spawn.get_command_line(pipe_handle=child_r)
            self._fds.extend([child_r, child_w])
            self._child = subprocess.Popen(  # noqa: S603 - this interpreter, multiprocessing's own command
                command,
                executable=spawn.get_executable(),
                env=environment,
                close_fds=True,
                pass_fds=self._fds,
                restore_signals=False,
            )
            self.pid = self._child.pid
            # As in CPython 3.13: a worker that dies before reading its data must not leave
            # this write blocked on a pipe whose reading end the scanner itself still holds.
            os.close(child_r)
            child_r = None
            os.close(child_w)
            child_w = None
            self.sentinel = parent_r
            with open(parent_w, "wb", closefd=False) as pipe:
                pipe.write(data.getbuffer())
        finally:
            parent = [descriptor for descriptor in (parent_r, parent_w) if descriptor is not None]
            self.finalizer = multiprocessing.util.Finalize(self, _close_descriptors, parent)
            for leftover in (child_r, child_w):
                if leftover is not None:
                    os.close(leftover)

    def poll(self, flag: int = os.WNOHANG) -> int | None:
        # subprocess reaps the child it started; a second waitpid here would race it.
        if self.returncode is None and self._child is not None:
            self.returncode = self._child.wait() if flag == 0 else self._child.poll()
        return self.returncode


class _WorkerProcess(multiprocessing.context.SpawnProcess):
    """A spawned worker started by :class:`_WorkerPopen`; ``keep`` is ``options.plugin_env``."""

    def __init__(self, *args: Any, keep: Iterable[str] = (), **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.credential_keep = tuple(keep)

    @staticmethod
    def _Popen(process_obj: BaseProcess) -> _WorkerPopen:
        return _WorkerPopen(process_obj)


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    return remaining


def _wait_slice(deadline: float) -> float:
    """The time left before *deadline*, at most one wait slice; TimeoutError once it has passed."""
    return min(_remaining(deadline), _MAX_WAIT_SECONDS)


def _encode_result(value: dict[str, Any]) -> bytes:
    # Match ScanResult.to_json: values JSON cannot represent (datetime, set,
    # bytes) become str() as in a thread-mode report, then the parent's
    # Finding.from_dict sanitizes them. NaN and infinity still fail closed.
    output = bytearray()
    encoder = json.JSONEncoder(allow_nan=False, separators=(",", ":"), default=str)
    for chunk in encoder.iterencode(value):
        output.extend(chunk.encode("utf-8"))
        if len(output) > MAX_RESULT_BYTES:
            raise ValueError("plugin result exceeds transport limit")
    return bytes(output)


def _exit_with_scanner(deadline: float) -> None:
    """Stop this worker when the scanner process exits or the deadline grace ends.

    The scanner can exit without running its cleanup (the job-deadline
    watchdog's ``os._exit``, SIGTERM or SIGKILL). A plugin that ignores its
    deadline would then keep running, with its credentials, as an orphan.
    The parent sentinel becomes readable as soon as the scanner process is gone.
    """
    parent = multiprocessing.parent_process()
    sentinels = [parent.sentinel] if parent is not None else []

    def watch() -> None:
        try:
            end = deadline + _WORKER_GRACE_SECONDS
            while (remaining := end - time.monotonic()) > 0:
                wait = min(remaining, _MAX_WAIT_SECONDS)
                if sentinels:
                    if multiprocessing.connection.wait(sentinels, wait):
                        break
                else:
                    time.sleep(wait)
        finally:
            os._exit(1)

    threading.Thread(target=watch, name="shadowscan-plugin-watchdog", daemon=True).start()


def _descriptor_limit() -> int:
    """Bound descriptor enumeration when the platform has no descriptor listing."""
    try:
        import resource

        soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft == resource.RLIM_INFINITY:
            return _MAX_DESCRIPTOR_LIMIT
        if soft >= 0:
            return min(soft, _MAX_DESCRIPTOR_LIMIT)
    except (ImportError, OSError, ValueError, OverflowError):
        pass
    try:
        limit = os.sysconf("SC_OPEN_MAX")
        if limit >= 0:
            return min(limit, _MAX_DESCRIPTOR_LIMIT)
    except (AttributeError, OSError, ValueError, OverflowError):
        pass
    return _MAX_DESCRIPTOR_LIMIT


def _keep_descriptors_from_programs() -> None:
    """Programs a plugin starts must not inherit this worker's descriptors.

    Spawn passes the result socket and multiprocessing's liveness pipe as
    inheritable descriptors. A program still holding the liveness pipe keeps
    the parent from seeing this worker exit, so a result that already arrived
    would be discarded at the deadline.
    """
    for listing in ("/proc/self/fd", "/dev/fd"):
        try:
            descriptors: Iterable[int] = [int(name) for name in os.listdir(listing)]
            break
        except (OSError, ValueError):
            continue
    else:
        descriptors = range(3, _descriptor_limit())
    for descriptor in descriptors:
        if descriptor > 2:
            try:
                os.set_inheritable(descriptor, False)
            except OSError:
                pass  # Closed meanwhile, such as the directory listing's own descriptor.


def _worker(
    channel: socket.socket,
    config: ScanConfig,
    signatures: list[Signature],
    number: int,
    deadline: float,
    identity_key: bytes,
    dump_directory: Path | None,
) -> None:
    """Import and execute the approved plugin only inside its spawned process."""
    _keep_descriptors_from_programs()
    _exit_with_scanner(deadline)
    # A plugin's print/log calls may contain credentials. Diagnostics must come
    # through the scanner's sanitized result, not inherited stdout or stderr.
    with open(os.devnull, "w") as sink:
        os.dup2(sink.fileno(), 1)
        os.dup2(sink.fileno(), 2)
    try:
        from shadowscan.comparison import IDENTITY_KEY_ENV
        from shadowscan.engine import Engine, _ConnectorRunner, _ExportLedger, _JobState
        from shadowscan.incremental import IncrementalCache

        index = SignatureIndex(signatures)
        engine = Engine(config, index)
        # Remove the operator's raw identity key, and every other credential
        # the operator exported for the built-in connectors, from the process
        # environment before importing or running the plugin; connectors that
        # declare ``uses_run_identity_key`` receive the decoded key via
        # ConnectorContext, and ``options.plugin_env`` names what a plugin keeps.
        os.environ.pop(IDENTITY_KEY_ENV, None)
        scrub_credential_environment(os.environ, config.plugin_env)
        exports = _ExportLedger()
        runner = _ConnectorRunner(
            engine,
            IncrementalCache(config, index),
            # The parent's prepare_private_directory result: expanded, symlink
            # free, owned and 0700. Never re-derive it from the raw option.
            dump_directory,
            exports,
        )
        runner._run_identity_key = identity_key
        state = _JobState(started_at=now_iso(), deadline=deadline)
        spec = config.connectors[0]
        _, findings, stats = runner._run_job(number, spec, state)
        payload = _encode_result(
            {
                "findings": [finding.to_dict() for finding in findings],
                "stats": asdict(stats),
                "exports": exports.entries([(number, spec)], set()),
            }
        )
        status = 0
    except BaseException:  # noqa: BLE001 - a plugin may raise SystemExit; never echo its exception
        payload = b'{"error":"plugin worker failed or its result exceeded the transport limit"}'
        status = 1
    try:
        try:
            channel.settimeout(_wait_slice(deadline))
            channel.sendall(len(payload).to_bytes(_LENGTH_BYTES, "big") + payload)
        finally:
            channel.close()
    except BaseException:  # noqa: BLE001 - an unsent result is a failed worker
        status = 1
    finally:
        # Exit now: a plugin's lingering non-daemon threads or atexit handlers
        # must not delay, and so discard, a result that was already sent.
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.flush()
            except Exception:  # noqa: BLE001, S110 - output goes to /dev/null; teardown must not raise
                pass
        os._exit(status)


def _read_exactly(channel: socket.socket, size: int, deadline: float) -> bytes:
    result = bytearray()
    while len(result) < size:
        channel.settimeout(_wait_slice(deadline))
        try:
            chunk = channel.recv(min(65536, size - len(result)))
        except TimeoutError:
            continue  # A wait slice ended; _wait_slice raises once the deadline has passed.
        if not chunk:
            raise ValueError("plugin result ended before its declared length")
        result.extend(chunk)
    return bytes(result)


def _receive(channel: socket.socket, deadline: float) -> bytes:
    """Read one length-prefixed result, bounded in size and by the original job deadline.

    The declared length ends the result, so a program the plugin started that
    still holds the worker's end of the socket cannot delay it.
    """
    size = int.from_bytes(_read_exactly(channel, _LENGTH_BYTES, deadline), "big")
    if size > MAX_RESULT_BYTES:
        raise ValueError("plugin result exceeds transport limit")
    return _read_exactly(channel, size, deadline)


def _stop(process: BaseProcess) -> None:
    if process.pid is None:
        return
    if process.is_alive():
        process.terminate()
        process.join(_CLEANUP_SECONDS)
    if process.is_alive():
        process.kill()
        process.join(_CLEANUP_SECONDS)
    if process.is_alive():
        # An OS task in uninterruptible kernel sleep cannot be forcibly reaped
        # even by SIGKILL. Do not hide that exceptional cleanup failure.
        raise RuntimeError("plugin worker could not be reaped; external process supervision required")
    process.close()


class _WorkerHandle:
    """Serialize the watchdog's kill with the supervisor's cleanup of one worker.

    ``Process.close()`` clears its handle before it marks the object closed;
    a kill from another thread in between would fail with AttributeError and
    end the scan without a report.
    """

    def __init__(self, process: BaseProcess) -> None:
        self._process = process
        self._lock = threading.Lock()

    def kill(self) -> None:
        with self._lock:
            try:
                if self._process.pid is not None and self._process.is_alive():
                    self._process.kill()
            except (OSError, ValueError):
                pass  # The worker already exited, or its process handle is closed.

    def stop(self) -> None:
        with self._lock:
            _stop(self._process)


def _check_statistics(raw: Any) -> None:
    """Refuse a worker's statistics unless every field has the type ``ScanStats`` gives it."""
    if not isinstance(raw, dict) or set(raw) != set(asdict(ScanStats("", ""))):
        raise ValueError("invalid plugin statistics")
    for key in ("connector", "started_at"):
        if not isinstance(raw[key], str):
            raise ValueError("invalid plugin statistics string")
    for key in ("finished_at", "skip_reason", "name"):
        if raw[key] is not None and not isinstance(raw[key], str):
            raise ValueError("invalid plugin statistics optional string")
    for key in ("findings", "objects_examined", "declared_omissions"):
        if type(raw[key]) is not int or raw[key] < 0:
            raise ValueError("invalid plugin statistics count")
    for key in ("incomplete", "skipped", "cached"):
        if type(raw[key]) is not bool:
            raise ValueError("invalid plugin statistics flag")
    for key in ("errors", "warnings"):
        if not isinstance(raw[key], list) or any(not isinstance(item, str) for item in raw[key]):
            raise ValueError("invalid plugin diagnostics")
    reasons = raw["incomplete_reasons"]
    if not isinstance(reasons, dict) or any(
        not isinstance(reason, str) or type(count) is not int or count < 0
        for reason, count in reasons.items()
    ):
        raise ValueError("invalid plugin incomplete reasons")
    validate_coverage_summary(raw["coverage"])


def _decode_result(
    payload: bytes, number: int, spec: ConnectorSpec
) -> tuple[list[Finding], ScanStats, list[dict[str, Any]]]:
    data = strict_json_loads(payload)
    if not isinstance(data, dict) or set(data) != {"findings", "stats", "exports"}:
        raise ValueError("invalid plugin result envelope")
    if not isinstance(data["findings"], list) or not isinstance(data["exports"], list):
        raise ValueError("invalid plugin result arrays")
    raw = data["stats"]
    _check_statistics(raw)
    stats = ScanStats(**sanitize(raw))
    stats.connector = spec.id
    # Reason keys are the plugin process's own text, bound for the banner and the exit-3 line.
    stats.incomplete_reasons = known_incomplete_reasons(stats.incomplete_reasons)
    stats.incomplete = stats.incomplete or stats.skipped or bool(stats.errors)
    findings = [Finding.from_dict(item) for item in data["findings"]]
    if any(finding.connector != spec.name for finding in findings) or stats.findings != len(findings):
        raise ValueError("invalid plugin finding attribution or count")
    for finding in findings:
        # The worker's engine derives each id from the plugin's name, but this payload is the
        # plugin process's own output: an id it carries is never kept (as in _ConnectorRunner._collect).
        finding.reattribute(spec.name, derive_id=True)
    exports = data["exports"]
    for entry in exports:
        if not isinstance(entry, dict) or set(entry) != {
            "config_ordinal",
            "part",
            "connector",
            "label",
            "filename",
            "complete",
            "exported",
        }:
            raise ValueError("invalid plugin export")
        if entry["config_ordinal"] != number or entry["connector"] != spec.name:
            raise ValueError("invalid plugin export attribution")
        part = entry["part"]
        if not isinstance(part, str) or not re.fullmatch(rf"{number:04d}(?:-[0-9]+)?", part):
            raise ValueError("invalid plugin export part")
        filename = entry["filename"]
        if filename is not None and (
            not isinstance(filename, str) or Path(filename).name != filename or filename in {".", ".."}
        ):
            raise ValueError("invalid plugin export filename")
        if type(entry["complete"]) is not bool or type(entry["exported"]) is not bool:
            raise ValueError("invalid plugin export flags")
        entry["label"] = spec.label
    return findings, stats, exports


def _run_plugin_process(
    runner: _ConnectorRunner, number: int, spec: ConnectorSpec, state: _JobState
) -> _JobResult:
    """Supervise one child and reject timeout, crash, or malformed/oversized output."""
    assert state.deadline is not None
    deadline = state.deadline
    # Do not transmit sibling configurations or load inventory in this child.
    dump_directory = runner._dump_directory
    config = replace(
        runner._config,
        connectors=[spec],
        inventory=[],
        plugin_execution="thread",
        dump_records=str(dump_directory) if dump_directory else None,
    )
    parent, child = socket.socketpair()
    try:
        process = _WorkerProcess(
            target=_worker,
            args=(
                child,
                config,
                list(runner._index.signatures.values()),
                number,
                deadline,
                runner._run_identity_key,
                dump_directory,
            ),
            daemon=True,
            name="shadowscan-plugin",
            keep=config.plugin_env,
        )
    except Exception:
        parent.close()
        child.close()
        raise

    handle = _WorkerHandle(process)
    state.kill_process = handle.kill
    runner._engine._report_progress(spec.id, "starting (process)")
    result: _JobResult | None = None
    message = "plugin process failed, crashed, or returned invalid/oversized output; results discarded"
    warnings: list[str] = []
    try:
        _remaining(deadline)
        if state.cancelled.is_set():
            raise TimeoutError
        # The worker starts with its own environment, without the scanner's credentials and
        # with PYTHONSAFEPATH=1: see _worker_environment and _WorkerPopen.
        process.start()
        if state.cancelled.is_set():
            raise TimeoutError
        child.close()
        payload = _receive(parent, deadline)
        process.join(_wait_slice(deadline))
        _remaining(deadline)
        if process.exitcode != 0:
            raise ValueError("plugin worker did not exit successfully")
        findings, stats, entries = _decode_result(payload, number, spec)
        _remaining(deadline)
        if state.cancelled.is_set():
            raise TimeoutError
        result = spec, findings, stats
    except TimeoutError:
        message = "connector_timeout completion deadline exceeded; plugin process results discarded"
        warnings = [
            "Plugin worker terminated; its descendants and external side effects are not rolled back."
        ]
    except Exception:  # noqa: BLE001, S110 - the generic message above stands; the exception may echo plugin configuration
        pass
    finally:
        parent.close()
        child.close()
        try:
            handle.stop()
        except RuntimeError as exc:
            result = None
            message = str(exc)
    if result is not None:
        runner._engine._report_progress(spec.id, f"{len(result[1])} findings (process)")
        if not state.cancelled.is_set() and time.monotonic() < deadline:
            for entry in entries:
                runner._exports.record(state, entry)
            return result
        message = "connector_timeout completion deadline exceeded; plugin process results discarded"
    runner._exports.record(
        state,
        {
            "config_ordinal": number,
            "part": f"{number:04d}",
            "connector": spec.name,
            "label": spec.label,
            "filename": None,
            "complete": False,
            "exported": False,
        },
    )
    state.cancelled.set()
    return (
        spec,
        [],
        ScanStats(
            connector=spec.id,
            started_at=state.started_at or now_iso(),
            finished_at=now_iso(),
            incomplete=True,
            skipped=True,
            skip_reason=message,
            errors=[message],
            warnings=warnings,
        ),
    )


def run_plugin_process(
    runner: _ConnectorRunner, number: int, spec: ConnectorSpec, state: _JobState
) -> _JobResult:
    """Keep process setup/resource failures fail-closed just like worker failures."""
    try:
        return _run_plugin_process(runner, number, spec, state)
    except Exception:  # noqa: BLE001 - report a fixed diagnostic, never configuration or exception text
        runner._exports.record(
            state,
            {
                "config_ordinal": number,
                "part": f"{number:04d}",
                "connector": spec.name,
                "label": spec.label,
                "filename": None,
                "complete": False,
                "exported": False,
            },
        )
        state.cancelled.set()
        message = "plugin process setup or supervision failed; results discarded"
        return (
            spec,
            [],
            ScanStats(
                connector=spec.id,
                started_at=state.started_at or now_iso(),
                finished_at=now_iso(),
                incomplete=True,
                skipped=True,
                skip_reason=message,
                errors=[message],
            ),
        )
