"""The isolated stage: what runs inside the namespaces for one adapter on one case.

``python -m tools.shadowbench.cases.stage SPEC.json OUT.json``

The runner starts this module as root under ``unshare --net --pid --fork
--kill-child --mount --mount-proc`` so the tool sees no network, no host
processes and a private mount table. Before anything from the case runs, the
stage checks that it is the init of that fresh PID namespace and not in the
runner's mount namespace, sets ``no_new_privs``, brings loopback up, mounts
an empty tmpfs over ``/root`` and ``/home`` so the operator's homes and
credentials are out of sight, and leaves the directory it was started in for
``/``, so no process it starts inherits a working directory under a hidden
path. It then serves the case's mock services, spawns the case's inert
processes under their declared names and command lines, runs the adapter's
invocations in order, and writes their results and the pid each process got.

Tools run as the unprivileged identity the spec names (the runner passes
uid/gid 65534 with no supplementary groups) with exactly the environment
their invocation declares and nothing inherited. Inert processes run as the
same identity with a fixed minimal environment and the work directory as
their working directory, so a process scanner sees them as it would see its
own user's processes (``/proc/<pid>/exe``, ``environ``, ``cwd``) and reaches
nothing through them that it could not reach itself. Only the stage itself,
the mock services and the namespace setup keep root. No tool process
outlives its invocation: after each invocation, and on a timeout, everything
in the namespace except the stage and the inert processes is killed,
including descendants that left the tool's process group with ``setsid``.

This is not a filesystem sandbox: a tool can still read whatever is
world-readable outside ``/root`` and ``/home``.
"""

from __future__ import annotations

import ctypes
import fcntl
import functools
import json
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from tools.shadowbench.cases.contract import SYSTEM_PATH
from tools.shadowbench.cases.mockserv import Services

FAKEPROC_C = r"""
#include <signal.h>
#include <unistd.h>
int main(void) { for (;;) pause(); return 0; }
"""

HIDDEN: tuple[str, ...] = ("/root", "/home")
"""Operator home directories the stage covers with an empty tmpfs."""
INERT_ENV: dict[str, str] = {"PATH": SYSTEM_PATH, "LANG": "C.UTF-8"}
"""The whole environment of an inert process; nothing is inherited from the stage."""
KILL_GRACE = 3.0
"""Seconds to collect a killed invocation's output before its pipes are closed."""

_MS_NOSUID, _MS_NODEV, _MS_NOEXEC = 0x2, 0x4, 0x8
_PR_SET_NO_NEW_PRIVS = 38


def build_fakeproc(path: Path) -> Path:
    """Compile the inert binary once; it ignores its arguments and sleeps until killed."""
    if path.exists():
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    src = path.with_suffix(".c")
    src.write_text(FAKEPROC_C, encoding="utf-8")
    subprocess.run(["gcc", "-O2", "-static", "-o", str(path), str(src)], check=True, capture_output=True)
    return path


@functools.cache
def _libc() -> ctypes.CDLL:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p]
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    return libc


def _check_call(rc: int, what: str) -> None:
    if rc != 0:
        err = ctypes.get_errno()
        raise OSError(err, f"{what}: {os.strerror(err)}")


def _tool_identity(spec: dict[str, Any]) -> tuple[int, int]:
    """The unprivileged (uid, gid) tools run as; a spec without one never runs a tool as root."""
    ids = spec.get("run_as")
    if (
        not isinstance(ids, list)
        or len(ids) != 2
        or not all(isinstance(i, int) and not isinstance(i, bool) and i > 0 for i in ids)
    ):
        raise ValueError(f"spec names no unprivileged identity to run tools as: {ids!r}")
    return ids[0], ids[1]


def _check_namespaces(host_mnt_ns: object) -> None:
    """Refuse to touch mounts or sweep processes unless this is a fresh PID and mount namespace."""
    if os.getpid() != 1:
        raise RuntimeError("the stage is not the init of a fresh PID namespace")
    if not isinstance(host_mnt_ns, str) or os.readlink("/proc/self/ns/mnt") == host_mnt_ns:
        raise RuntimeError("the stage shares the runner's mount namespace; refusing to mount over host paths")


def _no_new_privs() -> None:
    """Make setuid binaries and file capabilities inert for every process started from here on."""
    _check_call(_libc().prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), "prctl(PR_SET_NO_NEW_PRIVS)")


def _hide(paths: tuple[str, ...]) -> None:
    """Mount an empty, root-owned tmpfs over each path; only call this in a private mount namespace."""
    flags = _MS_NOSUID | _MS_NODEV | _MS_NOEXEC
    for path in paths:
        if not os.path.isdir(path):
            continue
        rc = _libc().mount(b"tmpfs", os.fsencode(path), b"tmpfs", flags, b"mode=0755,size=64k")
        _check_call(rc, f"mount tmpfs on {path}")
        if os.listdir(path):
            raise RuntimeError(f"{path} is still populated after mounting over it")


def _loopback_up() -> None:
    """Bring ``lo`` up in the fresh network namespace (iproute2 may be absent, so use ioctl)."""
    siocgifflags, siocsifflags, iff_up, iff_running = 0x8913, 0x8914, 0x1, 0x40
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        ifr = struct.pack("16sH14s", b"lo", 0, b"\0" * 14)
        flags = struct.unpack("16sH14s", fcntl.ioctl(sock, siocgifflags, ifr))[1]
        fcntl.ioctl(
            sock, siocsifflags, struct.pack("16sH14s", b"lo", flags | iff_up | iff_running, b"\0" * 14)
        )


def _spawn(
    processes: list[dict[str, Any]],
    fakeproc: Path,
    bindir: Path,
    run_as: tuple[int, int] | None = None,
    cwd: Path | None = None,
) -> list[dict[str, Any]]:
    """Start one inert process per record so ``/proc`` shows its name and command line.

    Each gets ``cwd`` (``/`` when none is given), never the stage's own working directory: a
    tool running as the same uid can follow ``/proc/<pid>/cwd`` of these processes.
    """
    bindir.mkdir(parents=True, exist_ok=True)
    bindir.chmod(0o755)
    out: list[dict[str, Any]] = []
    for rec in processes:
        name = str(rec["name"]).replace("/", "_") or "proc"
        exe = bindir / name
        if not exe.exists():
            shutil.copy2(fakeproc, exe)
            exe.chmod(0o755)
        argv = [str(a) for a in rec["argv"]] or [name]
        child = subprocess.Popen(
            argv,
            executable=str(exe),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=str(cwd or "/"),
            env=dict(INERT_ENV),
            user=run_as[0] if run_as else None,
            group=run_as[1] if run_as else None,
            extra_groups=[] if run_as else None,
        )
        out.append({"index": int(rec["index"]), "pid": child.pid, "name": name, "cmdline": " ".join(argv)})
    time.sleep(0.2)
    return out


def _kill_strays(keep: set[int]) -> None:
    """Kill every process in this PID namespace but the stage and ``keep``; a no-op outside one."""
    if os.getpid() != 1:
        return
    for entry in os.listdir("/proc"):
        if not entry.isdigit() or int(entry) == 1 or int(entry) in keep:
            continue
        try:
            os.kill(int(entry), signal.SIGKILL)
        except ProcessLookupError:
            pass


def _drain(proc: subprocess.Popen[bytes]) -> tuple[bytes, bytes]:
    """Collect a killed invocation's output without waiting on whatever still holds its pipes."""
    try:
        return proc.communicate(timeout=KILL_GRACE)
    except subprocess.TimeoutExpired as exc:
        out, err = exc.stdout or b"", exc.stderr or b""
    for stream in (proc.stdin, proc.stdout, proc.stderr):
        if stream is not None:
            stream.close()
    try:
        proc.wait(timeout=KILL_GRACE)
    except subprocess.TimeoutExpired:
        pass
    return out, err


def _run(
    inv: dict[str, Any], run_as: tuple[int, int] | None = None, sweep: set[int] | None = None
) -> dict[str, Any]:
    """Run one invocation; with ``sweep`` (the pids to spare), kill whatever else it left running.

    Only the stage's ``main`` passes ``sweep``, once it has checked it is the init of its own
    PID namespace; without it nothing but the invocation's own process group is ever killed.
    """
    started = time.monotonic()
    timed_out = False
    try:
        proc = subprocess.Popen(
            [str(a) for a in inv["argv"]],
            cwd=str(inv["cwd"]),
            env={str(k): str(v) for k, v in dict(inv.get("env") or {}).items()},
            stdin=subprocess.PIPE if inv.get("stdin") is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            user=run_as[0] if run_as else None,
            group=run_as[1] if run_as else None,
            extra_groups=[] if run_as else None,
        )
    except OSError as exc:
        return {
            "code": 127,
            "stdout": "",
            "stderr": f"cannot start: {exc}",
            "seconds": 0.0,
            "timed_out": False,
        }
    try:
        out, err = proc.communicate(
            input=(inv["stdin"].encode() if inv.get("stdin") is not None else None),
            timeout=float(inv.get("timeout") or 300),
        )
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        # A descendant that called setsid() left the group and may still hold the pipes.
        if sweep is not None:
            _kill_strays(sweep)
        out, err = _drain(proc)
    if sweep is not None:
        _kill_strays(sweep)
    return {
        "code": 124 if timed_out else proc.returncode,
        "stdout": out.decode("utf-8", "replace")[-2_000_000:],
        "stderr": err.decode("utf-8", "replace")[-200_000:],
        "seconds": round(time.monotonic() - started, 3),
        "timed_out": timed_out,
    }


def main(argv: list[str]) -> int:
    spec = json.loads(Path(argv[0]).read_text(encoding="utf-8"))
    out_path = Path(argv[1])
    result: dict[str, Any] = {"processes": [], "runs": [], "error": None}
    services = Services(list(spec.get("services") or []))
    children: list[dict[str, Any]] = []
    try:
        run_as = _tool_identity(spec)
        _check_namespaces(spec.get("host_mnt_ns"))
        _no_new_privs()
        _loopback_up()
        _hide(HIDDEN)
        # The stage may have been started inside a now-hidden directory; children inherit the cwd.
        os.chdir("/")
        work = Path(spec["work"])
        if not work.is_dir():
            raise RuntimeError(f"work directory {work} is not visible inside the stage")
        if spec.get("services"):
            services.start()
        if spec.get("processes"):
            children = _spawn(spec["processes"], Path(spec["fakeproc"]), work / "procbin", run_as, work)
            result["processes"] = children
        spare = {int(child["pid"]) for child in children}
        for inv in spec["invocations"]:
            result["runs"].append(_run(inv, run_as, spare))
    except Exception as exc:  # noqa: BLE001 - the stage must always report, never crash silently
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        for child in children:
            try:
                os.kill(int(child["pid"]), signal.SIGKILL)
            except ProcessLookupError:
                pass
        services.stop()
        out_path.write_text(json.dumps(result), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
