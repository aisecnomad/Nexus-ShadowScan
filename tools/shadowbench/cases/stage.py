"""The isolated stage: what runs inside the namespaces for one adapter on one case.

``python -m tools.shadowbench.cases.stage SPEC.json OUT.json``

The runner starts this module under ``unshare --net --pid --fork --mount-proc``
(root) so the tool sees no network and no host processes. Inside, the stage
brings loopback up, serves the case's mock services, spawns the case's inert
processes under their declared names and command lines, runs the adapter's
invocations in order, and writes their results and the pid each process got.
"""

from __future__ import annotations

import fcntl
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

from tools.shadowbench.cases.mockserv import Services

FAKEPROC_C = r"""
#include <signal.h>
#include <unistd.h>
int main(void) { for (;;) pause(); return 0; }
"""


def build_fakeproc(path: Path) -> Path:
    """Compile the inert binary once; it ignores its arguments and sleeps until killed."""
    if path.exists():
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    src = path.with_suffix(".c")
    src.write_text(FAKEPROC_C, encoding="utf-8")
    subprocess.run(["gcc", "-O2", "-static", "-o", str(path), str(src)], check=True, capture_output=True)
    return path


def _loopback_up() -> None:
    """Bring ``lo`` up in the fresh network namespace (iproute2 may be absent, so use ioctl)."""
    siocgifflags, siocsifflags, iff_up, iff_running = 0x8913, 0x8914, 0x1, 0x40
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        ifr = struct.pack("16sH14s", b"lo", 0, b"\0" * 14)
        flags = struct.unpack("16sH14s", fcntl.ioctl(sock, siocgifflags, ifr))[1]
        fcntl.ioctl(
            sock, siocsifflags, struct.pack("16sH14s", b"lo", flags | iff_up | iff_running, b"\0" * 14)
        )


def _spawn(processes: list[dict[str, Any]], fakeproc: Path, bindir: Path) -> list[dict[str, Any]]:
    """Start one inert process per record so ``/proc`` shows its name and command line."""
    bindir.mkdir(parents=True, exist_ok=True)
    out: list[dict[str, Any]] = []
    for rec in processes:
        name = str(rec["name"]).replace("/", "_") or "proc"
        exe = bindir / name
        if not exe.exists():
            shutil.copy2(fakeproc, exe)
        argv = [str(a) for a in rec["argv"]] or [name]
        child = subprocess.Popen(
            argv,
            executable=str(exe),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        out.append({"index": int(rec["index"]), "pid": child.pid, "name": name, "cmdline": " ".join(argv)})
    time.sleep(0.2)
    return out


def _run(inv: dict[str, Any]) -> dict[str, Any]:
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
        out, err = proc.communicate()
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
        _loopback_up()
        if spec.get("services"):
            services.start()
        if spec.get("processes"):
            children = _spawn(spec["processes"], Path(spec["fakeproc"]), Path(spec["work"]) / "procbin")
            result["processes"] = children
        for inv in spec["invocations"]:
            result["runs"].append(_run(inv))
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
