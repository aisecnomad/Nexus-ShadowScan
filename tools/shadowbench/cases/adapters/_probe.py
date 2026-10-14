"""Version probes: run a tool's binary for ``Adapter.version``, scrubbed, bounded and offline.

``version()`` runs once per tool on the operator's machine, outside the
per-case namespaces the runner gives the tool itself, so a probe must not hand
a third-party binary the operator's environment. ``run_probe`` gives it a fixed
``PATH``, a throwaway ``HOME`` (also its cwd and ``TMPDIR``, removed
afterwards), ``LANG=C.UTF-8`` and nothing else from the caller's environment:
no proxy, cloud, token or other credential variables. stdin is empty and a
timeout bounds the run. The runner needs root for its own namespaces, so a
probe started as root never runs the binary as root: it gets an empty network
namespace and a private mount namespace with empty tmpfs mounts over ``/root``
and ``/home``, and drops to uid/gid 65534 with no supplementary groups and
``no_new_privs``, the identity the stage gives the tool. Its throwaway home
then lives under ``/tmp`` and belongs to that identity. When ``unshare``,
``setpriv``, ``mount`` or ``sh`` is missing a root probe does not run at all.
A probe that cannot start, fails or times out reads as ``unknown``; it is
never retried with the caller's environment or identity.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path

PROBE_TIMEOUT = 30
PROBE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
VERSION = re.compile(r"(\d+\.\d+\.\d+\S*)")


def probe_env(home: Path, extra: Mapping[str, str] | None = None) -> dict[str, str]:
    """The whole environment of a probe; ``extra`` adds tool switches such as a telemetry opt-out."""
    env = {
        "PATH": PROBE_PATH,
        "HOME": str(home),
        "TMPDIR": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
        "TERM": "dumb",
    }
    env.update(extra or {})
    return env


#: The identity a root probe drops to: the stage's (``runner.TOOL_UID``), so it reaches no more than the tool.
PROBE_UID = PROBE_GID = 65534
#: Where a dropped probe's home lives: ``/root`` and ``/home`` are hidden from it.
PROBE_TMP = "/tmp"


def isolation() -> list[str] | None:
    """The prefix a probe runs under: none unprivileged, the drop as root, None if root cannot drop."""
    if not (hasattr(os, "geteuid") and os.geteuid() == 0):
        return []
    unshare = shutil.which("unshare", path=PROBE_PATH)
    setpriv = shutil.which("setpriv", path=PROBE_PATH)
    mount = shutil.which("mount", path=PROBE_PATH)
    sh = shutil.which("sh", path=PROBE_PATH)
    if not (unshare and setpriv and mount and sh):
        return None
    hide = " && ".join(f"{shlex.quote(mount)} -t tmpfs -o mode=0755 tmpfs {d}" for d in ("/root", "/home"))
    drop = f"{shlex.quote(setpriv)} --reuid={PROBE_UID} --regid={PROBE_GID} --clear-groups --no-new-privs --"
    # The probe's argv reaches the shell as positional parameters ("$@"), never as script text.
    return [
        unshare,
        "--net",
        "--mount",
        "--propagation",
        "private",
        "--fork",
        "--kill-child",
        "--",
        sh,
        "-c",
        f'{hide} && exec {drop} "$@"',
        "probe",
    ]


def run_probe(
    argv: Sequence[str], *, extra_env: Mapping[str, str] | None = None, timeout: int = PROBE_TIMEOUT
) -> subprocess.CompletedProcess[str] | None:
    """Run ``argv`` once as described in the module docstring; None when it cannot run or times out."""
    prefix = isolation()
    if prefix is None:
        return None
    dropped = bool(prefix)
    try:
        workspace = tempfile.TemporaryDirectory(
            prefix="shadowbench-probe-", dir=PROBE_TMP if dropped else None, ignore_cleanup_errors=True
        )
    except OSError:
        return None
    with workspace as tmp:
        home = Path(tmp)
        try:
            if dropped:
                os.chown(home, PROBE_UID, PROBE_GID)
            return subprocess.run(
                [*prefix, *argv],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env=probe_env(home, extra_env),
                cwd=home,
                stdin=subprocess.DEVNULL,
            )
        except (OSError, subprocess.SubprocessError):
            return None


def cli_version(binary: str, *args: str, pattern: re.Pattern[str] = VERSION) -> str:
    """The first ``pattern`` group in the output of ``binary <args>`` (``--version`` by default)."""
    proc = run_probe([binary, *(args or ("--version",))])
    if proc is None:
        return "unknown"
    match = pattern.search(proc.stdout + proc.stderr)
    return match.group(1) if match else "unknown"


def distribution_version(binary: str, distribution: str) -> str:
    """Ask the interpreter next to a console script for the installed distribution version."""
    python = Path(binary).parent / "python"
    if not python.exists():
        return "unknown"
    code = f"import importlib.metadata as m; print(m.version({distribution!r}))"
    proc = run_probe([str(python), "-I", "-c", code])
    if proc is None or proc.returncode != 0:
        return "unknown"
    return proc.stdout.strip() or "unknown"
