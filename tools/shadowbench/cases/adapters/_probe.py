"""Version probes: run a tool's binary for ``Adapter.version``, scrubbed, bounded and offline.

``version()`` runs once per tool on the operator's machine, outside the
per-case namespaces the runner gives the tool itself, so a probe must not hand
a third-party binary the operator's environment. ``run_probe`` gives it a fixed
``PATH``, a throwaway ``HOME`` (also its cwd and ``TMPDIR``, removed
afterwards), ``LANG=C.UTF-8`` and nothing else from the caller's environment:
no proxy, cloud, token or other credential variables. stdin is empty, a
timeout bounds the run, and when the probe runs as root (the runner needs root
for its own namespaces) and ``unshare`` is installed it also gets an empty
network namespace. A probe that cannot start, fails or times out reads as
``unknown``; it is never retried with the caller's environment.
"""

from __future__ import annotations

import os
import re
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


def isolation() -> list[str]:
    """``unshare --net --`` when the probe can get an empty network namespace, else nothing."""
    unshare = shutil.which("unshare", path=PROBE_PATH)
    if unshare and hasattr(os, "geteuid") and os.geteuid() == 0:
        return [unshare, "--net", "--"]
    return []


def run_probe(
    argv: Sequence[str], *, extra_env: Mapping[str, str] | None = None, timeout: int = PROBE_TIMEOUT
) -> subprocess.CompletedProcess[str] | None:
    """Run ``argv`` once as described in the module docstring; None when it cannot run or times out."""
    with tempfile.TemporaryDirectory(prefix="shadowbench-probe-", ignore_cleanup_errors=True) as tmp:
        home = Path(tmp)
        try:
            return subprocess.run(
                [*isolation(), *argv],
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
