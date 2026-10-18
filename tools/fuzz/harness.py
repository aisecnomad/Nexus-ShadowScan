"""Runs a fuzz target under Atheris, Google's coverage-guided fuzzer for Python (libFuzzer).

    python -m tools.fuzz TARGET [libFuzzer flags and corpus directories]

``TARGET`` is one of :data:`TARGET_NAMES`. Everything after it goes to libFuzzer, so
``-max_total_time=300`` bounds the run in seconds, ``-artifact_prefix=DIR/`` says where a failing
input is written, and a file named instead of a corpus directory is run once, which replays a
failure. The defaults below apply unless the same flag is given.

This module must not import the scanner: Atheris reports coverage only for modules that are
imported while its import hook is active, so the targets are imported inside it (see :func:`run`).
"""

from __future__ import annotations

import importlib
import shlex
import sys
import tempfile
from collections.abc import Sequence
from typing import Final

TARGET_NAMES: Final = ("redaction-text", "redaction-record", "lexing")

# Inputs are text a scanner reads from one file, so a few kilobytes reach every code path; a longer
# one only slows the run. Thirty seconds on one input is a hang: the lexer and redactor are linear
# or bounded by design. The memory limit turns a runaway allocation into a finding.
DEFAULT_FLAGS: Final = ("-max_len=8192", "-timeout=30", "-rss_limit_mb=2048")

USAGE: Final = (
    "usage: python -m tools.fuzz {" + "|".join(TARGET_NAMES) + "} [libFuzzer flags and corpus directories]"
)

INSTALL_HINT: Final = (
    "Atheris is not installed. Install the hash-locked fuzzing engine on Linux x86_64 (CPython 3.12 to "
    "3.14 have wheels):\n  python -m pip install --require-hashes --only-binary=:all: -r requirements.lock "
    "-r requirements-fuzz.lock\nSee docs/operations/fuzzing.md."
)


def libfuzzer_arguments(program: str, flags: Sequence[str]) -> list[str]:
    """``flags`` with the defaults for every flag they do not set, and an artifact directory.

    libFuzzer writes a failing input into the current directory unless told otherwise, which would
    be the checkout, so the default is a new temporary directory.
    """
    given = {flag.split("=", 1)[0] for flag in flags if flag.startswith("-")}
    defaults = [flag for flag in DEFAULT_FLAGS if flag.split("=", 1)[0] not in given]
    if "-artifact_prefix" not in given:
        defaults.append(f"-artifact_prefix={tempfile.mkdtemp(prefix='shadowscan-fuzz-')}/")
    return [program, *defaults, *flags]


def command(target: str) -> str:
    """The shell command that runs ``target`` again, which is how libFuzzer starts its helper processes.

    ``-minimize_crash``, ``-fork`` and ``-jobs`` re-run the program named first on the command line, so
    it must be a command that works from here: this interpreter, running this module.
    """
    return f"{shlex.quote(sys.executable)} -m tools.fuzz {target}"


def run(target: str, flags: Sequence[str] = ()) -> None:
    """Fuzz ``target``; this returns only when Atheris could not start."""
    try:
        atheris = importlib.import_module("atheris")
    except ModuleNotFoundError:
        raise SystemExit(INSTALL_HINT) from None
    # Only the scanner is instrumented: coverage of the standard library and of regex says nothing
    # about the scanner, and instrumenting them slows every execution.
    with atheris.instrument_imports(include=["shadowscan"]):
        targets = importlib.import_module("tools.fuzz.targets")
    atheris.Setup(libfuzzer_arguments(command(target), flags), targets.TARGETS[target])
    atheris.Fuzz()


def main(argv: Sequence[str] | None = None) -> None:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments or arguments[0] not in TARGET_NAMES:
        raise SystemExit(USAGE)
    run(arguments[0], arguments[1:])
