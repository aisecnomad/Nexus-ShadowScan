"""Keep the moved harness complexity ceilings in the parent repository.

The companion must match its reviewed gitlink before Ruff reads its sources.
This reads the harnesses as syntax; it never runs corpus artifacts.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

from tools import benchmark_suite, complexity_gate

ROOT = Path(__file__).resolve().parents[1]
BASELINE = "tools/benchmark_complexity_baseline.json"
SOURCE_ROOTS = (
    "tools/benchmark",
    "tools/benchmark_realworld",
    "tools/discovery_benchmark",
    "tools/shadowbench",
    "benchmarks",
)


def check(root: Path, *, update: bool = False) -> int:
    """Enforce existing ceilings, allowing only an explicit downward update."""
    commit = benchmark_suite.verify_pin(root)
    suite = root / "benchmark-suite"
    baseline = complexity_gate.load_baseline(root / BASELINE)
    if baseline.modules:
        raise ValueError("the moved harness baseline must not contain scanner module ceilings")
    measured = complexity_gate.measure_functions(suite, source_roots=SOURCE_ROOTS)
    version = complexity_gate.ruff_version(suite)
    grown, slack = complexity_gate.compare(
        measured,
        baseline.functions,
        complexity_gate.MAX_FUNCTION_COMPLEXITY,
        lambda value: f"complexity {value}",
    )
    if grown:
        print("Companion complexity grew:\n  " + "\n  ".join(grown), file=sys.stderr)
        return 1
    if update:
        complexity_gate.write_baseline(root / BASELINE, measured, {}, version)
        print(f"Lowered {BASELINE}: {len(slack)} entries tightened or dropped")
        return 0
    if slack:
        print(
            "Companion baseline allows more than the code has:\n  "
            + "\n  ".join(slack)
            + "\nRun python -m tools.benchmark_complexity --update to retain only the lower ceilings.",
            file=sys.stderr,
        )
        return 1
    print(f"Verified companion {commit}: {len(measured)} harness function ceilings unchanged")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--update", action="store_true", help="lower existing ceilings; never add or raise one"
    )
    args = parser.parse_args(argv)
    try:
        return check(ROOT, update=args.update)
    except (OSError, UnicodeError, ValueError, RecursionError, subprocess.SubprocessError) as exc:
        print(f"benchmark complexity: {type(exc).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
