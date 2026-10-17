"""Ratchet cyclomatic complexity down: existing debt is allowed, new debt is not.

``ruff``'s C901 rule was not enabled, so 119 functions sit above the usual
ceiling of 15 and the worst are past 50 — complexity that makes a security
scanner hard to change safely. Turning the rule on at 15 today would mean 119
inline suppressions, which hides the debt rather than tracking it; turning it
on at a ceiling the code already meets would mean a rule that permits
everything.

This gate takes the third path. It measures against the real target and
compares the result with a committed baseline: the build fails when a function
gets more complex than its recorded allowance, or when a new function appears
above the target, while existing functions stay buildable at their current
size. Lowering an entry is always accepted and rewrites the baseline, so the
ceiling can only move one way.

Usage::

    python -m tools.complexity_gate            # check against the baseline
    python -m tools.complexity_gate --update   # record improvements
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

#: The complexity every function should eventually meet.
TARGET = 15
ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "tools" / "complexity_baseline.json"
PACKAGE = "shadowscan"


def measure(package: str = PACKAGE) -> dict[str, int]:
    """Map ``path::function`` to its complexity, for everything above :data:`TARGET`."""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "ruff",
            "check",
            "--select",
            "C901",
            "--config",
            f"lint.mccabe.max-complexity={TARGET}",
            "--output-format",
            "json",
            package,
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )
    if result.returncode not in (0, 1):
        raise RuntimeError(f"ruff failed: {result.stderr.strip()}")
    found: dict[str, int] = {}
    for item in json.loads(result.stdout or "[]"):
        message = item.get("message", "")
        # "`name` is too complex (23 > 15)"
        name = message.split("`")[1] if "`" in message else "?"
        score = int(message.rsplit("(", 1)[1].split(">")[0].strip())
        path = Path(item["filename"]).resolve().relative_to(ROOT).as_posix()
        key = f"{path}::{name}"
        # A name can repeat within a file (an overridden method in two classes);
        # keep the worst, which is what the ceiling has to allow.
        found[key] = max(found.get(key, 0), score)
    return found


def load_baseline() -> dict[str, int]:
    if not BASELINE.exists():
        return {}
    data: dict[str, int] = json.loads(BASELINE.read_text(encoding="utf-8"))["allowances"]
    return data


def write_baseline(current: dict[str, int]) -> None:
    document = {
        "_comment": (
            f"Cyclomatic complexity above {TARGET} that predates the C901 gate. "
            "Entries may fall and be re-recorded with `python -m tools.complexity_gate --update`; "
            "they may never rise, and a function not listed here may not exceed the target. "
            "Removing an entry entirely is the goal."
        ),
        "target": TARGET,
        "allowances": dict(sorted(current.items())),
    }
    BASELINE.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def check() -> int:
    current = measure()
    baseline = load_baseline()
    regressions = []
    additions = []
    for key, score in sorted(current.items()):
        allowed = baseline.get(key)
        if allowed is None:
            additions.append((key, score))
        elif score > allowed:
            regressions.append((key, score, allowed))
    improvements = {k: v for k, v in current.items() if k in baseline and v < baseline[k]}
    resolved = sorted(set(baseline) - set(current))

    for key, score in additions:
        print(f"new function over the complexity target: {key} is {score} (target {TARGET})")
    for key, score, allowed in regressions:
        print(f"complexity rose: {key} is {score}, baseline allows {allowed}")
    if additions or regressions:
        print(
            "\nSplit the function, or justify the change and re-record with "
            "`python -m tools.complexity_gate --update`.",
            file=sys.stderr,
        )
        return 1
    if improvements or resolved:
        print(
            f"{len(improvements)} function(s) simplified and {len(resolved)} now at target; "
            "run `python -m tools.complexity_gate --update` to lock the improvement in."
        )
    print(f"complexity gate: {len(current)} function(s) above {TARGET}, none worse than the baseline")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--update", action="store_true", help="record the current measurements")
    args = parser.parse_args(argv)
    if args.update:
        current = measure()
        write_baseline(current)
        print(f"recorded {len(current)} allowance(s) in {BASELINE.relative_to(ROOT)}")
        return 0
    return check()


if __name__ == "__main__":
    raise SystemExit(main())
