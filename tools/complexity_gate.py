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
size. ``--update`` records only decreases and removals, so the ceiling moves
one way: it refuses, and writes nothing, while any function is new above the
target or above its allowance. Recording such an increase takes
``--allow-increase`` as well, and the raised allowance shows in the baseline's
diff for review.

Allowances are keyed ``path::qualified name``: a method by its class
(``Connector.analyze``) and a nested function by the function that encloses it
(``scan.visit``). Two methods that share a name in one file therefore have an
allowance each, so a new ``analyze`` cannot grow to the allowance of another
class's. Should two definitions share a qualified name too, as a property's
getter and setter do, the later ones are numbered (``Connector.size#2``).

Usage::

    python -m tools.complexity_gate                            # check against the baseline
    python -m tools.complexity_gate --update                   # record decreases and removals
    python -m tools.complexity_gate --update --allow-increase  # also record an accepted increase
"""

from __future__ import annotations

import argparse
import ast
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

#: The complexity every function should eventually meet.
TARGET = 15
ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "tools" / "complexity_baseline.json"
PACKAGE = "shadowscan"


def measure(package: str = PACKAGE) -> dict[str, int]:
    """Map ``path::qualified name`` to its complexity, for every function above :data:`TARGET`."""
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
    qualified: dict[str, dict[tuple[int, str], str]] = {}
    for item in json.loads(result.stdout or "[]"):
        message = item.get("message", "")
        # "`name` is too complex (23 > 15)"
        name = message.split("`")[1] if "`" in message else "?"
        score = int(message.rsplit("(", 1)[1].split(">")[0].strip())
        path = Path(item["filename"]).resolve().relative_to(ROOT).as_posix()
        if path not in qualified:
            qualified[path] = qualified_names(ROOT / path)
        row = item["location"]["row"]
        if (row, name) not in qualified[path]:
            raise RuntimeError(f"no definition of {name} at {path}:{row} to qualify")
        key = f"{path}::{qualified[path][row, name]}"
        if key in found:
            raise RuntimeError(f"{key} measured twice")
        found[key] = score
    return found


def qualified_names(path: Path) -> dict[tuple[int, str], str]:
    """Map each function's ``(line, name)`` in *path* to its name qualified as the module docstring says."""
    names: dict[tuple[int, str], str] = {}
    seen: Counter[str] = Counter()

    def visit(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
                qualified = f"{prefix}.{child.name}" if prefix else child.name
                if not isinstance(child, ast.ClassDef):
                    seen[qualified] += 1
                    if seen[qualified] > 1:
                        qualified = f"{qualified}#{seen[qualified]}"
                    names[child.lineno, child.name] = qualified
                visit(child, qualified)
            else:
                visit(child, prefix)

    visit(ast.parse(path.read_text(encoding="utf-8"), filename=str(path)), "")
    return names


def load_baseline() -> dict[str, int]:
    if not BASELINE.exists():
        return {}
    data: dict[str, int] = json.loads(BASELINE.read_text(encoding="utf-8"))["allowances"]
    return data


def write_baseline(current: dict[str, int]) -> None:
    document = {
        "_comment": (
            f"Cyclomatic complexity above {TARGET} that predates the C901 gate, keyed by file and "
            "qualified name (Class.method; a nested function under the function enclosing it). "
            "Entries may fall and be re-recorded with `python -m tools.complexity_gate --update`; "
            "they rise, and a function not listed here exceeds the target, only through a reviewed "
            "`--update --allow-increase`. "
            "Removing an entry entirely is the goal."
        ),
        "target": TARGET,
        "allowances": dict(sorted(current.items())),
    }
    BASELINE.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def worsened(current: dict[str, int], baseline: dict[str, int]) -> list[str]:
    """One line for each function new above the target, then for each above its allowance."""
    additions = []
    regressions = []
    for key, score in sorted(current.items()):
        allowed = baseline.get(key)
        if allowed is None:
            additions.append(f"new function over the complexity target: {key} is {score} (target {TARGET})")
        elif score > allowed:
            regressions.append(f"complexity rose: {key} is {score}, baseline allows {allowed}")
    return additions + regressions


def check() -> int:
    current = measure()
    baseline = load_baseline()
    improvements = {k: v for k, v in current.items() if k in baseline and v < baseline[k]}
    resolved = sorted(set(baseline) - set(current))

    worse = worsened(current, baseline)
    for line in worse:
        print(line)
    if worse:
        print(
            "\nSplit the function. An increase that review accepts is recorded with "
            "`python -m tools.complexity_gate --update --allow-increase`.",
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


def update(*, allow_increase: bool = False) -> int:
    """Record the current measurements if none is worse than the baseline, or if *allow_increase*."""
    current = measure()
    worse = worsened(current, load_baseline())
    for line in worse:
        print(line)
    if worse and not allow_increase:
        print(
            "\nNothing recorded: --update only lowers the baseline. Split the function, or pass "
            "--allow-increase as well to record an increase that review accepts.",
            file=sys.stderr,
        )
        return 1
    write_baseline(current)
    print(f"recorded {len(current)} allowance(s) in {BASELINE.relative_to(ROOT)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--update", action="store_true", help="record decreases and removals in the baseline")
    parser.add_argument(
        "--allow-increase",
        action="store_true",
        help="with --update, also record functions that are new above the target or above their allowance",
    )
    args = parser.parse_args(argv)
    if args.allow_increase and not args.update:
        parser.error("--allow-increase applies only with --update")
    if args.update:
        return update(allow_increase=args.allow_increase)
    return check()


if __name__ == "__main__":
    raise SystemExit(main())
