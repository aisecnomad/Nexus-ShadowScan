"""Ratchet the size of the largest functions and modules so they cannot grow back.

Two measures are held to ``tools/complexity_baseline.json``:

* the McCabe complexity that ruff reports as ``C901`` for every function in ``shadowscan/``, ``tools/`` and
  ``benchmarks/`` above ``MAX_FUNCTION_COMPLEXITY``. Ruff counts the body of a nested function into the
  function around it, and so does this gate; ``noqa`` comments do not hide a function from it.
* the physical line count of every module of the ``shadowscan`` package above ``MAX_MODULE_LINES``. The
  benchmark and tooling directories hold corpus and fixture modules that grow with their data, so only their
  functions are held.

The baseline lists what is already over a limit, each at the value it has today. Anything not listed must
stay under the limit, and anything listed may not rise above its value. The ratchet turns one way: when a
listed function or module improves, the check fails until ``--update`` writes the lower value (or drops the
entry once it is under the limit), so headroom that an improvement made cannot be spent again later.
``--update`` refuses to raise anything. A rise that review accepts is recorded with ``--rebaseline``, which
also writes the first baseline, and shows up as a diff of the JSON file.

Exit status: 0 within the baseline, 1 when something grew or the baseline is behind the code, 2 when the
measurement or the baseline cannot be trusted (ruff missing or failing, an unreadable file, a malformed
baseline).
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, NamedTuple

from shadowscan.utils.safe_json import strict_json_loads

ROOT = Path(__file__).resolve().parents[1]
BASELINE = "tools/complexity_baseline.json"
# What `make lint` checks, less tests/: the shipped package and the tooling around it. Ruff's own
# exclusions in pyproject.toml still apply, so the sample repositories under
# benchmarks/shadowbench/estate/artifacts do not count.
SOURCE_ROOTS = ("shadowscan", "tools", "benchmarks")
MODULE_ROOTS = ("shadowscan",)
MAX_FUNCTION_COMPLEXITY = 20
MAX_MODULE_LINES = 2000
SCHEMA = 1
RUFF_TIMEOUT_SECONDS = 300

_TOO_COMPLEX = re.compile(r"`[^`]+` is too complex \((\d+) > (\d+)\)")
_RUFF_VERSION = re.compile(r"ruff (\S+)")


class MeasurementError(ValueError):
    """The measurement or the baseline cannot be trusted; the gate fails closed on it."""


class Baseline(NamedTuple):
    ruff: str
    functions: dict[str, int]
    modules: dict[str, int]


def _run_ruff(root: Path, *arguments: str) -> str:
    """Standard output of ruff from the interpreter running the gate, run inside ``root``."""
    try:
        done = subprocess.run(
            [sys.executable, "-m", "ruff", *arguments],
            cwd=root,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=RUFF_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise MeasurementError(f"could not run ruff: {type(exc).__name__}") from None
    if done.returncode != 0:
        last = (done.stderr.strip().splitlines() or ["no error output"])[-1]
        raise MeasurementError(f"ruff exited with status {done.returncode}: {last[:200]}")
    return done.stdout


def ruff_version(root: Path) -> str:
    match = _RUFF_VERSION.fullmatch(_run_ruff(root, "--version").strip())
    if match is None:
        raise MeasurementError("ruff --version printed an unexpected line")
    return match.group(1)


def _relative(name: str, root: Path) -> str:
    path = Path(name)
    if not path.is_absolute():
        path = root / path
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        raise MeasurementError("ruff named a file outside the checkout") from None


def _qualified_names(path: Path) -> dict[int, str]:
    """The qualified name of every function in a file, by the line its ``def`` starts on.

    Nested functions read ``outer.<locals>.inner``, as ``__qualname__`` does. A name that repeats in one
    file (a conditional redefinition, say) keeps its first spelling and the later ones get ``#2``, ``#3``,
    in source order, so each definition has a ceiling of its own.
    """
    try:
        tree = ast.parse(path.read_bytes(), filename=str(path))
    except (OSError, SyntaxError, ValueError, RecursionError) as exc:
        raise MeasurementError(f"{path.name}: cannot parse the file ({type(exc).__name__})") from None
    starts: list[tuple[int, str]] = []
    pending: list[tuple[ast.AST, str]] = [(tree, "")]
    while pending:
        node, prefix = pending.pop()
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef):
                qualname = f"{prefix}{child.name}"
                starts.append((child.lineno, qualname))
                pending.append((child, f"{qualname}.<locals>."))
            elif isinstance(child, ast.ClassDef):
                pending.append((child, f"{prefix}{child.name}."))
            elif not isinstance(child, ast.expr):
                pending.append((child, prefix))
    names: dict[int, str] = {}
    seen: dict[str, int] = {}
    for line, qualname in sorted(starts):
        seen[qualname] = seen.get(qualname, 0) + 1
        names[line] = qualname if seen[qualname] == 1 else f"{qualname}#{seen[qualname]}"
    return names


def _finding(row: Any, root: Path) -> tuple[str, int, int]:
    """Path, line and complexity of one ruff ``C901`` finding; anything else is an error, not a skip."""
    location = row.get("location") if isinstance(row, dict) else None
    if (
        not isinstance(row, dict)
        or row.get("code") != "C901"
        or not isinstance(row.get("filename"), str)
        or not isinstance(row.get("message"), str)
        or not isinstance(location, dict)
        or type(location.get("row")) is not int
    ):
        raise MeasurementError("ruff printed a finding that is not a C901 complexity finding")
    match = _TOO_COMPLEX.fullmatch(row["message"])
    if match is None or int(match.group(2)) != MAX_FUNCTION_COMPLEXITY:
        raise MeasurementError("ruff printed a complexity message in a form this gate does not know")
    return _relative(row["filename"], root), location["row"], int(match.group(1))


def measure_functions(root: Path) -> dict[str, int]:
    """Complexity of every function above the limit, keyed ``path::qualified.name``."""
    output = _run_ruff(
        root,
        "check",
        "--no-cache",
        "--exit-zero",
        "--ignore-noqa",
        "--select",
        "C901",
        "--config",
        f"lint.mccabe.max-complexity = {MAX_FUNCTION_COMPLEXITY}",
        "--output-format",
        "json",
        *SOURCE_ROOTS,
    )
    try:
        rows = json.loads(output)
    except ValueError:
        raise MeasurementError("ruff did not print JSON") from None
    if not isinstance(rows, list):
        raise MeasurementError("ruff printed JSON that is not a list of findings")
    names: dict[str, dict[int, str]] = {}
    measured: dict[str, int] = {}
    for row in rows:
        path, line, complexity = _finding(row, root)
        if path not in names:
            names[path] = _qualified_names(root / path)
        if line not in names[path]:
            raise MeasurementError(f"{path}:{line}: no function starts on the line ruff reported")
        measured[f"{path}::{names[path][line]}"] = complexity
    return measured


def measure_modules(root: Path) -> dict[str, int]:
    """Line count of every module above the limit, keyed by path; the files are the ones ruff would lint."""
    modules: dict[str, int] = {}
    for name in _run_ruff(root, "check", "--no-cache", "--show-files", *MODULE_ROOTS).splitlines():
        if not name.endswith(".py"):
            continue
        path = _relative(name, root)
        try:
            lines = len((root / path).read_bytes().splitlines())
        except OSError as exc:
            raise MeasurementError(f"{path}: cannot read the file ({type(exc).__name__})") from None
        if lines > MAX_MODULE_LINES:
            modules[path] = lines
    return modules


def load_baseline(path: Path) -> Baseline:
    """The baseline, validated: a malformed file is an error, never an empty or a generous baseline."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise MeasurementError(
            f"{BASELINE} does not exist; write the first one with "
            "`python -m tools.complexity_gate --rebaseline`"
        ) from None
    data = strict_json_loads(text)
    if not isinstance(data, dict) or set(data) != {"schema", "ruff", "functions", "modules"}:
        raise MeasurementError(f"{BASELINE} must be an object with schema, ruff, functions and modules")
    if type(data["schema"]) is not int or data["schema"] != SCHEMA or not isinstance(data["ruff"], str):
        raise MeasurementError(f"{BASELINE} has an unsupported schema or ruff version")
    for name in ("functions", "modules"):
        table = data[name]
        if not isinstance(table, dict) or not all(
            isinstance(key, str) and type(value) is int and value > 0 for key, value in table.items()
        ):
            raise MeasurementError(f"{BASELINE}: {name} must map names to positive whole numbers")
    return Baseline(data["ruff"], data["functions"], data["modules"])


def write_baseline(path: Path, functions: Mapping[str, int], modules: Mapping[str, int], ruff: str) -> None:
    payload = {
        "schema": SCHEMA,
        "ruff": ruff,
        "functions": dict(sorted(functions.items())),
        "modules": dict(sorted(modules.items())),
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def compare(
    measured: Mapping[str, int],
    ceilings: Mapping[str, int],
    limit: int,
    describe: Callable[[int], str],
) -> tuple[list[str], list[str]]:
    """What grew past the baseline, and what the baseline still allows that the code no longer needs."""
    grown: list[str] = []
    slack: list[str] = []
    for key in sorted(measured.keys() | ceilings.keys()):
        now, allowed = measured.get(key), ceilings.get(key)
        if now is not None and allowed is None:
            grown.append(f"{key}: {describe(now)}, over the limit of {limit} and not in the baseline")
        elif now is not None and allowed is not None and now > allowed:
            grown.append(f"{key}: {describe(now)}, up from {allowed} in the baseline")
        elif now is None and allowed is not None:
            slack.append(
                f"{key}: now within the limit of {limit} (or gone), but the baseline still allows {allowed}"
            )
        elif now is not None and allowed is not None and now < allowed:
            slack.append(f"{key}: now {describe(now)}, but the baseline still allows {allowed}")
    return grown, slack


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m tools.complexity_gate",
        description=(
            f"Fail when a function (ruff C901 above {MAX_FUNCTION_COMPLEXITY}) or a module (above "
            f"{MAX_MODULE_LINES} lines) grows past {BASELINE}, or when the baseline allows more than the "
            "code has."
        ),
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--update",
        action="store_true",
        help="lower the baseline to the current code; refuses to raise or add any entry",
    )
    mode.add_argument(
        "--rebaseline",
        action="store_true",
        help="write the current measurements as the baseline, rises included (the first baseline, or a "
        "rise that review accepts)",
    )
    return parser


def _differences(
    functions: Mapping[str, int], modules: Mapping[str, int], baseline: Baseline
) -> tuple[list[str], list[str]]:
    grown_functions, slack_functions = compare(
        functions, baseline.functions, MAX_FUNCTION_COMPLEXITY, lambda value: f"complexity {value}"
    )
    grown_modules, slack_modules = compare(
        modules, baseline.modules, MAX_MODULE_LINES, lambda value: f"{value} lines"
    )
    return grown_functions + grown_modules, slack_functions + slack_modules


def _complain(title: str, lines: list[str], advice: str) -> None:
    print(f"{title}\n" + "\n".join(f"  {line}" for line in lines) + f"\n{advice}", file=sys.stderr)


def _enforce(grown: list[str], slack: list[str], baseline_ruff: str, version: str) -> int:
    """Report everything that keeps the code from matching the baseline; 1 when there is anything."""
    if grown:
        _complain(
            f"Grew past {BASELINE}:",
            grown,
            "Split the function or module instead of raising the number. A rise that review accepts is "
            "recorded with `python -m tools.complexity_gate --rebaseline`.",
        )
    if slack:
        _complain(
            f"{BASELINE} allows more than the code has:",
            slack,
            "Run `python -m tools.complexity_gate --update` and commit the lower baseline, so the room this "
            "improvement made cannot be spent again.",
        )
    if baseline_ruff != version:
        print(
            f"The baseline was written with ruff {baseline_ruff} and this is ruff {version}; complexity "
            "counting can differ between ruff versions.",
            file=sys.stderr,
        )
    return 1


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    path = ROOT / BASELINE
    try:
        functions, modules, version = measure_functions(ROOT), measure_modules(ROOT), ruff_version(ROOT)
        if args.rebaseline:
            write_baseline(path, functions, modules, version)
            print(f"Wrote {BASELINE}: {len(functions)} functions and {len(modules)} modules over their limit")
            return 0
        baseline = load_baseline(path)
        grown, slack = _differences(functions, modules, baseline)
        if args.update and not grown:
            write_baseline(path, functions, modules, version)
            print(f"Lowered {BASELINE}: {len(slack)} entries tightened or dropped")
            return 0
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        print(f"complexity gate: {exc}", file=sys.stderr)
        return 2
    if args.update:
        _complain(
            "Refusing to raise the baseline:",
            grown,
            "Split the function or module instead. A rise that review accepts is recorded with "
            "`python -m tools.complexity_gate --rebaseline`.",
        )
        return 1
    if grown or slack:
        return _enforce(grown, slack, baseline.ruff, version)
    largest = max(functions, key=lambda key: (functions[key], key), default=None)
    print(
        f"Checked {len(functions)} functions over complexity {MAX_FUNCTION_COMPLEXITY} and {len(modules)} "
        f"modules over {MAX_MODULE_LINES} lines against {BASELINE}: none grew"
        + (f" (most complex: {largest} at {functions[largest]})" if largest else "")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
