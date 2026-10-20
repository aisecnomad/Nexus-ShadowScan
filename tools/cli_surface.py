"""Snapshot the command-line surface of ``shadowscan`` as deterministic JSON.

The CLI is a public contract (``docs/reference/stability.md``): command names,
their parameters and the exit codes scripts and CI gates read. This module
walks the Click command tree of ``shadowscan.cli:main`` and writes what a
caller depends on to ``docs/reference/cli-surface.json``; a test fails when
the committed snapshot differs from the code::

    python -m tools.cli_surface          # rewrite the snapshot (make cli-surface)
    python -m tools.cli_surface --check  # exit 1 when it is stale

Help text is left out on purpose: rewording an option's help is not a
contract change. Defaults are kept only when they are plain values.
The exit codes come from the table under "Exit codes" in
``docs/reference/cli.md``, the page operators read; :func:`code_exit_codes`
lists the codes the CLI source can produce so a test can hold the two together.
"""

from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path
from typing import Any

import click

from tools.snapshot_json import drift, drift_report, dumps

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = ROOT / "docs" / "reference" / "cli-surface.json"
CLI_REFERENCE = ROOT / "docs" / "reference" / "cli.md"
CLI_PACKAGE = ROOT / "shadowscan" / "cli"
SCHEMA = "shadowscan.cli-surface/v1"

# "--connector-timeout is a deprecated alias" in an option's help names an alias kept for
# compatibility; the snapshot lists it so removing it reads as the breaking change it is.
_DEPRECATED_ALIAS = re.compile(r"(--[a-z0-9][a-z0-9-]*) is a deprecated alias")
_EXIT_ROW = re.compile(r"^\|\s*\*\*(\d+)\*\*\s*\|\s*(.+?)\s*\|\s*$")


def _plain_default(value: Any) -> Any:
    """A default as JSON when it is a plain value; Click's unset sentinel and callables are None."""
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, tuple | list) and all(isinstance(item, bool | int | float | str) for item in value):
        return list(value)
    return None


def _type(param: click.Parameter) -> dict[str, Any]:
    kind = param.type
    described: dict[str, Any] = {"name": kind.name}
    if isinstance(kind, click.Choice):
        described["choices"] = [str(choice) for choice in kind.choices]
    elif isinstance(kind, click.IntRange | click.FloatRange):
        described["min"] = kind.min
        described["max"] = kind.max
    elif isinstance(kind, click.Path):
        described["exists"] = kind.exists
        described["file_okay"] = kind.file_okay
        described["dir_okay"] = kind.dir_okay
    return described


def _parameter(param: click.Parameter) -> dict[str, Any]:
    option = isinstance(param, click.Option)
    is_flag = bool(option and param.is_flag)  # type: ignore[attr-defined]
    default = _plain_default(param.default)
    if is_flag and default is None and not param.secondary_opts:
        default = False  # a plain flag Click leaves unset reads as off
    help_text = (param.help or "") if isinstance(param, click.Option) else ""
    envvar = param.envvar
    return {
        "name": param.name,
        "param_type": "option" if option else "argument",
        "opts": list(param.opts),
        "secondary_opts": list(param.secondary_opts),
        "type": _type(param),
        "nargs": param.nargs,
        "multiple": param.multiple,
        "required": param.required,
        "is_flag": is_flag,
        "count": bool(option and param.count),  # type: ignore[attr-defined]
        "default": default,
        "envvar": list(envvar) if isinstance(envvar, list | tuple) else envvar,
        "hidden": bool(option and param.hidden),  # type: ignore[attr-defined]
        "deprecated_aliases": sorted(
            alias for alias in _DEPRECATED_ALIAS.findall(help_text) if alias in param.opts
        ),
    }


def _command(name: str, command: click.Command) -> dict[str, Any]:
    described: dict[str, Any] = {
        "name": name,
        "kind": "group" if isinstance(command, click.Group) else "command",
        "hidden": command.hidden,
        "deprecated": bool(command.deprecated),
        "params": [_parameter(param) for param in command.params],
    }
    if isinstance(command, click.Group):
        described["commands"] = [
            _command(child, command.commands[child]) for child in sorted(command.commands)
        ]
    return described


def documented_exit_codes(text: str | None = None) -> dict[str, str]:
    """``{code: meaning}`` from the "Exit codes" table of the command reference."""
    page = CLI_REFERENCE.read_text(encoding="utf-8") if text is None else text
    section = page.split("\n## Exit codes\n", 1)
    if len(section) != 2:
        raise ValueError(f"{CLI_REFERENCE.name} has no '## Exit codes' section")
    body = section[1].split("\n## ", 1)[0]
    codes = {match.group(1): match.group(2) for line in body.splitlines() if (match := _EXIT_ROW.match(line))}
    if not codes:
        raise ValueError(f"the '## Exit codes' section of {CLI_REFERENCE.name} has no table rows")
    return dict(sorted(codes.items(), key=lambda item: int(item[0])))


def _integer_literals(node: ast.AST) -> set[int]:
    return {
        child.value
        for child in ast.walk(node)
        if isinstance(child, ast.Constant) and type(child.value) is int
    }


def _is_exit_call(func: ast.expr) -> bool:
    """``sys.exit``, ``click.exceptions.Exit``, ``os._exit`` and a bare ``Exit``."""
    if isinstance(func, ast.Attribute):
        return func.attr in {"exit", "_exit", "Exit"}
    return isinstance(func, ast.Name) and func.id == "Exit"


def code_exit_codes(package: Path = CLI_PACKAGE) -> set[int]:
    """Every integer literal the CLI source passes to an exit call or declares as an exit code.

    Reads ``sys.exit(N)``, ``raise click.exceptions.Exit(N if ... else M)``, an
    ``exit_code = N`` class attribute and the ``return N`` of ``_exit_code``. A
    code computed elsewhere is not seen; the test holds these to the documented table.
    """
    found: set[int] = set()
    for path in sorted(package.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _is_exit_call(node.func):
                for argument in node.args:
                    found |= _integer_literals(argument)
            elif isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == "exit_code" for target in node.targets
            ):
                found |= _integer_literals(node.value)
            elif isinstance(node, ast.FunctionDef) and node.name == "_exit_code":
                for child in ast.walk(node):
                    if isinstance(child, ast.Return) and child.value is not None:
                        found |= _integer_literals(child.value)
    return found


def snapshot() -> dict[str, Any]:
    """The CLI surface as a JSON-ready mapping, with stable ordering."""
    from shadowscan.cli import main

    return {
        "schema": SCHEMA,
        "generated_by": "python -m tools.cli_surface",
        "entry_point": "shadowscan = shadowscan.cli:main",
        "exit_codes": documented_exit_codes(),
        "root": _command("shadowscan", main),
    }


def render(data: dict[str, Any] | None = None) -> str:
    """The snapshot as text: indented, with each parameter on one line so a diff names it."""
    return dumps(data if data is not None else snapshot(), leaf=lambda item: "param_type" in item)


def flatten(data: dict[str, Any]) -> dict[str, Any]:
    """Command paths, ``command --option`` parameters and ``exit N`` keys, so a drift report names them."""
    flat: dict[str, Any] = {f"exit {code}": meaning for code, meaning in data.get("exit_codes", {}).items()}

    def visit(command: dict[str, Any], path: str) -> None:
        flat[path] = {key: value for key, value in command.items() if key not in {"params", "commands"}}
        for param in command.get("params", []):
            label = param["opts"][0] if param["param_type"] == "option" else str(param["name"]).upper()
            flat[f"{path} {label}"] = param
        for child in command.get("commands", []):
            visit(child, f"{path} {child['name']}")

    if isinstance(data.get("root"), dict):
        visit(data["root"], data["root"]["name"])
    return flat


def stale_message(committed: str) -> str | None:
    """None when ``committed`` is the current snapshot, else the drift report to fail with."""
    current = snapshot()
    if committed == render(current):
        return None
    try:
        old = json.loads(committed)
    except ValueError:
        old = {}
    changes = drift(flatten(old if isinstance(old, dict) else {}), flatten(current))
    return drift_report(SNAPSHOT.relative_to(ROOT).as_posix(), "make cli-surface", changes)


def main(argv: list[str]) -> int:
    if argv not in ([], ["--check"]):
        print("usage: python -m tools.cli_surface [--check]", file=sys.stderr)
        return 2
    if argv == ["--check"]:
        committed = SNAPSHOT.read_text(encoding="utf-8") if SNAPSHOT.is_file() else ""
        message = stale_message(committed)
        if message is not None:
            print(message, file=sys.stderr)
            return 1
        return 0
    SNAPSHOT.write_text(render(), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
