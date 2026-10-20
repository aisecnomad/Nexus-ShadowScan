"""The public contracts docs/reference/stability.md freezes for 1.0 cannot drift unnoticed.

``docs/reference/cli-surface.json`` records every command, option, alias and
documented exit code; ``docs/reference/python-api.json`` records every public
module's ``__all__`` with signatures. Both are generated from the code, and a
change to either is a contract change the pull request classifies as additive
or breaking.
"""

from __future__ import annotations

import ast
import importlib
import inspect
import json

import pytest

from tools import cli_surface, public_api
from tools.snapshot_json import drift, drift_report, dumps


def test_cli_surface_snapshot_is_current() -> None:
    message = cli_surface.stale_message(cli_surface.SNAPSHOT.read_text(encoding="utf-8"))
    assert message is None, message


# The suite raises the matcher's budget defaults for ordinary tests; the snapshot records the shipped ones.
@pytest.mark.production_budgets
def test_python_api_snapshot_is_current() -> None:
    message = public_api.stale_message(public_api.SNAPSHOT.read_text(encoding="utf-8"))
    assert message is None, message


def test_every_exit_code_the_cli_can_return_is_documented_and_every_documented_one_is_used() -> None:
    documented = {int(code) for code in cli_surface.documented_exit_codes()}
    assert documented == {0, 1, 2, 3}
    used = cli_surface.code_exit_codes()
    assert used <= documented, (
        f"exit codes in shadowscan/cli/ not in docs/reference/cli.md: {used - documented}"
    )
    assert documented <= used, f"documented exit codes no CLI code path returns: {documented - used}"


def test_exit_code_table_is_read_from_its_own_section_only() -> None:
    page = (
        "## Output formats\n\n| **9** | not an exit code |\n\n"
        "## Exit codes\n\n| Exit | Meaning |\n|---|---|\n| **0** | Passed |\n| **3** | Incomplete |\n\n"
        "## Next\n\n| **7** | elsewhere |\n"
    )
    assert cli_surface.documented_exit_codes(page) == {"0": "Passed", "3": "Incomplete"}
    with pytest.raises(ValueError, match="no '## Exit codes' section"):
        cli_surface.documented_exit_codes("# Commands\n")


def test_exit_code_scan_reads_every_way_the_cli_exits(tmp_path) -> None:
    (tmp_path / "a.py").write_text(
        "import sys, click\n"
        "def _exit_code(result):\n    return 3 if result else 0\n"
        "class E(click.UsageError):\n    exit_code = 1\n"
        "def f(x):\n    raise click.exceptions.Exit(2 if x else 0)\n"
        "def g():\n    sys.exit(4)\n",
        encoding="utf-8",
    )
    assert cli_surface.code_exit_codes(tmp_path) == {0, 1, 2, 3, 4}


def test_deprecated_aliases_are_part_of_the_snapshot() -> None:
    flat = cli_surface.flatten(json.loads(cli_surface.SNAPSHOT.read_text(encoding="utf-8")))
    timeout = flat["shadowscan scan --connector-timeout-seconds"]
    assert timeout["opts"] == ["--connector-timeout-seconds", "--connector-timeout"]
    assert timeout["deprecated_aliases"] == ["--connector-timeout"]


def test_every_public_module_declares_its_public_names() -> None:
    missing = [
        name for name in public_api.public_modules() if not hasattr(importlib.import_module(name), "__all__")
    ]
    assert not missing, f"public modules without __all__ (docs/reference/stability.md): {missing}"


def test_public_modules_define_no_undeclared_public_names() -> None:
    """A top-level definition without an underscore is listed in ``__all__``, or it reads as public by accident."""
    problems = []
    for name in public_api.public_modules():
        module = importlib.import_module(name)
        declared = set(module.__all__)
        problems += [
            f"{name}.{defined}"
            for defined in public_api.defined_public_names(module)
            if defined not in declared
        ]
        problems += [f"{name}.{listed} (not defined)" for listed in declared if not hasattr(module, listed)]
    assert not problems, (
        "add these names to the module's __all__ and run `make python-api`, or prefix them with an "
        f"underscore if they are internal: {problems}"
    )


def test_the_api_snapshot_covers_the_api_reference_pages() -> None:
    modules = set(json.loads(public_api.SNAPSHOT.read_text(encoding="utf-8"))["modules"])
    assert modules == set(public_api.public_modules())
    assert {
        "shadowscan",
        "shadowscan.connectors",
        "shadowscan.connectors.base",
        "shadowscan.models",
    } <= modules
    # Underscore modules are internal whatever the reference pages say.
    assert not [name for name in modules if any(part.startswith("_") for part in name.split("."))]


def _signature_of(source: str) -> str | None:
    namespace: dict[str, object] = {}
    exec(compile("from __future__ import annotations\n" + source, "<test>", "exec"), namespace)
    return public_api._signature(namespace["f"])


@pytest.mark.parametrize(
    ("source", "rendered"),
    [
        (
            "def f(a, /, b: int = 1, *, c: str | None = None) -> None: ...",
            "(a, /, b: int = 1, *, c: str | None = None) -> None",
        ),
        (
            "def f(*args: int, key=frozenset({'b', 'a'}), **kw: str): ...",
            "(*args: int, key=frozenset({'a', 'b'}), **kw: str)",
        ),
        ("def f(a, b, /): ...", "(a, b, /)"),
        ("def f(x=object()): ...", "(x=<object>)"),
        ("def f(x=(1,), y={'b': 2, 'a': 1}): ...", "(x=(1,), y={'a': 1, 'b': 2})"),
    ],
)
def test_signatures_render_without_hash_seeds_or_addresses(source: str, rendered: str) -> None:
    assert _signature_of(source) == rendered


def test_drift_report_classifies_removals_as_breaking_and_additions_as_additive() -> None:
    changes = drift({"a": 1, "b": 2, "c": 3}, {"b": 2, "c": 4, "d": 5})
    assert changes == {"added": ["d"], "removed": ["a"], "changed": ["c"]}
    report = drift_report("x.json", "make x", changes)
    assert "removed (breaking):\n  a" in report and "added (additive):\n  d" in report
    assert "make x" in report and "stability.md" in report


def test_snapshot_json_keeps_leaf_objects_on_one_line() -> None:
    text = dumps({"a": [{"leaf": 1, "x": [1, 2]}, {"b": {}}]}, leaf=lambda item: "leaf" in item)
    assert text == '{\n  "a": [\n    {"leaf": 1, "x": [1, 2]},\n    {\n      "b": {}\n    }\n  ]\n}\n'
    assert json.loads(text) == {"a": [{"leaf": 1, "x": [1, 2]}, {"b": {}}]}


def test_internal_cli_modules_are_not_public() -> None:
    """``shadowscan.cli`` and its ``_*`` command modules are internal: the command line is the contract."""
    modules = set(public_api.public_modules())
    assert "shadowscan.cli" not in modules
    tree = ast.parse(inspect.getsource(importlib.import_module("shadowscan.cli")))
    registered = [
        alias.name
        for node in tree.body
        if isinstance(node, ast.ImportFrom) and node.module == "shadowscan.cli"
        for alias in node.names
    ]
    assert registered and all(name.startswith("_") for name in registered)
