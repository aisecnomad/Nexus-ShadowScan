"""The CLI package keeps ``shadowscan.cli`` as the one place a name is replaced.

``shadowscan/cli.py`` became the ``shadowscan.cli`` package, with each group of
commands in its own module. Tests and embedding callers replace the scan
runner, the consoles and connector discovery on ``shadowscan.cli``; a command
module that bound one of those names when it was imported would keep the
original, and a test replacing it would pass through a different code path
than the one it names. Every command therefore looks these names up on the
package when it runs.
"""

from __future__ import annotations

import ast
import io
from pathlib import Path

import pytest
from click.testing import CliRunner
from rich.console import Console

import shadowscan.cli as cli
from shadowscan.cli import main

# The names tests and callers replace on shadowscan.cli.
SEAMS = frozenset(
    {"console", "err_console", "_run_scan", "_emit", "available_connectors", "render_dashboard"}
)
COMMAND_MODULES = sorted(
    path
    for path in Path(cli.__file__).parent.glob("_*.py")
    if path.name not in {"__init__.py", "__main__.py"}
)


def test_command_modules_never_bind_a_seam_at_import():
    assert COMMAND_MODULES
    bound = []
    for path in COMMAND_MODULES:
        for node in ast.parse(path.read_text(encoding="utf-8")).body:
            if isinstance(node, ast.ImportFrom):
                bound.extend(
                    f"{path.name}: {alias.name}"
                    for alias in node.names
                    if (alias.asname or alias.name) in SEAMS
                )
    assert not bound, "look these up as _cli.<name> at call time:\n  " + "\n  ".join(bound)


def test_replaced_scan_runner_receives_a_command_from_a_submodule(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "_run_scan", lambda config, opts: calls.append(config))
    result = CliRunner().invoke(main, ["jwt", "--file", "/dev/null"])
    assert result.exit_code == 0, result.output
    [config] = calls
    assert [spec.name for spec in config.connectors] == ["identity.jwt"]


def test_replaced_connector_discovery_is_what_run_consults(monkeypatch):
    monkeypatch.setattr(cli, "available_connectors", lambda: {})
    result = CliRunner().invoke(main, ["run", "code.filesystem"])
    assert result.exit_code == 1  # a usage error, as the README's exit codes say
    assert "unknown connector 'code.filesystem'" in result.output


def test_replaced_console_receives_output_from_a_submodule(monkeypatch):
    output = io.StringIO()
    monkeypatch.setattr(cli, "console", Console(file=output, width=200))
    result = CliRunner().invoke(main, ["connectors", "--surface", "identity"])
    assert result.exit_code == 0, result.output
    assert "identity.okta" in output.getvalue()


# Every click command the single cli.py module defined, by the name it had there.
_COMMANDS = (
    "code",
    "controls_command",
    "dashboard_command",
    "diff",
    "endpoint",
    "gateway",
    "inventory",
    "inventory_check",
    "inventory_stubs",
    "jwt",
    "list_connectors",
    "mcp_registry",
    "mcp_registry_snapshot",
    "merge_command",
    "run",
    "scan",
    "signatures",
    "signatures_list",
    "signatures_show",
    "signatures_test",
)


@pytest.mark.parametrize("name", _COMMANDS)
def test_each_command_stays_importable_from_the_package(name: str) -> None:
    import click

    import shadowscan.cli as cli

    command = getattr(cli, name)
    assert isinstance(command, click.Command)
    # It is the command the group runs, not a copy.
    registered = {id(c) for c in cli.main.commands.values()}
    for group in (c for c in cli.main.commands.values() if isinstance(c, click.Group)):
        registered |= {id(c) for c in group.commands.values()}
    assert id(command) in registered
