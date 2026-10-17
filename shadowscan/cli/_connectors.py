"""connectors command."""

from __future__ import annotations

import json
from typing import Any

import click
from rich.table import Table
from rich.text import Text

import shadowscan.cli as _cli
from shadowscan.cli import main
from shadowscan.connectors import (
    builtin_connector_names,
    connectors_for_surface,
    get_connector_class,
    plugin_registry_errors,
)
from shadowscan.models import Surface


# ---------------------------------------------------------------- connectors
@main.command("connectors")
@click.option("--surface", type=click.Choice([s.value for s in Surface]), help="filter by surface")
@click.option("--json", "as_json", is_flag=True, help="print JSON instead of the human-readable output")
def list_connectors(surface: str | None, as_json: bool) -> None:
    """List available connectors and their configuration keys."""
    names = connectors_for_surface(surface) if surface else sorted(_cli.available_connectors())
    rows: list[dict[str, Any]] = []
    for n in names:
        if n not in builtin_connector_names():
            rows.append(
                {
                    "name": n,
                    "surface": n.split(".")[0],
                    "description": "Third-party plugin (not loaded; explicitly allow before use)",
                    "config": {},
                    "requires": [],
                    "offline": "unknown",
                    "enabled": False,
                }
            )
            continue
        try:
            cls = get_connector_class(n)
        except Exception as exc:  # noqa: BLE001 - a connector that cannot load is listed with its error
            rows.append({"name": n, "error": str(exc)})
            continue
        config = dict(cls.config_keys)
        for key, text in cls.shared_config_keys.items():
            config.setdefault(key, text)
        rows.append(
            {
                "name": n,
                "surface": cls.surface.value,
                "description": cls.description,
                "config": config,
                "requires": cls.requires,
                "offline": cls.offline_formats,
            }
        )
    for problem in plugin_registry_errors():
        _cli.err_console.print(Text(f"warning: plugin registry: {problem}", style="yellow"))
    if as_json:
        click.echo(json.dumps(rows, indent=2))
        return
    table = Table(title="ShadowScan connectors", header_style="bold")
    table.add_column("Connector", no_wrap=True)
    table.add_column("Surface", no_wrap=True)
    table.add_column("Description", ratio=2)
    table.add_column("Config keys", ratio=2)
    for r in rows:
        if "error" in r:
            table.add_row(Text(r["name"]), "?", Text(r["error"], style="red"), "")
            continue
        # Build styled Text directly: key descriptions are rendered literally,
        # never parsed as Rich markup.
        keys = Text()
        for number, (key, description) in enumerate(r["config"].items()):
            if number:
                keys.append("\n")
            keys.append(str(key), style="bold")
            keys.append(f": {description}")
        description = Text(r["description"])
        if r["requires"]:
            description.append("\n")
            description.append(f"requires: {', '.join(r['requires'])}", style="dim")
        table.add_row(Text(r["name"]), Text(str(r["surface"])), description, keys)
    _cli.console.print(table)
