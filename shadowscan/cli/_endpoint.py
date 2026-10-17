"""endpoint command."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import click
from rich.text import Text

# Late-bound through the package: tests patch ``shadowscan.cli.<name>``, and the commands must see the
# patched object, as they did when this was a single module.
import shadowscan.cli as _cli_pkg
from shadowscan.cli import ScanOptions, err_console, main, scan_options
from shadowscan.config import ConnectorSpec
from shadowscan.endpoint import (
    appdata_outside_profile,
    default_label,
    describe,
    endpoint_include,
    endpoint_paths,
)
from shadowscan.models import ScanStats, now_iso
from shadowscan.utils.output import encodable_text, terminal_text


# ----------------------------------------------------------------- endpoint
@main.command()
@click.option(
    "--home",
    "home_dir",
    type=click.Path(exists=True, file_okay=False),
    default=None,
    help="profile directory to inspect (default: the current user's home)",
)
@click.option(
    "--label", default=None, help="resource prefix for every finding (default: endpoint:<hostname>)"
)
@click.option(
    "--list",
    "list_only",
    is_flag=True,
    help="print the known locations that exist under the profile and exit without scanning",
)
@scan_options
def endpoint(home_dir: str | None, label: str | None, list_only: bool, opts: ScanOptions) -> None:
    """Scan this workstation's AI client configuration at its well-known locations: MCP client
    configs, coding-agent settings, user-level skills, rules and instruction files."""
    # HOME is operator-trusted like --home: resolving it lets a profile below a
    # linked /home (FreeBSD, image-based Fedora) pass the scan root link policy.
    home = Path(home_dir).resolve() if home_dir else Path.home().resolve()
    discovery_errors: list[str] = []
    found = endpoint_paths(home, errors=discovery_errors)
    if not home_dir and appdata_outside_profile(home):
        # Folder redirection: Windows clients keep their configuration below
        # %APPDATA%, which the profile walk does not reach. An empty result
        # there would be a gap, not an absence. --home ignores %APPDATA%,
        # which belongs to the scanning user rather than the inspected profile.
        discovery_errors.append(
            "APPDATA is redirected outside the profile's AppData/Roaming; Windows client "
            "configuration there is not scanned"
        )
    if list_only:
        for line in describe(found, home):
            click.echo(encodable_text(terminal_text(line)))
        for error in discovery_errors:
            err_console.print(Text(terminal_text(error)))
        if not found and not discovery_errors:
            err_console.print(
                Text(terminal_text(f"no known AI client configuration locations exist under {home}"))
            )
        if discovery_errors:
            raise click.exceptions.Exit(3)
        return
    # A location that could not be inspected safely makes the scan incomplete
    # (exit 3), but every other location is still read. Nothing to read is a
    # complete, empty result, not a setup failure: the profile simply has no
    # AI client wired in. The note stays in the report.
    now = now_iso()
    discovery = ScanStats(connector="engine.endpoint", started_at=now, finished_at=now)
    if discovery_errors:
        discovery.errors.extend(discovery_errors)
        discovery.incomplete = True
    elif not found:
        discovery.warnings.append(f"no known AI client configuration locations exist under {home}")
    # The profile is walked only along the known locations, so the relative
    # paths keep the `.claude/`, `.cursor/` context the file signatures expect
    # and nothing else in the profile is read.
    config: dict[str, Any] = {
        "paths": [str(home)],
        "include": endpoint_include(),
        "label": label or default_label(),
        "scan_secrets": True,
    }
    extra = [discovery] if discovery.errors or discovery.warnings else None
    _cli_pkg._run_scan(
        opts.config([ConnectorSpec(name="code.filesystem", config=config)]), opts, extra_stats=extra
    )
