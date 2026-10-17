"""inventory group (check, stubs)."""

from __future__ import annotations

import hashlib

import click
import yaml
from rich.table import Table
from rich.text import Text

from shadowscan.cli import LEVELS, _load_report, console, err_console, main
from shadowscan.errors import SetupError
from shadowscan.models import Finding, Kind
from shadowscan.registry import Inventory, card_stub_for
from shadowscan.utils.output import prepare_private_directory, terminal_text, write_private_text


# ----------------------------------------------------------------- inventory
@main.group()
def inventory() -> None:
    """Work with the sanctioned agent inventory (Agent Capability Cards)."""


@inventory.command("check")
@click.argument("paths", nargs=-1, required=True)
def inventory_check(paths: tuple[str, ...]) -> None:
    """Validate inventory files and list the registered agents."""
    try:
        inv = Inventory.load(list(paths))
    except SetupError as exc:
        raise click.ClickException(str(exc)) from None
    except (ValueError, TypeError, OSError, yaml.YAMLError):
        raise click.ClickException(
            "could not load inventory; check file access and document structure"
        ) from None
    for link in inv.skipped_links:
        message = f"warning: inventory {link}: symbolic link skipped (links are not followed)"
        err_console.print(Text(terminal_text(message), style="yellow"))
    for notice in inv.autonomy_warnings():
        err_console.print(Text(terminal_text(f"warning: {notice}"), style="yellow"))
    table = Table(title=f"{len(inv)} registered agents", header_style="bold")
    table.add_column("Agent id")
    table.add_column("Name")
    table.add_column("Owner")
    table.add_column("Resources")
    table.add_column("EU AI Act class (declared)")
    table.add_column("Source")
    for e in inv.entries:
        # Inventory cards come from a scanned tree or an operator path: strip terminal control
        # sequences (ESC/CSI/OSC, bidi overrides) as well as Rich markup from every field.
        if e.resources:
            resources = Text("\n".join(terminal_text(r) for r in e.resources))
        else:
            resources = Text("none (suggestions only)", style="dim")
        table.add_row(
            Text(terminal_text(e.agent_id)),
            Text(terminal_text(e.name or "")),
            Text(terminal_text(e.owner or "")),
            resources,
            Text(terminal_text((e.governance or {}).get("eu_ai_act_risk_class", ""))),
            Text(terminal_text(e.source or "")),
        )
    console.print(table)


@inventory.command("stubs")
@click.argument("findings_json", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--out",
    "-o",
    "out_dir",
    type=click.Path(file_okay=False),
    required=True,
    help="directory to write one capability-card YAML per shadow agent",
)
@click.option(
    "--kinds",
    default="agent,mcp-server,workflow,bot-app,agent-config",
    show_default=True,
    help="finding kinds to register",
)
@click.option(
    "--min-risk",
    type=click.Choice(LEVELS),
    default="low",
    show_default=True,
    help="register only findings at or above this risk level",
)
def inventory_stubs(findings_json: str, out_dir: str, kinds: str, min_risk: str) -> None:
    """Generate Agent Capability Card stubs for shadow findings so they can be reviewed and registered."""
    wanted = {k.strip() for k in kinds.split(",")}
    unknown_kinds = sorted(wanted - {kind.value for kind in Kind})
    if unknown_kinds:
        raise click.BadParameter(
            f"unknown finding kind(s): {', '.join(unknown_kinds)}; "
            f"choose from {', '.join(kind.value for kind in Kind)}",
            param_hint="--kinds",
        )
    threshold = LEVELS.index(min_risk)
    # Finish validation and card generation before writing any approval stubs.
    # A bad later record must not leave an apparently successful partial import.
    data = _load_report(findings_json)
    try:
        cards = []
        for record in data["findings"]:
            finding = Finding.from_dict(record)
            if (
                finding.kind.value not in wanted
                or finding.shadow is False
                or LEVELS.index(finding.risk.level.value) > threshold
            ):
                continue
            cards.append((finding.id, card_stub_for(finding)))
    except (ValueError, TypeError, OSError, KeyError, AttributeError, RecursionError):
        raise click.ClickException(
            "report contains a malformed finding; no inventory stubs were written"
        ) from None
    try:
        out = prepare_private_directory(out_dir)
    except (OSError, ValueError):
        raise click.ClickException(
            "inventory output requires a private directory with mode 0700 and no symlinks"
        ) from None
    n = 0
    for finding_id, card in cards:
        suffix = hashlib.sha256(finding_id.encode()).hexdigest()[:8]
        path = out / f"{card['metadata']['agent_id']}-{suffix}.yaml"
        try:
            write_private_text(path, yaml.safe_dump(card, sort_keys=False, allow_unicode=True))
        except (OSError, ValueError):
            raise click.ClickException(
                "could not write inventory stub; check output path and permissions"
            ) from None
        n += 1
    console.print(Text(terminal_text(f"wrote {n} capability card stub(s) to {out}"), style="green"))
