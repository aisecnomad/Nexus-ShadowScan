"""dashboard command."""

from __future__ import annotations

import os

import click
from rich.text import Text

from shadowscan.cli import _load_report, err_console, main
from shadowscan.comparison import MAX_REPORT_BYTES, ReportDigestMismatch
from shadowscan.dashboard import (
    MAX_HISTORY,
    HistoryError,
    build_inventory,
    load_history,
    parse_instant,
    render_inventory_json,
)
from shadowscan.fleet import merge_reports, report_result, source_names
from shadowscan.utils.output import terminal_text, write_private_text
from shadowscan.utils.redaction import sanitize_text


# ----------------------------------------------------------------- dashboard
def _as_of_option(ctx: click.Context, param: click.Parameter, value: str | None) -> str | None:
    if value is None:
        return None
    moment = parse_instant(value)
    if moment is None:
        raise click.BadParameter(
            "expected an ISO 8601 time with a UTC offset, such as 2026-10-10T00:00:00+00:00"
        )
    return moment.isoformat()


@main.command("dashboard")
@click.argument("reports", nargs=-1, required=True, type=click.Path(exists=True, dir_okay=False))
@click.option(
    "-o",
    "--output",
    required=True,
    type=click.Path(dir_okay=False),
    help="write the dashboard HTML to this file (mode 0600, never through a symbolic link another user owns)",
)
@click.option(
    "--inventory-json",
    type=click.Path(dir_okay=False),
    default=None,
    help="also write the shadowscan.inventory/v1 JSON document to this file",
)
@click.option(
    "--baseline",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="show drift against this earlier report; an incomparable baseline exits 3",
)
@click.option(
    "--history",
    "history_dir",
    type=click.Path(exists=True, file_okay=False),
    default=None,
    help=f"show trends from the JSON reports in this directory (the newest {MAX_HISTORY})",
)
@click.option(
    "--as-of",
    callback=_as_of_option,
    default=None,
    metavar="TIME",
    help="measure source staleness against this time instead of the newest source's last scan",
)
def dashboard_command(
    reports: tuple[str, ...],
    output: str,
    inventory_json: str | None,
    baseline: str | None,
    history_dir: str | None,
    as_of: str | None,
) -> None:
    """Write a static fleet dashboard (and optionally inventory JSON) from JSON reports.

    Several reports are merged as `merge` would. One report is read as `merge`
    reads a source: autonomy is classified again, registration counts only from
    its own `inventory_present`, and a report written before that field existed
    that records registration is refused (exit 1). A fleet report is used as
    written. Coverage per source and connector comes first, and data
    that was not collected never reads as zero. The page loads nothing and runs
    one hashed script. Exit 3 when any input is incomplete or the baseline
    comparison is incomplete; the files are still written."""
    targets = [os.path.abspath(output)] + ([os.path.abspath(inventory_json)] if inventory_json else [])
    if len(set(targets)) != len(targets):
        raise click.BadParameter("must differ from --output", param_hint="--inventory-json")
    names = source_names(reports)
    loaded = [(name, _load_report(path)) for name, path in zip(names, reports, strict=True)]
    try:
        result = merge_reports(loaded) if len(loaded) > 1 else report_result(*loaded[0])
    except ValueError as exc:
        raise click.ClickException(sanitize_text(str(exc))) from None
    baseline_report = _load_report(baseline) if baseline else None
    history = None
    if history_dir:
        try:
            history = load_history(history_dir)
        except ReportDigestMismatch:
            raise click.ClickException("a history report changed while it was being read") from None
        except HistoryError as exc:
            raise click.ClickException(str(exc)) from None
        except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
            # Report text and paths never reach the message.
            raise click.ClickException(
                "could not read a history report (ShadowScan JSON, regular file, at most "
                f"{MAX_REPORT_BYTES // (1024 * 1024)} MiB)"
            ) from None
    try:
        inventory = build_inventory(
            result,
            name=names[0],
            baseline=baseline_report,
            current=loaded[0][1] if len(loaded) == 1 else None,
            history=history,
            as_of=as_of,
        )
        import shadowscan.cli as _cli_pkg

        page = _cli_pkg.render_dashboard(inventory)
        document = render_inventory_json(inventory) if inventory_json else None
    except (OverflowError, RecursionError, TypeError, ValueError):
        raise click.ClickException("could not render dashboard; report data is invalid") from None
    for path, text, what in ((output, page, "dashboard"), (inventory_json, document, "inventory JSON")):
        if path is None or text is None:
            continue
        try:
            write_private_text(path, text)
        except (OSError, ValueError):
            raise click.ClickException(f"could not write {what}; check output path and permissions") from None
        err_console.print(Text(terminal_text(f"wrote {what} to {path}"), style="green"))
    drift = inventory["drift"]
    raise click.exceptions.Exit(3 if not inventory["complete"] or (drift and not drift["comparable"]) else 0)
