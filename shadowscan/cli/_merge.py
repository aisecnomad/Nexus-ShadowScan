"""merge command."""

from __future__ import annotations

import click
from rich.text import Text

from shadowscan.cli import (
    LEVELS,
    ScanOptions,
    _emit,
    _exit_code,
    _load_report,
    console,
    main,
)
from shadowscan.fleet import merge_reports, source_names
from shadowscan.reporters import FORMATS
from shadowscan.utils.redaction import sanitize_text


@main.command("merge")
@click.argument("reports", nargs=-1, required=True, type=click.Path(exists=True, dir_okay=False))
@click.option(
    "-f",
    "--format",
    "fmt",
    type=click.Choice(FORMATS),
    default="table",
    show_default=True,
    help="output format",
)
@click.option(
    "-o", "--output", type=click.Path(dir_okay=False), default=None, help="write the merged report to a file"
)
@click.option("--max-rows", type=int, default=None, help="limit rows printed in table mode")
def merge_command(reports: tuple[str, ...], fmt: str, output: str | None, max_rows: int | None) -> None:
    """Combine JSON reports from several machines or scans into one fleet report.

    Findings with the same identity merge; every finding records the reports it
    came from. The result is incomplete (exit 3) when any source was."""
    loaded = [(name, _load_report(path)) for name, path in zip(source_names(reports), reports, strict=True)]
    try:
        result = merge_reports(loaded)
    except ValueError as exc:
        raise click.ClickException(sanitize_text(str(exc))) from None
    verbose: int = main.verbose  # type: ignore[attr-defined]
    _emit(result, fmt, output, verbose >= 1, max_rows)
    raise click.exceptions.Exit(_exit_code(result, None))
