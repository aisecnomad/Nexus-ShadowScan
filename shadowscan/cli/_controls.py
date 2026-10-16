"""controls command."""

from __future__ import annotations

import click
from rich.text import Text

from shadowscan.cli import _load_report, err_console, main
from shadowscan.controls import ControlSelectionError, build_control_evidence, check_sources, control_catalogs
from shadowscan.fleet import merge_reports, source_names
from shadowscan.reporters.controls import CONTROL_FORMATS, render_controls
from shadowscan.utils.output import encodable_text, terminal_report_text, terminal_text, write_private_text
from shadowscan.utils.redaction import sanitize_text


@main.command("controls")
@click.argument("reports", nargs=-1, required=True, type=click.Path(exists=True, dir_okay=False))
@click.option(
    "-f",
    "--format",
    "fmt",
    type=click.Choice(CONTROL_FORMATS),
    default="markdown",
    show_default=True,
    help="output format",
)
@click.option("-o", "--output", type=click.Path(dir_okay=False), default=None, help="write to a file")
@click.option(
    "--framework",
    "frameworks",
    multiple=True,
    metavar="PREFIX",
    help="report only this control catalog, by prefix (eu-ai-act-2024) or framework (eu-ai-act); repeatable",
)
def controls_command(
    reports: tuple[str, ...], fmt: str, output: str | None, frameworks: tuple[str, ...]
) -> None:
    """List, per AI governance control, the findings of JSON reports that reference it.

    Covers the NIST AI RMF, ISO/IEC 42001, EU AI Act and AIUC-1 catalogs.

    Several reports are merged as `merge` merges them; pass the source reports, not a merged
    report. Evidence references, not compliance determinations: author mappings, not
    independently reviewed. The output is written with an incomplete-scan banner and the command
    exits 3 when any report is incomplete."""
    try:
        catalogs = control_catalogs(frameworks)
    except ControlSelectionError as exc:
        raise click.ClickException(str(exc)) from None
    loaded = [(name, _load_report(path)) for name, path in zip(source_names(reports), reports, strict=True)]
    try:
        check_sources(loaded)
        result = merge_reports(loaded)
    except ValueError as exc:
        raise click.ClickException(sanitize_text(str(exc))) from None
    try:
        evidence = build_control_evidence(result, loaded, catalogs=catalogs)
        text = render_controls(evidence, fmt)
    except (OverflowError, RecursionError, TypeError, ValueError):
        raise click.ClickException("could not render control evidence; report data is invalid") from None
    if output:
        try:
            write_private_text(output, text)
        except (OSError, ValueError):
            raise click.ClickException(
                "could not write control evidence; check output path and permissions"
            ) from None
        err_console.print(Text(terminal_text(f"wrote {fmt} control evidence to {output}"), style="green"))
    else:
        click.echo(encodable_text(terminal_report_text(text, fmt)), nl=False)
    raise click.exceptions.Exit(0 if evidence["evidence_scope"]["complete"] else 3)
