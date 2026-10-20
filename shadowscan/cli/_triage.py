"""Read-only, offline terminal triage of an existing JSON report."""

from __future__ import annotations

import json
import sys

import click
from rich.console import Console
from rich.table import Table
from rich.text import Text

from shadowscan.cli import LEVELS, _load_report, main
from shadowscan.fleet import report_result
from shadowscan.models import Finding, ScanResult
from shadowscan.utils.output import terminal_text
from shadowscan.utils.redaction import sanitize_text

PAGE_SIZE = 10
MAX_DETAIL_CHARS = 32_000


def _text(value: str, limit: int = 500) -> Text:
    # Sanitization precedes clipping: a cut through a credential must not
    # turn it into a shape that the sanitizer no longer recognizes.
    cleaned = terminal_text(sanitize_text(value))
    return Text(cleaned[:limit] + ("…" if len(cleaned) > limit else ""))


def _matching(result: ScanResult, level: str | None, query: str) -> list[Finding]:
    return [
        finding
        for finding in result.findings
        if (level is None or finding.risk.level.value == level)
        and query.casefold() in (finding.title + " " + finding.resource).casefold()
    ]


def _detail(finding: Finding) -> Text:
    # JSON escapes controls inside values. Retain only the formatter's own
    # line breaks, then neutralize terminal controls and markup on every line.
    document = sanitize_text(json.dumps(finding.to_dict(), ensure_ascii=False, indent=2))
    clipped = document[:MAX_DETAIL_CHARS]
    visible = "\n".join(terminal_text(line) for line in clipped.split("\n"))
    if len(document) > MAX_DETAIL_CHARS:
        visible += "\n… detail truncated; inspect the private JSON report for the full finding"
    return Text(visible)


def _page(console: Console, findings: list[Finding], page: int, complete: bool) -> None:
    console.print(
        Text(
            f"Report: {'complete for its declared scope' if complete else 'INCOMPLETE — exit 3'}"
            f" | {len(findings)} matching findings | page {page + 1}"
        )
    )
    table = Table("Row", "Risk", "Surface", "Finding", "Resource")
    for number, finding in enumerate(findings[page * PAGE_SIZE : (page + 1) * PAGE_SIZE], 1):
        table.add_row(
            str(number),
            Text(f"{finding.risk.level.value} {finding.risk.score}"),
            _text(finding.surface.value),
            _text(finding.title),
            _text(finding.resource, 150),
        )
    console.print(table)


def _browse(console: Console, result: ScanResult, level: str | None, query: str) -> None:
    page = 0
    while True:
        findings = _matching(result, level, query)
        page = min(page, max(0, (len(findings) - 1) // PAGE_SIZE))
        _page(console, findings, page, result.complete)
        console.print(Text("n/p: page | /text: search | all: clear search | 1–10: details | q: quit"))
        try:
            command = click.prompt("triage", default="q", show_default=False).strip()
        except (click.Abort, EOFError):
            return
        if command == "q":
            return
        if command in {"n", "p"}:
            page = max(0, page + (1 if command == "n" else -1))
        elif command == "all" or command.startswith("/"):
            query, page = ("" if command == "all" else command[1:500]), 0
        elif command.isascii() and command.isdecimal() and len(command) <= 2:
            row = int(command)
            position = page * PAGE_SIZE + row - 1
            if 1 <= row <= PAGE_SIZE and position < len(findings):
                console.print(_detail(findings[position]))
        else:
            console.print(Text("Use n, p, /text, all, a visible row number, or q."))


@main.command("triage")
@click.argument("report", type=click.Path(exists=True, dir_okay=False))
@click.option("--level", type=click.Choice(LEVELS), help="Show only this risk level.")
@click.option("--search", default="", help="Filter titles and resources by literal text.")
@click.option("--list", "list_only", is_flag=True, help="Print the first page without prompting.")
def triage_command(report: str, level: str | None, search: str, list_only: bool) -> None:
    """Browse a JSON report locally, without network calls or changing findings.

    Filtering does not change completeness. Quitting an incomplete report
    exits 3. This view validates the report as fleet import does; it does not
    attest authenticity or mark findings resolved.
    """
    try:
        result = report_result("triage", _load_report(report))
    except (ValueError, TypeError, OverflowError, RecursionError):
        raise click.ClickException("invalid report; triage requires a valid ShadowScan JSON report") from None
    console = Console(markup=False, highlight=False)
    if list_only or not sys.stdin.isatty():
        _page(console, _matching(result, level, search), 0, result.complete)
    else:
        _browse(console, result, level, search)
    raise click.exceptions.Exit(0 if result.complete else 3)
