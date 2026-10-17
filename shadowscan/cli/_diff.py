"""diff command."""

from __future__ import annotations

import json
import string
from typing import Any

import click

from shadowscan.cli import LEVELS, console, main
from shadowscan.comparison import (
    DRIFT_CLASSES,
    MAX_BASELINE_AGE_DAYS,
    ReportDigestMismatch,
    compare_reports,
    load_report,
    load_report_with_digest,
)
from shadowscan.utils.output import terminal_text


# ---------------------------------------------------------------------- diff
def _drift_classes_option(ctx: click.Context, param: click.Parameter, value: str | None) -> tuple[str, ...]:
    if value is None:
        return ()
    names = [name.strip() for name in value.split(",")]
    if any(name not in DRIFT_CLASSES for name in names):
        raise click.BadParameter(f"expected a comma-separated list of {', '.join(DRIFT_CLASSES)}")
    return tuple(dict.fromkeys(names))


def _sha256_option(ctx: click.Context, param: click.Parameter, value: str | None) -> str | None:
    if value is None:
        return None
    if len(value) != 64 or any(character not in string.hexdigits for character in value):
        raise click.BadParameter("expected a SHA-256 digest of 64 hexadecimal characters")
    return value.lower()


def _risk_rose(change: dict[str, Any]) -> bool:
    """Whether a changed finding moved to a more severe risk level (LEVELS runs most to least severe)."""
    return LEVELS.index(change["after"]["risk"]["level"]) < LEVELS.index(change["before"]["risk"]["level"])


@main.command()
@click.argument("baseline", type=click.Path(exists=True, dir_okay=False))
@click.argument("current", type=click.Path(exists=True, dir_okay=False))
@click.option("--json", "as_json", is_flag=True, help="print JSON instead of the human-readable output")
@click.option(
    "--fail-on-new",
    is_flag=True,
    help=(
        "exit 2 if the comparison has new findings or findings whose risk level rose; "
        "an incomplete comparison still exits 3"
    ),
)
@click.option(
    "--fail-on-drift",
    "fail_on_drift",
    metavar="CLASSES",
    callback=_drift_classes_option,
    help=(
        "exit 2 if the comparison has adverse drift in any of these comma-separated classes "
        f"({', '.join(DRIFT_CLASSES)}); an incomplete comparison still exits 3"
    ),
)
@click.option(
    "--baseline-sha256",
    metavar="HEX",
    callback=_sha256_option,
    help="refuse the baseline (exit 1) unless the SHA-256 of its file is HEX, as sha256sum prints it",
)
@click.option(
    "--max-baseline-age-days",
    type=click.IntRange(min=1, max=MAX_BASELINE_AGE_DAYS),
    default=None,
    metavar="DAYS",
    help=(
        "make the comparison incomplete (exit 3) if the baseline scan started more than this many "
        "days ago, has no valid start time, or started after the current scan"
    ),
)
@click.option(
    "--shadow-only",
    is_flag=True,
    help=(
        "display only findings whose shadow field is true (unmatched against the supplied "
        "inventory); counts, incompleteness reasons and exit codes still cover every finding"
    ),
)
def diff(
    baseline: str,
    current: str,
    as_json: bool,
    fail_on_new: bool,
    fail_on_drift: tuple[str, ...],
    baseline_sha256: str | None,
    max_baseline_age_days: int | None,
    shadow_only: bool,
) -> None:
    """Compare reports; missing findings require complete, comparable scans to resolve."""
    try:
        baseline_report, digest = load_report_with_digest(baseline, expected_sha256=baseline_sha256)
    except ReportDigestMismatch:
        # Nothing from an unreviewed baseline is parsed or echoed.
        raise click.ClickException("baseline digest does not match --baseline-sha256") from None
    except (ValueError, TypeError, OSError):
        raise click.ClickException("invalid comparison input; expected two ShadowScan JSON reports") from None
    try:
        comparison = compare_reports(
            baseline_report,
            load_report(current),
            max_baseline_age_days=max_baseline_age_days,
        )
    except (ValueError, TypeError, OSError):
        raise click.ClickException("invalid comparison input; expected two ShadowScan JSON reports") from None
    comparison["baseline"].update(sha256=digest, pinned=baseline_sha256 is not None)

    def displayed(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        # shadow is tri-state: None means no inventory was supplied, which is
        # not evidence the finding is shadow, so only shadow=True passes.
        if not shadow_only:
            return records
        return [d for d in records if d.get("shadow") is True]

    if as_json:
        # The JSON document always carries the full comparison (never make a
        # filtered view look complete); the filter adds a view alongside it.
        if shadow_only:
            comparison = {
                **comparison,
                "shadow_only_view": {
                    key: [d["id"] for d in displayed(comparison[key])]
                    for key in ("new", "resolved", "unknown", "changed")
                    if key != "changed"
                }
                | {"changed": [c["after"]["id"] for c in comparison["changed"] if c["after"].get("shadow")]},
            }
        click.echo(json.dumps(comparison, indent=2, default=str))
    else:
        keys = ("new", "resolved", "unknown", "changed")
        new, resolved, unknown, changed = (comparison[key] for key in keys)
        # Scan-local IDs (baseline "<", current ">") cannot be matched across reports.
        local_baseline, local_current = (comparison["not_comparable"][key] for key in ("baseline", "current"))
        console.print(
            f"[bold]{len(new)} new[/bold], [bold]{len(resolved)} resolved[/bold],"
            f" [bold]{len(unknown)} unknown[/bold], [bold]{len(changed)} changed[/bold],"
            f" [bold]{len(local_baseline) + len(local_current)} not comparable[/bold]"
        )
        totals = ", ".join(f"{name} {count}" for name, count in comparison["drift_summary"].items())
        adverse = [name for name, flagged in comparison["adverse"].items() if flagged]
        console.print(
            f"drift: {totals}" + (f" (adverse: {', '.join(adverse)})" if adverse else ""),
            markup=False,
            highlight=False,
        )
        for reason in comparison["reasons"]:
            console.print(f"Comparison incomplete: {reason}", markup=False)
        # Imported titles and resources are untrusted: Rich's highlighter is
        # quadratic on long tokens (a 50k-character title took about 30 s).
        for marker, records in (
            ("+", new),
            ("-", resolved),
            ("?", unknown),
            ("<", local_baseline),
            (">", local_current),
        ):
            for d in sorted(displayed(records), key=lambda d: -d["risk"]["score"]):
                line = f"  {marker} {d['risk']['level']:8} {d['title']}  {d['resource']}"
                console.print(terminal_text(line), markup=False, highlight=False)
        for change in changed:
            if shadow_only and change["after"].get("shadow") is not True:
                continue
            x, y = change["before"], change["after"]
            fields_changed = ", ".join(change["changed_fields"])
            line = f"  ~ {y['title']}: {fields_changed} (risk {x['risk']['score']} → {y['risk']['score']})"
            classes = list(dict.fromkeys(entry["class"] for entry in change["drift"]))
            if classes:
                line += f" [{', '.join(classes)}]"
            console.print(terminal_text(line), markup=False, highlight=False)
    if not comparison["comparable"]:
        raise click.exceptions.Exit(3)
    if fail_on_new and (comparison["new"] or any(_risk_rose(change) for change in comparison["changed"])):
        raise click.exceptions.Exit(2)
    if any(comparison["adverse"][name] for name in fail_on_drift):
        raise click.exceptions.Exit(2)
