"""Bounded local readiness checks; deliberately not a finding report.

For an ordinary (not ``--quick``) root, the readiness check is followed by the
scanner's own walk with content analysis left out: it lists the static coverage
gaps a full scan would record (files over ``max_file_size``, unfollowed links,
non-regular entries) without reading any other file content.
"""

from __future__ import annotations

import json
import os
from typing import Any

import click

from shadowscan.cli import ScanOptions, _remediation_lines
from shadowscan.config import DEFAULT_CONNECTOR_TIMEOUT, ConnectorSpec
from shadowscan.connectors.base import ConnectorContext, ConnectorError
from shadowscan.connectors.code.filesystem import FilesystemConnector, _checked_scan_root
from shadowscan.reporters.table import incomplete_reasons_text
from shadowscan.signatures import SignatureIndex
from shadowscan.utils.files import open_confined_directory
from shadowscan.utils.output import terminal_text, write_private_text
from shadowscan.utils.staged import StagedScanError, staged_snapshot

# Bounds the per-root list of gap files kept in the preflight report.
_MAX_LISTED_GAPS = 200


def _static_gaps(root: str, common: dict[str, Any], opts: ScanOptions) -> dict[str, Any]:
    """The static coverage gaps a full scan of ``root`` would record, by reason and by file.

    It runs ``code.filesystem`` in its ``preflight`` mode: the same walk, size limits and
    link accounting as a scan, with no file analyzed. Its ``subset-scan`` marker is dropped
    here; any other reason predicts an incomplete full scan.
    """
    from shadowscan.engine import Engine

    spec = ConnectorSpec(name="code.filesystem", config={**common, "paths": [root], "preflight": True})
    try:
        result = Engine(opts.config([spec])).run()
    except Exception:  # noqa: BLE001 - third-party exception text may echo paths or values
        return {"problem": "the static walk could not run; run the full scan for details"}
    reasons = {k: v for k, v in result.summary()["incomplete_reasons"].items() if k != "subset-scan"}
    if not result.summary()["incomplete_reasons"]:
        # A preflight always carries its subset marker; none means the connector failed or was skipped.
        return {"problem": "the static walk recorded no diagnostic; run the full scan for details"}
    files = [
        {"path": detail["path"], "reason": detail["reason"]}
        for stats in result.stats
        for detail in (stats.coverage or {}).get("details", [])
        if detail.get("path") and detail.get("reason") in reasons
    ]
    return {"reasons": reasons, "files": files[:_MAX_LISTED_GAPS], "files_total": len(files)}


def _root_check(path: str, common: dict[str, Any], opts: ScanOptions) -> dict[str, Any]:
    result: dict[str, Any] = {"path": path, "ready": False}
    try:
        root = _checked_scan_root(path)
        fd = open_confined_directory(root)
        os.close(fd)
        result["path"] = str(root)
        if common.get("staged"):
            # No signatures or source analysis: the empty index is only the context contract.
            ctx = ConnectorContext(config={}, index=SignatureIndex([]))
            with staged_snapshot(root, ctx) as snapshot:
                result.update(staged_files=snapshot.files, staged_deletions=snapshot.deleted)
        else:
            config = {**common, "path": str(root)}
            estimate = FilesystemConnector.estimate_timeout_seconds(config, float(DEFAULT_CONNECTOR_TIMEOUT))
            result["connector_timeout_seconds"] = (
                opts.connector_timeout_seconds or estimate or float(DEFAULT_CONNECTOR_TIMEOUT)
            )
        result["ready"] = True
        if not common.get("staged"):
            result["static_gaps"] = _static_gaps(str(root), common, opts)
    except StagedScanError as exc:
        result["problem"] = str(exc)
    except (ConnectorError, OSError, ValueError):
        result["problem"] = "root could not be safely opened; check the directory and read permissions"
    return result


def code_preflight(paths: tuple[str, ...], common: dict[str, Any], opts: ScanOptions) -> None:
    """Inspect local roots without claiming they have passed a scan."""
    if opts.fmt not in {"table", "json"}:
        raise click.UsageError("--preflight supports --format table or json; it does not emit a scan report")
    roots = [_root_check(path, common, opts) for path in paths]
    ready = all(root["ready"] for root in roots)
    gaps = [root["static_gaps"] for root in roots if "static_gaps" in root]
    complete_expected = ready and not any(gap.get("reasons") or "problem" in gap for gap in gaps)
    report = {
        "schema": "shadowscan.code-preflight/v1",
        "scan_performed": False,
        "ready": ready,
        "static_gaps_found": ready and not complete_expected,
        "scope": "staged Git blobs only" if common.get("staged") else "local filesystem roots",
        "roots": roots,
        "note": (
            "Readiness and static coverage gaps only: root access, files over the size limit and unfollowed "
            "links (or, for quick mode, bounded staged content). No source analysis, credential detection or "
            "inventory validation has run, so a full scan can still be incomplete for content. "
            "Run the same command without --preflight to scan."
        ),
    }
    text = json.dumps(report, indent=2) + "\n"
    if opts.output:
        try:
            write_private_text(opts.output, text)
        except (OSError, ValueError):
            raise click.ClickException(
                "could not write preflight output; check path and permissions"
            ) from None
    elif opts.fmt == "json":
        click.echo(text, nl=False)
    else:
        click.echo(f"Preflight {'ready' if ready else 'blocked'} — no scan performed")
        for root in roots:
            detail = root.get("problem", "root accessible")
            if "staged_files" in root:
                detail = f"{root['staged_files']} staged file(s), {root['staged_deletions']} deletion(s)"
            elif "connector_timeout_seconds" in root:
                detail += f"; connector budget {root['connector_timeout_seconds']:g}s"
            click.echo(terminal_text(f"{root['path']}: {detail}"))
            _echo_static_gaps(root.get("static_gaps"))
        click.echo(report["note"])
        reasons: dict[str, int] = {}
        for gap in gaps:
            for reason, count in gap.get("reasons", {}).items():
                reasons[reason] = reasons.get(reason, 0) + count
        remediation = _remediation_lines(reasons)
        if remediation:
            click.echo("to resolve:\n" + "\n".join(terminal_text(line) for line in remediation), err=True)
    raise SystemExit(0 if complete_expected else 3)


def _echo_static_gaps(gaps: dict[str, Any] | None) -> None:
    if gaps is None:
        return
    if "problem" in gaps:
        click.echo(terminal_text(f"  static gaps: {gaps['problem']}"))
        return
    if not gaps["reasons"]:
        click.echo("  static gaps: none found")
        return
    click.echo(
        f"  static gaps (a full scan would be incomplete, exit 3): {incomplete_reasons_text(gaps['reasons'])}"
    )
    for item in gaps["files"]:
        click.echo(terminal_text(f"    {item['reason']}: {item['path']}"))
    if gaps["files_total"] > len(gaps["files"]):
        click.echo(f"    ... {gaps['files_total'] - len(gaps['files'])} more in --format json")
