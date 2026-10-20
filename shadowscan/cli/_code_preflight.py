"""Bounded local readiness checks; deliberately not a finding or coverage report."""

from __future__ import annotations

import json
import os
from typing import Any

import click

from shadowscan.cli import ScanOptions
from shadowscan.config import DEFAULT_CONNECTOR_TIMEOUT
from shadowscan.connectors.base import ConnectorContext, ConnectorError
from shadowscan.connectors.code.filesystem import FilesystemConnector, _checked_scan_root
from shadowscan.signatures import SignatureIndex
from shadowscan.utils.files import open_confined_directory
from shadowscan.utils.output import terminal_text, write_private_text
from shadowscan.utils.staged import StagedScanError, staged_snapshot


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
    report = {
        "schema": "shadowscan.code-preflight/v1",
        "scan_performed": False,
        "ready": ready,
        "scope": "staged Git blobs only" if common.get("staged") else "local filesystem roots",
        "roots": roots,
        "note": (
            "Readiness only: root access and, for quick mode, bounded staged content. No source analysis, "
            "credential detection, inventory validation or completeness verdict has run. "
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
        click.echo(report["note"])
    raise SystemExit(0 if ready else 3)
