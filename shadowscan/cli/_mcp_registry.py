"""mcp-registry group (snapshot)."""

from __future__ import annotations

import hashlib
import sys

import click
from rich.text import Text

from shadowscan.cli import err_console, main
from shadowscan.mcp_registry import (
    DEFAULT_MAX_PAGES,
    DEFAULT_REGISTRY_URL,
    PAGE_LIMIT,
    SnapshotError,
    fetch_snapshot,
    registry_base_url,
)
from shadowscan.utils.output import terminal_text, write_private_text


# -------------------------------------------------------------- mcp registry
@main.group("mcp-registry")
def mcp_registry() -> None:
    """Produce MCP Registry snapshots to pin in options.mcp_registries."""


@mcp_registry.command("snapshot")
@click.option(
    "--url",
    default=DEFAULT_REGISTRY_URL,
    show_default=True,
    help="base URL of a registry serving the MCP Registry API (HTTPS only)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(dir_okay=False),
    required=True,
    help="snapshot file to write (mode 0600)",
)
@click.option(
    "--max-pages",
    type=click.IntRange(1, DEFAULT_MAX_PAGES),
    default=DEFAULT_MAX_PAGES,
    show_default=True,
    help=f"fail without writing when the listing has more pages of {PAGE_LIMIT} server versions",
)
@click.option(
    "--ca-bundle",
    type=click.Path(exists=True, dir_okay=False),
    help="PEM CA bundle for a registry behind private PKI; verification stays on",
)
@click.option(
    "--allow-private-origin",
    is_flag=True,
    help="allow a registry on a private address; HTTPS and origin checks still apply",
)
def mcp_registry_snapshot(
    url: str, output: str, max_pages: int, ca_bundle: str | None, allow_private_origin: bool
) -> None:
    """List every server version of an MCP registry (deleted ones included) into a pinned snapshot.

    The listing is complete or nothing is written: a failed request, an invalid page, a
    repeated cursor or a page or size limit exits 3. The SHA-256 to pin is printed on stdout.
    """
    try:
        registry_base_url(url, allow_private_origin=allow_private_origin)
    except SnapshotError as exc:
        raise click.BadParameter(str(exc), param_hint="--url") from None
    try:
        text = fetch_snapshot(
            url, max_pages=max_pages, ca_bundle=ca_bundle, allow_private_origin=allow_private_origin
        )
    except SnapshotError as exc:
        err_console.print(Text(terminal_text(f"error: {exc}; no snapshot written"), style="red"))
        sys.exit(3)
    try:
        write_private_text(output, text)
    except (OSError, ValueError):
        raise click.ClickException("could not write snapshot; check output path and permissions") from None
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    note = f"wrote MCP registry snapshot to {output}; pin it with sha256: {digest}"
    err_console.print(Text(terminal_text(note), style="green"))
    click.echo(digest)
