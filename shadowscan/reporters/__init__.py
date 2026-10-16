"""Output formats: table (terminal), json, sarif, csv, markdown, html, cyclonedx, ocsf."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from shadowscan.models import ScanResult
from shadowscan.reporters.csv_ import render_csv
from shadowscan.reporters.cyclonedx import render_cyclonedx
from shadowscan.reporters.html import render_html
from shadowscan.reporters.json_ import render_json
from shadowscan.reporters.markdown import render_markdown
from shadowscan.reporters.ocsf import render_ocsf
from shadowscan.reporters.sarif import render_sarif
from shadowscan.signatures import SignatureIndex


@runtime_checkable
class Renderer(Protocol):
    """Structural contract every reporter satisfies.

    A renderer turns a :class:`~shadowscan.models.ScanResult` into a string
    (JSON, SARIF, CSV, Markdown, HTML, CycloneDX, OCSF, …).

    Most renderers need only ``result``; CycloneDX additionally accepts a
    :class:`~shadowscan.signatures.SignatureIndex` so it can name custom-pack
    signatures in the BOM.  The protocol allows *any* extra keyword arguments
    so new optional context can be added without touching the contract.
    """

    def __call__(self, result: ScanResult, **kwargs: object) -> str: ...


RENDERERS: dict[str, Renderer] = {
    "json": render_json,
    "sarif": render_sarif,
    "csv": render_csv,
    "markdown": render_markdown,
    "md": render_markdown,
    "html": render_html,
    "cyclonedx": render_cyclonedx,  # type: ignore[dict-item]  # accepts extra `index` kwarg
    "ocsf": render_ocsf,
}

FORMATS = ["table", *sorted(k for k in RENDERERS if k != "md")]


def render(result: ScanResult, fmt: str, index: SignatureIndex | None = None) -> str:
    """Render ``result``; ``index`` is the scan's signature index (custom packs included), when known."""
    if fmt == "cyclonedx" and index is not None:
        return render_cyclonedx(result, index)
    try:
        return RENDERERS[fmt](result)
    except KeyError as exc:
        raise ValueError(f"unknown format {fmt!r}; choose from {', '.join(FORMATS)}") from exc


__all__ = ["Renderer", "RENDERERS", "FORMATS", "render"]
