"""Output formats: table (terminal), json, sarif, csv, markdown, html, cyclonedx, ocsf."""

from __future__ import annotations

from typing import Protocol

from shadowscan.models import ScanResult
from shadowscan.reporters.csv_ import render_csv
from shadowscan.reporters.cyclonedx import render_cyclonedx
from shadowscan.reporters.html import render_html
from shadowscan.reporters.json_ import render_json
from shadowscan.reporters.markdown import render_markdown
from shadowscan.reporters.ocsf import render_ocsf
from shadowscan.reporters.sarif import render_sarif
from shadowscan.signatures import SignatureIndex


class Renderer(Protocol):
    """The contract every entry of :data:`RENDERERS` satisfies.

    A renderer turns a :class:`~shadowscan.models.ScanResult` into the text of
    one output format (JSON, SARIF, CSV, Markdown, HTML, CycloneDX, OCSF). The
    result is its only required argument, passed positionally, so a renderer
    may name it as it likes; CycloneDX's optional signature index, which names
    custom-pack signatures in the BOM, is passed only by :func:`render`.
    """

    def __call__(self, result: ScanResult, /) -> str: ...


RENDERERS: dict[str, Renderer] = {
    "json": render_json,
    "sarif": render_sarif,
    "csv": render_csv,
    "markdown": render_markdown,
    "md": render_markdown,
    "html": render_html,
    "cyclonedx": render_cyclonedx,
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
