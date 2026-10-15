"""The README banner and architecture diagrams stay derived from the code."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections.abc import Callable

import pytest

from shadowscan import __version__
from shadowscan.cli import main as cli
from shadowscan.connectors import builtin_connector_names
from shadowscan.models import Surface
from shadowscan.reporters import FORMATS
from tools.readme_visuals import (
    ASSETS,
    BANNER,
    CONNECTORS,
    DATA_FLOW,
    REPORT_COMMANDS,
    ROOT,
    SURFACE_COLOURS,
    SURFACES,
    main,
    render_banner,
    render_connectors,
    render_data_flow,
    rendered,
)

_SVG = "{http://www.w3.org/2000/svg}"


def _text(svg: str) -> str:
    return " ".join(
        "".join(node.itertext()) for node in ET.fromstring(svg.split("\n", 1)[1]).iter(f"{_SVG}text")
    )


def test_committed_images_match_the_generator() -> None:
    for path, text in rendered().items():
        assert path.read_text(encoding="utf-8") == text, f"{path.name} is stale; run `make readme-visuals`"
    assert main(["--check"]) == 0


@pytest.mark.parametrize("render", [render_banner, render_data_flow, render_connectors])
def test_images_are_well_formed_accessible_svg(render: Callable[[], str]) -> None:
    svg = render()
    root = ET.fromstring(svg.split("\n", 1)[1])
    assert root.tag == f"{_SVG}svg" and root.get("role") == "img"
    assert root.find(f"{_SVG}title") is not None and root.find(f"{_SVG}desc") is not None


def test_every_surface_has_a_label_and_colours() -> None:
    assert set(SURFACES) == set(Surface) == set(SURFACE_COLOURS)


def test_connector_diagram_names_every_built_in_connector() -> None:
    text = _text(render_connectors())
    assert all(name in text.split() for name in builtin_connector_names())


def test_data_flow_names_every_surface_report_format_and_report_command() -> None:
    text = _text(render_data_flow())
    assert all(surface.value in text.split() for surface in Surface)
    assert all(fmt in text.split() for fmt in FORMATS)
    assert set(REPORT_COMMANDS) <= set(cli.commands)


def test_data_flow_does_not_present_plugins_as_isolated() -> None:
    """An allowlisted plugin keeps the scanner's privileges; the process backend is not a sandbox."""
    text = _text(render_data_flow())
    assert "plugins are not sandboxed" in text
    assert "isolated plugins" not in text


def test_banner_names_every_surface() -> None:
    text = _text(render_banner())
    assert all(label in text for label, _ in SURFACES.values())


@pytest.mark.parametrize("render", [render_banner, render_data_flow, render_connectors])
def test_images_carry_no_version_count_or_repository_slug(render: Callable[[], str]) -> None:
    """Figures baked into an image go stale silently; keep them in checked text."""
    text = _text(render())
    assert __version__ not in text
    assert "aisecnomad" not in text and "Project-Nexus" not in text
    assert not re.search(r"\b\d{2,}\b", text.replace("(exit 3)", "").replace("exit 3", ""))


def test_readme_and_architecture_page_reference_the_generated_images() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    raw = "https://raw.githubusercontent.com/aisecnomad/Nexus-ShadowScan/main/docs/assets/"
    for path in (BANNER, DATA_FLOW):
        assert f"{raw}{path.name}" in readme
    assert f"assets/{CONNECTORS.name}" in (ROOT / "docs" / "architecture.md").read_text(encoding="utf-8")


def test_docs_assets_holds_only_the_generated_images() -> None:
    """Raster images cannot be regenerated or checked, so only the generated SVGs belong here."""
    assert {path.name for path in ASSETS.iterdir()} == {path.name for path in rendered()}
    assert all(path.parent == ASSETS for path in rendered())
