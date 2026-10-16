"""The README banner and architecture diagrams stay derived from the code."""

from __future__ import annotations

import json
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
    BENCHMARK,
    BENCHMARK_RUN,
    CONNECTORS,
    DATA_FLOW,
    REPORT_COMMANDS,
    ROOT,
    SURFACE_COLOURS,
    SURFACES,
    benchmark_rows,
    main,
    render_banner,
    render_benchmark,
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


@pytest.mark.parametrize("render", [render_banner, render_data_flow, render_connectors, render_benchmark])
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
    cleaned = text.replace("(exit 3)", "").replace("exit 3", "")
    cleaned = re.sub(r"\b\d+ connectors\b", "", cleaned)
    cleaned = re.sub(r"\b\d+ signatures\b", "", cleaned)
    assert not re.search(r"\b\d{2,}\b", cleaned)


def test_readme_and_architecture_page_reference_the_generated_images() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    raw = "https://raw.githubusercontent.com/aisecnomad/Nexus-ShadowScan/main/docs/assets/"
    for path in (BANNER, DATA_FLOW, BENCHMARK):
        assert f"{raw}{path.name}" in readme
    assert f"assets/{CONNECTORS.name}" in (ROOT / "docs" / "architecture.md").read_text(encoding="utf-8")


def test_docs_assets_holds_only_the_generated_images() -> None:
    """Generated SVGs and the cross-tool benchmark image belong here."""
    allowed = {path.name for path in rendered()} | {"benchmarks-cross-tool.webp"}
    assert {path.name for path in ASSETS.iterdir()} == allowed
    assert all(path.parent == ASSETS for path in rendered())


def test_benchmark_chart_shows_every_tool_of_the_committed_run_with_its_caveats() -> None:
    """The chart's figures come only from a committed results file, and it says what they are not."""
    with (BENCHMARK_RUN / "metrics.json").open(encoding="utf-8") as handle:
        tools = json.load(handle)["tools"]
    rows = benchmark_rows()
    assert {name for name, *_ in rows} == set(tools)
    text = _text(render_benchmark())
    for name, coverage, estate, scope, (low, high) in rows:
        assert tools[name]["estate"]["recall"] == estate and tools[name]["in_scope"]["recall"] == scope
        assert tools[name]["in_scope"]["recall_ci"] == [low, high]
        assert name in text and coverage in text and f"{estate:.2f}" in text
        assert f"{scope:.2f} ({low:.2f}-{high:.2f})" in text
    assert BENCHMARK_RUN.name in text
    assert "Author-written synthetic corpus" in text
    assert "unsupported surfaces count as misses" in text
    assert "IN-SCOPE RECALL" in text
    assert "not a verdict on any product" in text
    assert "compare tools on in-scope recall" in render_benchmark()
    assert "aisecnomad" not in text
