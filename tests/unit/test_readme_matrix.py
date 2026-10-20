"""The generated detection matrix (docs/reference/detection-matrix.md) stays derived from the shipped catalogs."""

from __future__ import annotations

import dataclasses

import pytest

from shadowscan.connectors import builtin_connector_names
from shadowscan.signatures.loader import Signal, Signature, load_signatures
from tools.readme_matrix import BEGIN, END, FRAMEWORKS, _mcp_rows, main, render, replace_block


def _mcp() -> Signature:
    (mcp,) = [signature for signature in load_signatures() if signature.id == "protocol.mcp"]
    return mcp


def test_every_listed_framework_is_a_shipped_framework_signature() -> None:
    frameworks = {signature.id for signature in load_signatures() if signature.category == "framework"}
    assert set(FRAMEWORKS) <= frameworks
    assert len(set(FRAMEWORKS)) == len(FRAMEWORKS)


def test_block_names_each_identity_gateway_lowcode_saas_and_network_connector() -> None:
    block = render()
    listed = [
        name
        for name in builtin_connector_names()
        if name.split(".", 1)[0] in {"identity", "gateway", "lowcode", "saas", "network"}
    ]
    assert listed and all(f"| `{name}` |" in block for name in listed)
    assert block.startswith(BEGIN) and block.endswith(END)


def test_replace_block_keeps_the_surrounding_text() -> None:
    text = f"intro\n{BEGIN}\nold\n{END}\noutro\n"
    assert replace_block(text, f"{BEGIN}\nnew\n{END}") == f"intro\n{BEGIN}\nnew\n{END}\noutro\n"


@pytest.mark.parametrize(
    "text",
    [
        "no markers\n",
        f"{BEGIN}\nonly the start\n",
        f"{END}\n{BEGIN}\n",
        f"{BEGIN}\n{END}\n{BEGIN}\n{END}\n",
    ],
    ids=["missing", "unterminated", "reversed", "repeated"],
)
def test_replace_block_refuses_missing_or_ambiguous_markers(text: str) -> None:
    with pytest.raises(ValueError, match="markers"):
        replace_block(text, f"{BEGIN}\n{END}")


def test_cli_rejects_unknown_arguments(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--write"]) == 2
    assert "usage" in capsys.readouterr().err


def test_mcp_dependency_in_an_unnamed_ecosystem_is_refused() -> None:
    # Regression: a dependency signal in an ecosystem without a display name
    # disappeared from the table instead of failing the generator.
    mcp = _mcp()
    extended = dataclasses.replace(
        mcp, signals=[*mcp.signals, Signal(type="dependency", ecosystem="rubygems", names=["mcp"])]
    )
    with pytest.raises(ValueError, match="rubygems"):
        _mcp_rows(extended)


def test_mcp_rows_keep_wildcard_globs_prefixes_and_host_patterns() -> None:
    # Regression: wildcard-only globs, dependency prefixes and pattern-matched
    # hosts were dropped, so the table under-stated what is recognized.
    mcp = _mcp()
    rows = "\n".join(_mcp_rows(mcp))
    files = [glob for signal in mcp.signals if signal.type == "file" for glob in signal.globs]
    assert "**/.well-known/mcp.json" in files and "`.well-known/mcp.json`" in rows
    assert "`**/" not in rows
    prefixes = [prefix for signal in mcp.signals if signal.type == "dependency" for prefix in signal.prefixes]
    assert prefixes and all(f"`{prefix}*`" in rows for prefix in prefixes)
    patterns = [value for signal in mcp.signals if signal.type == "domain" for value in signal.values]
    assert any(value.startswith("re:") for value in patterns)
    assert "regular expression" in rows.split("| Remote MCP hosts |", 1)[1].split("\n", 1)[0]
