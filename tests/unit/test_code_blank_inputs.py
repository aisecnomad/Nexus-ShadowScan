"""A blank manifest, agent manifest or MCP configuration declares nothing, and leaves nothing unread.

langgraph's own CLI tests keep a zero-byte ``langgraph.json``: no parser accepts empty text,
so it was an input defect, and agent and MCP configuration is never discounted or declared, so
the whole repository exited 3 under every profile. A blank file is reported as a note instead;
strict accounting still counts that note, and a file with NUL bytes stays an undecodable gap.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_BLANK_INPUTS = [
    "langgraph.json",
    "libs/cli/tests/unit_tests/cli/langgraph.json",
    ".mcp.json",
    "package.json",
    "config/agents.yaml",
    ".well-known/agent.json",
]


def _scan(run_connector, root: Path, **config):
    (root / "app.py").write_text("VALUE = 1\n")
    _, ctx = run_connector("code.filesystem", path=str(root), label="repo", use_git=False, **config)
    return ctx.stats


@pytest.mark.parametrize("rel", _BLANK_INPUTS)
@pytest.mark.parametrize("content", [b"", b"  \n\t\r\n", b"\xef\xbb\xbf\n"])
def test_blank_input_is_complete_with_a_note(run_connector, tmp_path, rel, content):
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    stats = _scan(run_connector, tmp_path)
    assert not stats.incomplete and not stats.errors, stats.errors
    assert any("with a note (empty" in warning for warning in stats.warnings), stats.warnings


@pytest.mark.parametrize("rel", _BLANK_INPUTS)
@pytest.mark.parametrize("content", [b"", b"  \n"])
def test_blank_input_is_still_counted_under_strict_coverage(run_connector, tmp_path, rel, content):
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    stats = _scan(run_connector, tmp_path, strict_coverage=True)
    assert stats.incomplete


@pytest.mark.parametrize("rel", ["langgraph.json", ".mcp.json"])
@pytest.mark.parametrize("content", [b"\x00", b"\x00 \n"])
def test_nul_bearing_input_stays_an_undecodable_gap(run_connector, tmp_path, rel, content):
    (tmp_path / rel).write_bytes(content)
    stats = _scan(run_connector, tmp_path)
    assert stats.incomplete
    assert not any("with a note (empty" in warning for warning in stats.warnings)
