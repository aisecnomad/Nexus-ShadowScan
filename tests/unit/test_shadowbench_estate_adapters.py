"""Unit tests for the ShadowBench estate adapters (tools/shadowbench/estate/adapters)."""

from __future__ import annotations

import pytest

from tools.shadowbench.estate.adapters.common import client_slug

# --- client names ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "slug"),
    [
        ("Claude Desktop App", "claude-desktop"),
        ("claude_desktop", "claude-desktop"),
        ("CLAUDE_DESKTOP", "claude-desktop"),
        ("Cline (VS Code)", "cline"),
        ("Continue (VS Code)", "continue"),
        ("GitHub Copilot (VS Code)", "copilot"),
    ],
)
def test_client_slug_prefers_the_most_specific_client(name: str, slug: str) -> None:
    assert client_slug(name) == slug


@pytest.mark.parametrize(
    ("name", "slug"),
    [
        # Names the 2026-10-11 run's tools printed; their mapping must not move.
        ("claude code", "claude-code"),
        ("Claude Code", "claude-code"),
        ("claude_code", "claude-code"),
        ("claude", "claude-code"),
        ("claude desktop", "claude-desktop"),
        ("cursor", "cursor"),
        ("windsurf", "windsurf"),
        ("vscode", "generic"),
        ("VS Code", "generic"),
        ("gemini cli", "gemini-cli"),
        ("gemini_cli", "gemini-cli"),
        ("Gemini CLI", "gemini-cli"),
        ("codex", "codex"),
        ("continue", "continue"),
        ("amazon_q", "amazon-q"),
        ("Amazon Q", "amazon-q"),
        # Other table rows and fallbacks.
        ("GitHub Copilot Chat", "copilot"),
        ("lm studio", "lm-studio"),
        ("Amazon Q Developer", "amazon-q"),
        ("cline", "cline"),
        ("decline-bot", "generic"),
        ("", "generic"),
        ("node", "generic"),
    ],
)
def test_client_slug_table(name: str, slug: str) -> None:
    assert client_slug(name) == slug
