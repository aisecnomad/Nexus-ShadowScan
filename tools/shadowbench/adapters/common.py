"""Shared helpers for estate adapters."""

from __future__ import annotations

from tools.shadowbench import taxonomy

#: Client display names and ids, as third-party tools print them, mapped onto
#: `ai-client:` taxonomy values.
CLIENT_SLUGS: dict[str, str] = {
    "claude code": "claude-code",
    "claude-code": "claude-code",
    "claude": "claude-code",
    "claude desktop": "claude-desktop",
    "claude-desktop": "claude-desktop",
    "cursor": "cursor",
    "windsurf": "windsurf",
    "codeium": "windsurf",
    "vscode": "generic",
    "vs code": "generic",
    "codex": "codex",
    "gemini": "gemini-cli",
    "gemini cli": "gemini-cli",
    "gemini-cli": "gemini-cli",
    "continue": "continue",
    "cline": "cline",
    "goose": "generic",
    "aider": "generic",
    "copilot": "copilot",
    "github copilot": "copilot",
    "amazon q": "amazon-q",
    "amazonq": "amazon-q",
    "amazon_q": "amazon-q",
    "kiro": "generic",
    "lm studio": "lm-studio",
    "lmstudio": "lm-studio",
    "openclaw": "generic",
}


def client_slug(name: str) -> str:
    lowered = name.strip().lower()
    if lowered in CLIENT_SLUGS:
        return CLIENT_SLUGS[lowered]
    for key, slug in CLIENT_SLUGS.items():
        if key in lowered:
            return slug
    return taxonomy.GENERIC
