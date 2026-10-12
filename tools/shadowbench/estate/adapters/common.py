"""Shared helpers for estate adapters."""

from __future__ import annotations

import re

from tools.shadowbench.estate import taxonomy

#: Client display names and ids, as third-party tools print them, mapped onto
#: `ai-client:` taxonomy values. Keys are written in normalized form (see
#: `normalize_client`); `client_slug` tries an exact match before any
#: substring match, so order here carries no meaning.
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
    "amazon-q": "amazon-q",
    "kiro": "generic",
    "lm studio": "lm-studio",
    "lmstudio": "lm-studio",
    "openclaw": "generic",
}

_QUALIFIER = re.compile(r"\([^)]*\)|\[[^\]]*\]")


def normalize_client(name: str) -> str:
    """Lowercase, `_` as `-`, whitespace collapsed: `Claude_Desktop ` -> `claude-desktop`."""
    return " ".join(name.lower().replace("_", "-").split())


_NORMALIZED_SLUGS = {normalize_client(key): slug for key, slug in CLIENT_SLUGS.items()}
_LONGEST_FIRST = sorted(_NORMALIZED_SLUGS.items(), key=lambda item: (-len(item[0]), item[0]))


def _contains(text: str, key: str) -> bool:
    return re.search(rf"(?<![a-z0-9]){re.escape(key)}(?![a-z0-9])", text) is not None


def client_slug(name: str) -> str:
    """The `ai-client:` value for a client name a tool printed.

    An exact match on the normalized name wins, then on the name without its
    parenthesized qualifiers (`Cline (VS Code)` is Cline, not VS Code), then
    the longest table key found as a whole word, so `Claude Desktop App` is
    Claude Desktop rather than the shorter `claude`.
    """
    full = normalize_client(name)
    head = normalize_client(_QUALIFIER.sub(" ", name))
    for candidate in (full, head):
        if candidate in _NORMALIZED_SLUGS:
            return _NORMALIZED_SLUGS[candidate]
    for candidate in (head, full):
        for key, slug in _LONGEST_FIRST:
            if candidate and _contains(candidate, key):
                return slug
    return taxonomy.GENERIC
