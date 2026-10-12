"""Shared helpers for estate adapters."""

from __future__ import annotations

import re
import shlex
from collections.abc import Sequence
from pathlib import Path

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


# --- Wrapper scripts ---------------------------------------------------------
#
# Some tools need a shell (output redirection, several steps per unit). Every
# value interpolated into a generated script is shell-quoted: run directories
# carry estate unit names, which come from the corpus and are untrusted.

#: Script lines that start the first-failure tracker `step` lines update.
STATUS_INIT = "status=0"
#: The last script line: the exit status of the first step that failed.
STATUS_EXIT = 'exit "$status"'


def sh_command(
    argv: Sequence[str | Path],
    *,
    stdin: str | Path | None = None,
    stdout: str | Path | None = None,
    stderr: str | Path | None = None,
) -> str:
    """One shell command line with every word and redirection target quoted."""
    line = shlex.join(str(part) for part in argv)
    for operator, target in (("<", stdin), (">", stdout), ("2>", stderr)):
        if target is not None:
            line += f" {operator} {shlex.quote(str(target))}"
    return line


def sh_step(
    argv: Sequence[str | Path],
    *,
    stdin: str | Path | None = None,
    stdout: str | Path | None = None,
    stderr: str | Path | None = None,
) -> str:
    """A command line that records its exit status in `status` unless an earlier step failed.

    The script keeps running later steps, then `STATUS_EXIT` reports the first
    failure, so a crash in any step never reads as a clean run. A failed
    redirection counts as a failed step.
    """
    command = sh_command(argv, stdin=stdin, stdout=stdout, stderr=stderr)
    return f'{command} || {{ rc=$?; [ "$status" -ne 0 ] || status=$rc; }}'


def write_script(path: Path, lines: Sequence[str]) -> Path:
    """Write an executable POSIX shell script."""
    path.write_text("\n".join(["#!/bin/sh", *lines]) + "\n", encoding="utf-8")
    path.chmod(0o755)
    return path


# --- Launcher shims ----------------------------------------------------------

#: Programs an MCP client configuration can name as a server command. A tool
#: that starts configured servers must never get to run one: the benchmark
#: never executes corpus content, whatever the host has installed.
LAUNCHERS: tuple[str, ...] = (
    "npx",
    "npm",
    "pnpm",
    "pnpx",
    "yarn",
    "bun",
    "bunx",
    "deno",
    "node",
    "nodejs",
    "uv",
    "uvx",
    "pipx",
    "python",
    "python3",
    *(f"python3.{minor}" for minor in range(8, 15)),
    "docker",
    "podman",
    "nerdctl",
    "java",
    "dotnet",
    "go",
)

_SHIM = "#!/bin/sh\nprintf '%s\\n' {message} >&2\nexit 126\n"


def refuse_launchers(directory: Path) -> list[str]:
    """Write refusing `LAUNCHERS` shims into `directory`; return the lines that put them first on PATH.

    Each shim prints why it refused and exits 126 without reading its
    arguments. Only PATH lookups are covered: an absolute command path in a
    client configuration, or a configuration that sets its own `PATH`, is
    not intercepted, so third-party tools still belong on a disposable
    runner with no credentials.
    """
    directory = directory.absolute()
    if ":" in str(directory):
        # A colon would split the PATH entry and silently disable every shim.
        raise ValueError(f"launcher shim directory must not contain ':': {directory}")
    directory.mkdir(exist_ok=True)
    for name in LAUNCHERS:
        message = f"shadowbench: refused to start {name}: the benchmark never executes corpus content"
        shim = directory / name
        shim.write_text(_SHIM.format(message=shlex.quote(message)), encoding="utf-8")
        shim.chmod(0o755)
    return [f'PATH={shlex.quote(str(directory))}:"$PATH"', "export PATH"]
