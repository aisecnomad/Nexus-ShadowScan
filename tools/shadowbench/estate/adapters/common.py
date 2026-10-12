"""Shared helpers for estate adapters."""

from __future__ import annotations

import re
import shlex
from collections.abc import Sequence
from pathlib import Path

from tools.shadowbench.estate import taxonomy

#: Client display names and ids, as third-party tools print them, mapped onto
#: `ai-client:` taxonomy values. Keys are compared as words (see
#: `client_words`), so case and separators do not matter; `client_slug`
#: tries an exact match before any partial one, so order here carries no
#: meaning.
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
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
_WORD = re.compile(r"[a-z0-9]+")
#: Keys shorter than this are only matched as whole words: `cline` is inside
#: `decline` and `incline`.
_MIN_FRAGMENT = 6


def client_words(name: str) -> tuple[str, ...]:
    """Lowercase alphanumeric words: `Claude_Desktop `, `claude-desktop` -> ('claude', 'desktop')."""
    return tuple(_WORD.findall(name.lower()))


_BY_WORDS = {client_words(key): slug for key, slug in CLIENT_SLUGS.items()}
_BY_COMPACT = {"".join(words): slug for words, slug in _BY_WORDS.items()}
_LONGEST_FIRST = sorted(_BY_WORDS.items(), key=lambda item: (-len("".join(item[0])), item[0]))


def _has_run(words: tuple[str, ...], key: tuple[str, ...]) -> bool:
    """Whether `key` occurs in `words` as consecutive whole words."""
    return any(words[start : start + len(key)] == key for start in range(len(words) - len(key) + 1))


def client_slug(name: str) -> str:
    """The `ai-client:` value for a client name a tool printed.

    Names compare as their run-together words, so case and separators do not
    matter (`Claude_Desktop`, `claude-desktop`, `ClaudeDesktop`). An exact
    match wins, first on the whole name, then on the name without its
    parenthesized qualifiers (`Cline (VS Code)` is Cline, not VS Code). Next
    comes the longest table key found as whole words, in the name as written
    or with camelCase split (`Claude Desktop App` is Claude Desktop rather
    than the shorter `claude`; `CopilotChat` is Copilot). Last, the longest
    key of at least `_MIN_FRAGMENT` letters inside the run-together name
    (`claudecodeagent`).
    """
    head = _QUALIFIER.sub(" ", name)
    for text in (name, head):
        compact = "".join(client_words(text))
        if compact in _BY_COMPACT:
            return _BY_COMPACT[compact]
    for text in (head, name):
        forms = (client_words(text), client_words(_CAMEL.sub(" ", text)))
        for key, slug in _LONGEST_FIRST:
            if any(_has_run(words, key) for words in forms):
                return slug
    for text in (head, name):
        compact = "".join(client_words(text))
        for key, slug in _LONGEST_FIRST:
            fragment = "".join(key)
            if len(fragment) >= _MIN_FRAGMENT and fragment in compact:
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
