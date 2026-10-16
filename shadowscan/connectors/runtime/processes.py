"""Runtime processes: AI agents, MCP servers and model servers seen running.

``runtime.processes`` reads process inventories and reports, per host and
user, the AI tools that were running: coding-agent CLIs, AI desktop apps, MCP
servers launched by a client, local model servers and agent frameworks'
development servers. A running process is the strongest local evidence that a
configured tool is in use; the engine links these findings to the
``endpoint.inventory`` findings for the same tool on the same device (see
``shadowscan.correlation``).

Offline, ``input`` reads osquery ``processes`` results (an array of rows or
logger lines with ``columns`` and ``hostIdentifier``), Microsoft Defender
``DeviceProcessEvents``, CrowdStrike process events, or any JSON/CSV with a
command line or executable name. Live, the connector reads ``/proc`` on Linux
without following the ``exe`` link.

Command lines can carry credentials (``--api-key sk-...``), so a command line
never enters a finding or a ``--dump-records`` export: only the matched tool,
the executable's base name and, for an MCP server, its package name are kept.
"""

from __future__ import annotations

import os
import platform
import re
import socket
import stat
import time
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar

from shadowscan.connectors.base import (
    BaseConnector,
    ConnectorContext,
    ConnectorError,
    _NoDump,
    _positive_limit,
)
from shadowscan.connectors.common import finalize
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.utils.text import parse_timestamp


@dataclass(frozen=True, slots=True)
class ProcessRule:
    tool: str  # stable id used in resources
    product: str
    signature: str | None
    role: str  # agent | app | mcp-server | model-server | framework


# Executable base names (lower case, without ``.exe``) that are the tool itself.
EXECUTABLES: dict[str, ProcessRule] = {
    "claude": ProcessRule("claude-code", "Claude Code", "coding-agent.claude-code", "agent"),
    "codex": ProcessRule("codex", "OpenAI Codex CLI", "coding-agent.openai-codex", "agent"),
    "gemini": ProcessRule("gemini-cli", "Gemini CLI", "coding-agent.gemini-cli", "agent"),
    "aider": ProcessRule("aider", "Aider", "coding-agent.aider", "agent"),
    "goose": ProcessRule("goose", "Goose", "coding-agent.goose", "agent"),
    "goosed": ProcessRule("goose", "Goose", "coding-agent.goose", "agent"),
    "openclaw": ProcessRule("openclaw", "OpenClaw", "coding-agent.openclaw", "agent"),
    "opencode": ProcessRule("opencode", "OpenCode", None, "agent"),
    "cursor-agent": ProcessRule("cursor-agent", "Cursor CLI", "coding-agent.cursor", "agent"),
    "kiro-cli": ProcessRule("kiro-cli", "Kiro CLI", None, "agent"),
    "ollama": ProcessRule("ollama", "Ollama", None, "model-server"),
    "llama-server": ProcessRule("llama-cpp", "llama.cpp server", None, "model-server"),
    "lms": ProcessRule("lm-studio", "LM Studio", None, "model-server"),
    "github-mcp-server": ProcessRule(
        "mcp:github-mcp-server", "GitHub MCP server", "protocol.mcp", "mcp-server"
    ),
}
# Desktop applications, by executable base name and a path fragment that identifies the vendor's bundle.
DESKTOP_APPS: tuple[tuple[str, str, ProcessRule], ...] = (
    ("claude", "claude.app/", ProcessRule("claude-desktop", "Claude Desktop", None, "app")),
    ("claude", "anthropicclaude", ProcessRule("claude-desktop", "Claude Desktop", None, "app")),
    ("chatgpt", "chatgpt.app/", ProcessRule("chatgpt-desktop", "ChatGPT desktop", None, "app")),
    ("chatgpt", "openai.chatgpt", ProcessRule("chatgpt-desktop", "ChatGPT desktop", None, "app")),
    ("cursor", "cursor", ProcessRule("cursor", "Cursor", "coding-agent.cursor", "app")),
    ("windsurf", "windsurf", ProcessRule("windsurf", "Windsurf", "coding-agent.windsurf", "app")),
    ("lm studio", "lm studio", ProcessRule("lm-studio", "LM Studio", None, "model-server")),
    ("ollama", "ollama.app/", ProcessRule("ollama", "Ollama", None, "model-server")),
)
# Packages run through node, npx, uvx, pipx or python -m.
PACKAGES: tuple[tuple[re.Pattern[str], ProcessRule], ...] = (
    (re.compile(r"@anthropic-ai/claude-code(?:@|/|$)"), EXECUTABLES["claude"]),
    (re.compile(r"@openai/codex(?:@|/|$)"), EXECUTABLES["codex"]),
    (re.compile(r"@google/gemini-cli(?:@|/|$)"), EXECUTABLES["gemini"]),
    (re.compile(r"(?:^|/)openclaw(?:@|/|$)"), EXECUTABLES["openclaw"]),
    (re.compile(r"^aider(?:\.main)?$|(?:^|/)aider-chat(?:@|$)"), EXECUTABLES["aider"]),
    (
        re.compile(r"^vllm(?:\.entrypoints\.[\w.]+)?$"),
        ProcessRule("vllm", "vLLM", "provider.vllm", "model-server"),
    ),
    (re.compile(r"^open[-_]webui$"), ProcessRule("open-webui", "Open WebUI", None, "app")),
    (
        re.compile(r"^litellm(?:\.proxy[\w.]*)?$"),
        ProcessRule("litellm", "LiteLLM proxy", "platform.litellm", "app"),
    ),
    (re.compile(r"^crewai$"), ProcessRule("crewai", "CrewAI", "framework.crewai", "framework")),
    (
        re.compile(r"^langgraph(?:[-_]cli)?$"),
        ProcessRule("langgraph", "LangGraph server", "framework.langgraph", "framework"),
    ),
)
_MCP_PACKAGE = re.compile(
    r"^(?:@modelcontextprotocol/server-[\w.-]+|@[\w.-]+/[\w.-]*mcp[\w.-]*|[\w.-]*mcp[-_]server[\w.-]*|"
    r"mcp[-_][\w.-]+|[\w.-]+[-_]mcp)(?:@[\w.^~<>=-]+)?$",
    re.IGNORECASE,
)
_LAUNCHERS = {
    "node", "nodejs", "npx", "npm", "bunx", "bun", "deno", "uvx", "uv", "pipx", "python", "python3",
    "pnpm", "yarn",
}  # fmt: skip
# A package manager subcommand that installs or inspects rather than runs: nothing after it is running.
_NOT_RUNNING = {
    "install", "i", "ci", "add", "remove", "rm", "uninstall", "update", "upgrade", "list", "ls", "init",
    "publish", "pip", "sync", "lock", "build", "audit", "outdated", "info", "view", "show",
}  # fmt: skip
_PYTHON = re.compile(r"^python(?:\d+(?:\.\d+)?)?w?$")
_WHITESPACE = re.compile(r"\s")
# Single-letter interpreter options without a value (-W and -X take one; -m names the module).
_PYTHON_FLAGS = frozenset("bBdEiIOPqRsSuvx")


@dataclass(frozen=True, slots=True)
class _Grammar:
    """The options a launcher may put before its target, so they are skipped rather than guessed."""

    flags: frozenset[str]  # options without a value
    values: frozenset[str]  # options that take the next argument as their value
    prefixes: tuple[str, ...] = ()  # option families without a value (deno's --allow-net)
    stops: frozenset[str] = frozenset()  # inline code or a shell command: no target runs
    modules: frozenset[str] = frozenset()  # options naming a Python module to run (uv run -m)


_RUN_GRAMMAR = _Grammar(
    flags=frozenset(
        {
            "-y", "--yes", "-q", "--quiet", "--no-cache", "--offline", "--isolated", "--prefer-offline",
            "--prefer-online", "--no-install", "--ignore-existing", "--silent", "--frozen", "--locked",
            "--no-sync", "--no-project", "--no-dev", "--all-extras", "--exact", "--no-config",
        }
    ),
    values=frozenset(
        {
            "--from", "--with", "--with-requirements", "--with-editable", "--python", "--index",
            "--index-url", "--default-index", "--extra-index-url", "--find-links", "--directory",
            "--project", "--package", "--spec", "--registry", "--cache", "--cwd", "--extra", "--group",
            "--env-file", "-p",
        }
    ),
    stops=frozenset({"-c", "--call"}),
)  # fmt: skip
# uv run also runs a Python module: `uv run -m aider`.
_UV_RUN_GRAMMAR = _Grammar(
    _RUN_GRAMMAR.flags, _RUN_GRAMMAR.values, stops=_RUN_GRAMMAR.stops, modules=frozenset({"-m", "--module"})
)
_NODE_GRAMMAR = _Grammar(
    flags=frozenset(
        {
            "--no-warnings", "--enable-source-maps", "--experimental-strip-types", "--inspect",
            "--inspect-brk", "--inspect-wait", "--no-deprecation", "--trace-warnings",
            "--trace-deprecation", "--expose-gc", "--preserve-symlinks", "--preserve-symlinks-main",
        }
    ),
    values=frozenset({"-r", "--require", "--import", "--loader", "--experimental-loader", "--env-file"}),
    stops=frozenset(
        {"-e", "--eval", "-p", "--print", "-c", "--check", "-i", "--interactive", "--test", "--run"}
    ),
)  # fmt: skip
_DENO_GRAMMAR = _Grammar(
    flags=frozenset(
        {
            "-A", "-R", "-W", "-N", "-E", "-S", "-I", "-q", "--quiet", "--no-prompt", "--no-check",
            "--reload", "-r", "--watch", "--lock", "--no-lock", "--cached-only", "--no-remote", "--no-npm",
            "--node-modules-dir", "--env-file",
        }
    ),
    values=frozenset({"-c", "--config", "--import-map", "--cert", "--location", "--seed"}),
    prefixes=("--allow-", "--deny-", "--unstable"),
)  # fmt: skip
# Subcommands that run a target, per launcher; any other subcommand runs none.
_RUN_SUBCOMMANDS = {
    "npm": {"exec", "x"},
    "pnpm": {"exec", "dlx"},
    "yarn": {"exec", "dlx"},
    "pipx": {"run"},
    "bun": {"x"},
    "deno": {"run"},
    "uv": {"run", "tool"},
}
# Package runners are interpreter scripts (a shebang, or a .cmd shim on Windows): the kernel
# shows `node /usr/bin/npx -y pkg` or `python3 /usr/bin/pipx run ...`. These script names run
# as the runner they name.
_RUNNER_SCRIPTS = {
    "npx": "npx", "npx-cli.js": "npx", "npm": "npm", "npm-cli.js": "npm", "pnpm": "pnpm",
    "pnpm.cjs": "pnpm", "pnpm.js": "pnpm", "yarn": "yarn", "yarn.js": "yarn", "pipx": "pipx",
    "uv": "uv", "uvx": "uvx",
}  # fmt: skip
# Python modules that are package runners: `python -m pipx run ...`, `python -m uv run ...`.
_RUNNER_MODULES = frozenset({"pipx", "uv"})

# Field names of process exports, in order of preference.
_HOST_FIELDS = (
    "host",
    "hostname",
    "host_name",
    "computer_name",
    "ComputerName",
    "DeviceName",
    "device",
    "aid",
)
_USER_FIELDS = ("user", "username", "user_name", "UserName", "AccountName", "InitiatingProcessAccountName")
_CMD_FIELDS = ("cmdline", "command_line", "CommandLine", "ProcessCommandLine", "command", "args")
_EXE_FIELDS = ("path", "exe", "executable", "image", "ImageFileName", "FolderPath", "process_path")
_NAME_FIELDS = ("name", "process_name", "FileName", "comm")
_TIME_FIELDS = ("start_time", "Timestamp", "timestamp", "ts", "time", "ProcessCreationTime", "@timestamp")
_PID_FIELDS = ("pid", "ProcessId", "process_id", "TargetProcessId")
_PROC = Path("/proc")
_MAX_CMDLINE_BYTES = 64 * 1024
# No package or module name is longer (npm allows 214 characters, with room for a version
# spec). The package patterns backtrack on long arguments, and Python's re holds the GIL
# for a whole match: an unprivileged process's argument, or one offline row, must not
# stall every connector and the deadline that would stop them.
_MAX_PACKAGE_CANDIDATE = 256
_MAX_ARGV = 64
_MAX_IDENTITY_CHARS = 4096

# Only these fixed labels leave collection. Paths and environment values never do.
_LIBRARIES = {
    "ggml": re.compile(r"libggml(?:[-_.]|$)"),
    "llama": re.compile(r"libllama(?:[-_.]|$)"),
    "torch": re.compile(r"libtorch(?:[-_.]|$)"),
    "onnxruntime": re.compile(r"(?:lib)?onnxruntime(?:[-_.]|$)"),
    "tokenizers": re.compile(r"(?:lib)?tokenizers(?:[-_.]|$)"),
    "vllm": re.compile(r"vllm(?:[-_.]|$)"),
}
_MODEL_FORMATS = {"gguf", "safetensors", "onnx"}
_ENV_KEYS = {
    "OLLAMA_HOST",
    "OLLAMA_MODELS",
    "VLLM_WORKER_MULTIPROC_METHOD",
    "VLLM_ATTENTION_BACKEND",
    "HF_HOME",
    "CUDA_VISIBLE_DEVICES",
    "TGI_HOSTNAME",
}
_INSPECTION_STATUSES = {"ok", "denied", "unreadable", "truncated", "not_requested", "not_applicable"}
# Statuses that leave inspection scope complete: read, not asked for, or a
# source the process does not have (ESRCH from a zombie whose threads have all
# exited, so no address space or descriptor table is left).
_COMPLETE_STATUSES = {"ok", "not_requested", "not_applicable"}
# /proc/<pid>/stat states of a process whose leader thread has exited.
_EXITED_STATES = {"Z", "X"}
# PF_KTHREAD in the flags field of /proc/<pid>/stat.
_PF_KTHREAD = 0x00200000
_MAP_LINE = re.compile(
    r"^[0-9a-f]+-[0-9a-f]+\s+[rwxps-]{4}\s+[0-9a-f]+\s+[0-9a-f]+:[0-9a-f]+\s+\d+(?:\s+(.*))?$", re.I
)


class _InspectionLimit(Exception):
    """A fixed, non-sensitive limit reason."""


class _KernelThread(Exception):
    """A kernel thread: no user environment, mappings or descriptors to inspect."""


@dataclass
class _InspectionBudget:
    ctx: ConnectorContext
    total_bytes: int
    total_entries: int
    deadline: float
    process_bytes: int = 0

    def check(self) -> None:
        self.ctx.check_deadline()
        if time.monotonic() >= self.deadline:
            raise _InspectionLimit("inspection deadline")

    def entry(self) -> None:
        self.check()
        if self.total_entries <= 0:
            raise _InspectionLimit("inspection entry budget")
        self.total_entries -= 1

    def read(self, directory: int, name: str, limit: int) -> bytes:
        self.check()
        size = min(limit, self.process_bytes, self.total_bytes)
        if size <= 0:
            raise _InspectionLimit("inspection byte budget")
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError("not a regular proc file")
            chunks: list[bytes] = []
            remaining = size
            while remaining:
                self.check()
                chunk = os.read(fd, min(remaining, 8192))
                if not chunk:
                    return b"".join(chunks)
                chunks.append(chunk)
                remaining -= len(chunk)
                self.process_bytes -= len(chunk)
                self.total_bytes -= len(chunk)
            # Reaching a cap is conservatively incomplete; do not read past a budget.
            raise _InspectionLimit("inspection byte budget")
        finally:
            os.close(fd)


def _stat_fields(directory: int, budget: _InspectionBudget) -> list[str]:
    """The /proc/<pid>/stat fields after the command name (``fields[0]`` is the state)."""
    raw = budget.read(directory, "stat", 4096).decode("ascii", "replace")
    end = raw.rfind(")")
    fields = raw[end + 1 :].split() if end >= 0 else []
    if (
        len(fields) < 20
        or not fields[19].isascii()
        or not fields[19].isdecimal()
        or not fields[6].isascii()
        or not fields[6].isdecimal()
    ):
        raise ValueError("malformed process stat")
    return fields


def _proc_state(directory: int, budget: _InspectionBudget) -> tuple[str, int]:
    """The process state and its thread count (``num_threads``)."""
    fields = _stat_fields(directory, budget)
    if not fields[17].isascii() or not fields[17].isdecimal():
        raise ValueError("malformed process stat")
    return fields[0], int(fields[17])


def _proc_identity(directory: int, budget: _InspectionBudget) -> dict[str, str]:
    fields = _stat_fields(directory, budget)
    if int(fields[6]) & _PF_KTHREAD:
        raise _KernelThread
    namespace = os.open("ns", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
    try:
        inode = os.stat("pid", dir_fd=namespace).st_ino
    finally:
        os.close(namespace)
    return {"pid_namespace": str(inode), "start_time_ticks": fields[19]}


def _maps(raw: bytes, budget: _InspectionBudget, max_entries: int) -> tuple[list[str], list[str]]:
    libraries: set[str] = set()
    packaging: set[str] = set()
    for number, line in enumerate(raw.decode("utf-8", "replace").splitlines()):
        budget.entry()
        if number >= max_entries:
            raise _InspectionLimit("mapping count")
        match = _MAP_LINE.fullmatch(line)
        if match is None:
            raise ValueError("malformed process maps")
        path = (match.group(1) or "").removesuffix(" (deleted)")
        base = path.rsplit("/", 1)[-1].lower()
        libraries.update(name for name, pattern in _LIBRARIES.items() if pattern.match(base))
        if any(part.startswith("_MEI") for part in path.split("/")):
            packaging.add("pyinstaller")
    return sorted(libraries), sorted(packaging)


def _fd_indicators(
    directory: int, budget: _InspectionBudget, max_entries: int
) -> tuple[list[str], list[str]]:
    formats: set[str] = set()
    packaging: set[str] = set()
    fd_directory = os.open("fd", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
    try:
        with os.scandir(fd_directory) as entries:
            for number, entry in enumerate(entries):
                budget.entry()
                if number >= max_entries:
                    raise _InspectionLimit("descriptor count")
                if not entry.name.isascii() or not entry.name.isdecimal():
                    raise ValueError("malformed descriptor name")
                if min(budget.process_bytes, budget.total_bytes) < 4096:
                    raise _InspectionLimit("descriptor link byte budget")
                try:
                    target = os.readlink(entry.name, dir_fd=fd_directory)
                except FileNotFoundError:
                    budget.ctx.warn(
                        "runtime.processes: descriptor closed during inspection", incomplete=False
                    )
                    continue  # A descriptor can close independently of the process.
                count = len(target.encode("utf-8", "replace"))
                budget.process_bytes -= count
                budget.total_bytes -= count
                if count > 4096 or budget.process_bytes < 0 or budget.total_bytes < 0:
                    raise _InspectionLimit("descriptor link byte budget")
                path = target.removesuffix(" (deleted)")
                suffix = path.rsplit(".", 1)[-1].lower()
                if suffix in _MODEL_FORMATS:
                    formats.add(suffix)
                if any(part.startswith("_MEI") for part in path.split("/")):
                    packaging.add("pyinstaller")
    finally:
        os.close(fd_directory)
    return sorted(formats), sorted(packaging)


_Match = tuple[ProcessRule, str | None]
# A launcher's target: the name it runs, the arguments after it, and whether the name is a
# "command" (a runner's positional), a "module" (python -m) or a "script" (an interpreter's file).
_Target = tuple[str, list[str], str]


def classify(executable: str | None, argv: list[str]) -> _Match | None:
    """The AI tool a process runs, and an MCP package name when it is an MCP server."""
    return _classify(executable, argv)[0]


def classify_command(executable: str | None, argv: list[str]) -> tuple[_Match | None, bool]:
    """``classify`` of a process, and whether more arguments could have changed a None.

    When the executable does not identify a tool, ``argv[0]`` is read as well: a process title
    or shebang can name the launcher there while the executable is its interpreter (osquery's
    ``path`` is node for ``npm exec ...``). A process title that replaced the command line is a
    single argument with spaces in ``/proc/<pid>/cmdline`` (npm's ``npm exec pkg``), so an
    ``argv[0]`` with whitespace is also read split into words, ahead of the other arguments. The
    flag is true when the arguments ran out before a launcher's target was read, or when there
    were none: only then can arguments an argument or byte limit dropped change the result.
    """
    match, exhausted = _classify(executable, argv)
    if match is None and executable and argv:
        match, title_exhausted = _classify(None, argv)
        exhausted = exhausted or title_exhausted
    if match is None and argv and _WHITESPACE.search(argv[0]):
        title, cut = _split_bounded(argv[0])
        if len(title) > 1:
            # A title cut by the bounds is not followed by the arguments after it.
            match, title_exhausted = _classify(None, title if cut else [*title, *argv[1:]])
            exhausted = exhausted or title_exhausted
    return match, match is None and (exhausted or not argv)


def _classify(executable: str | None, argv: list[str], depth: int = 0) -> tuple[_Match | None, bool]:
    """``classify``, and whether more arguments could change a None (the launcher's target was unread)."""
    if depth >= _MAX_ARGV:
        return None, False
    exe = (executable or (argv[0] if argv else "") or "").replace("\\", "/")
    if not exe:
        return None, True
    base = exe.rsplit("/", 1)[-1].lower()
    base = base[:-4] if base.endswith(".exe") else base
    lowered = exe.lower()
    for name, fragment, rule in DESKTOP_APPS:
        if base == name and fragment in lowered:
            return (rule, None), False
    if base in EXECUTABLES:
        if base == "ollama":
            # `ollama list` and `ollama pull` do not run a model.
            if len(argv) < 2:
                return None, True
            if argv[1] not in {"serve", "run", "runner"}:
                return None, False
        return (EXECUTABLES[base], None), False
    if base not in _LAUNCHERS and not _PYTHON.match(base):
        return None, False
    target, exhausted = _target(base, argv[1:])
    if target is None:
        return None, exhausted
    name, rest, kind = target
    if name in _NOT_RUNNING:
        return None, False
    name = name.replace("\\", "/")
    leaf = name.rsplit("/", 1)[-1].lower()
    if kind == "script":
        runner = _RUNNER_SCRIPTS.get(leaf.removesuffix(".exe"))
        if runner is not None:
            return _classify(runner, [runner, *rest], depth + 1)
        if _PYTHON.match(base):
            return None, False  # a Python script names no package; only -m does
        if "/node_modules/" in name and base in {"node", "nodejs"}:
            tail = name.split("/node_modules/")[-1].split("/")
            name = "/".join(tail[:2]) if tail[0].startswith("@") else tail[0]
        elif base == "deno" and name.startswith("npm:"):
            name = name[4:]
    elif kind == "module":
        if name in _RUNNER_MODULES:
            return _classify(name, [name, *rest], depth + 1)
    else:
        # A package runner executes its positional command, not the package named by
        # --from/--package, nor a later argument to that command.
        leaf = leaf.removesuffix(".exe")
        if leaf in EXECUTABLES or leaf in _LAUNCHERS or _PYTHON.match(leaf):
            return _classify(name, [name, *rest], depth + 1)
    return _package_rule(name), False


def _package_rule(name: str) -> _Match | None:
    """The rule a package or module name matches."""
    if len(name) > _MAX_PACKAGE_CANDIDATE:
        return None
    for pattern, rule in PACKAGES:
        if pattern.search(name):
            return rule, None
    if _MCP_PACKAGE.match(name):
        package = name.rsplit("@", 1)[0] if name.count("@") > (1 if name.startswith("@") else 0) else name
        return ProcessRule(f"mcp:{package.lower()}", "MCP server", "protocol.mcp", "mcp-server"), package
    return None


def _target(launcher: str, args: list[str]) -> tuple[_Target | None, bool]:
    """Only the executed module, script or command, using the launcher's grammar.

    Unknown options are not guessed. Dependencies supplied with --from, --package,
    --require or --import do not establish the executed tool. The flag is true when the
    arguments ran out before the target, so more arguments could have named one.
    """
    if _PYTHON.match(launcher):
        return _python_target(args)
    if launcher in {"node", "nodejs"}:
        found, exhausted = _positional(args, _NODE_GRAMMAR)
        return (None, exhausted) if found is None else ((found[0], found[1], "script"), False)
    grammar = _DENO_GRAMMAR if launcher == "deno" else _RUN_GRAMMAR
    found, exhausted = _positional(args, grammar)
    if found is None:
        return None, exhausted
    name, rest, kind = found
    if launcher in _RUN_SUBCOMMANDS:
        if name not in _RUN_SUBCOMMANDS[launcher]:
            return None, False
        if launcher == "uv" and name == "tool":
            found, exhausted = _positional(rest, grammar)
            if found is None:
                return None, exhausted
            if found[0] != "run":
                return None, False
            rest = found[1]
        elif launcher == "uv":
            grammar = _UV_RUN_GRAMMAR
        found, exhausted = _positional(rest, grammar)
        if found is None:
            return None, exhausted
        name, rest, kind = found
        return (name, rest, "script" if launcher == "deno" else kind), False
    return (name, rest, kind), False


def _python_target(args: list[str]) -> tuple[_Target | None, bool]:
    """The module (-m) or script a Python interpreter runs, reading its options as CPython does."""
    i = 0
    while i < len(args):
        arg = args[i]
        i += 1
        if not arg.startswith("-") or arg == "-" or arg == "--" or arg.startswith("--"):
            if arg == "--":
                return ((args[i], args[i + 1 :], "script"), False) if i < len(args) else (None, True)
            if arg.startswith("-"):
                return None, False  # stdin, or a long option not read here
            return (arg, args[i:], "script"), False
        # Short options can be combined (-Im, -BW ignore): read them a letter at a time.
        for position in range(1, len(arg)):
            letter = arg[position]
            if letter in _PYTHON_FLAGS:
                continue
            if letter in "mWX":
                value = arg[position + 1 :]
                if not value:
                    if i >= len(args):
                        return None, True
                    value = args[i]
                    i += 1
                if letter == "m":
                    return (value, args[i:], "module"), False
                break  # the rest of this argument was the -W or -X value
            # -c (inline code) and any option not known here: no module or script runs, or
            # it is not guessed which one does.
            return None, False
    return None, True


def _positional(args: list[str], grammar: _Grammar) -> tuple[tuple[str, list[str], str] | None, bool]:
    """Read one positional operand, consuming only recognized option values.

    Returns the operand, the arguments after it and its kind ("module" when a module option
    named it, else "command"), or None and whether the arguments ran out before an operand.
    A ``--name=value`` option carries its own value, so an unknown one is skipped rather than
    read as taking the next argument; one that runs inline code stops the search.
    """
    i = 0
    while i < len(args):
        arg = args[i]
        i += 1
        if arg == "--":
            return ((args[i], args[i + 1 :], "command"), False) if i < len(args) else (None, True)
        name, assigned, value = arg.partition("=") if arg.startswith("-") else (arg, "", "")
        if name in grammar.stops:
            return None, False
        if name in grammar.modules:
            if assigned:
                return (value, args[i:], "module"), False
            return ((args[i], args[i + 1 :], "module"), False) if i < len(args) else (None, True)
        if assigned:
            if name.startswith("--") or name in grammar.flags or name in grammar.values:
                continue
            return None, False
        if name in grammar.values:
            if i >= len(args):
                return None, True
            i += 1
        elif name in grammar.flags or (grammar.prefixes and name.startswith(grammar.prefixes)):
            continue
        elif arg.startswith("-"):
            return None, False
        else:
            return (arg, args[i:], "command"), False
    return None, True


@dataclass
class _Run:
    host: str
    user: str
    rule: ProcessRule
    processes: int = 0
    pids: list[int] = field(default_factory=list)
    executables: Counter = field(default_factory=Counter)
    packages: Counter = field(default_factory=Counter)
    first: str | None = None
    last: str | None = None
    observed_at: str | None = None
    inspections: list[dict[str, Any]] = field(default_factory=list)
    truncated: int = 0


class RuntimeProcessConnector(BaseConnector, _NoDump):
    # Command lines can carry credentials: records are never exported with --dump-records.

    name: ClassVar[str] = "runtime.processes"
    surface: ClassVar[Surface] = Surface.RUNTIME
    provider: ClassVar[str | None] = "runtime"
    description: ClassVar[str] = (
        "AI agents, desktop apps, MCP servers and model servers running on hosts, from process inventories "
        "(osquery, EDR exports) or the local /proc."
    )
    config_keys: ClassVar[dict[str, str]] = {
        "label": "host name used when records carry none (default: the host name)",
        "max_processes": "maximum processes read from /proc in live mode (default 100,000)",
        "inspect_maps": "live only: inspect bounded mapped-library names (default false)",
        "inspect_fds": "live only: inspect descriptor links, never targets (default false)",
        "inspect_env_keys": "live only: allowlisted environment key names to inspect (default empty)",
        "max_inspection_bytes": "maximum inspection bytes per process (default 262,144)",
        "max_inspection_total_bytes": "maximum inspection bytes across the scan (default 16,777,216)",
        "max_inspection_entries": "maximum mappings, descriptors and environment entries per scan (100,000)",
        "max_mappings": "maximum mappings per process (default 4,096)",
        "max_fds": "maximum descriptors per process (default 1,024)",
        "inspection_timeout_seconds": "maximum live inspection duration in seconds (default 30)",
        "input": (
            "offline: osquery processes results, Defender DeviceProcessEvents, CrowdStrike process events or "
            "JSON/CSV with a command line or executable"
        ),
    }
    offline_formats: ClassVar[str] = "JSON / JSONL / CSV process inventories (osquery, Defender, CrowdStrike)"

    def __init__(self, ctx: ConnectorContext) -> None:
        super().__init__(ctx)
        self.label = str(ctx.get("label") or socket.gethostname() or "host")
        self.max_processes = _positive_limit(ctx.get("max_processes", 100_000), "max_processes")
        self.inspect_maps = ctx.get("inspect_maps", False)
        self.inspect_fds = ctx.get("inspect_fds", False)
        if not isinstance(self.inspect_maps, bool) or not isinstance(self.inspect_fds, bool):
            raise ConnectorError("inspect_maps and inspect_fds must be booleans")
        env_keys = ctx.get("inspect_env_keys", [])
        if not isinstance(env_keys, list) or any(
            not isinstance(key, str) or key not in _ENV_KEYS for key in env_keys
        ):
            raise ConnectorError("inspect_env_keys must contain only documented allowlisted key names")
        self.inspect_env_keys = set(env_keys)
        self.inspection_enabled = bool(self.inspect_maps or self.inspect_fds or self.inspect_env_keys)
        self.max_inspection_bytes = _positive_limit(
            ctx.get("max_inspection_bytes", 262_144), "max_inspection_bytes"
        )
        self.max_inspection_total_bytes = _positive_limit(
            ctx.get("max_inspection_total_bytes", 16_777_216), "max_inspection_total_bytes"
        )
        self.max_inspection_entries = _positive_limit(
            ctx.get("max_inspection_entries", 100_000), "max_inspection_entries"
        )
        self.max_mappings = _positive_limit(ctx.get("max_mappings", 4096), "max_mappings")
        self.max_fds = _positive_limit(ctx.get("max_fds", 1024), "max_fds")
        self.inspection_timeout_seconds = _positive_limit(
            ctx.get("inspection_timeout_seconds", 30), "inspection_timeout_seconds"
        )

    # ------------------------------------------------------------------ live
    def collect(self) -> Iterable[dict[str, Any]]:
        proc = _PROC
        if platform.system() != "Linux" or not proc.is_dir():
            raise ConnectorError(
                "runtime.processes: live mode reads /proc on Linux; elsewhere export osquery processes and "
                "set 'input'"
            )
        restricted = _restricted_view(proc)
        if restricted:
            # Processes this view cannot list are invisible, not merely unreadable.
            self.ctx.warn(f"runtime.processes: not every process is visible: {restricted}")
        seen = 0
        unreadable = 0
        truncated = 0
        unread = 0
        inspection_stopped = False
        users: dict[int, str] = {}
        budget = _InspectionBudget(
            self.ctx,
            self.max_inspection_total_bytes,
            self.max_inspection_entries,
            time.monotonic() + self.inspection_timeout_seconds,
        )
        for entry in os.scandir(proc):
            self.ctx.check_deadline()
            if not entry.name.isdigit():
                continue
            if seen >= self.max_processes:
                self.ctx.warn(
                    f"runtime.processes: stopped after max_processes ({self.max_processes:,}) processes"
                )
                break
            seen += 1
            inspection: dict[str, Any] | None = None
            observed_at = datetime.now(UTC).isoformat()
            try:
                directory = os.open(proc / entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    before: dict[str, str] | None = None
                    if self.inspection_enabled and not inspection_stopped:
                        if (
                            budget.total_bytes <= 0
                            or budget.total_entries <= 0
                            or time.monotonic() >= budget.deadline
                        ):
                            inspection_stopped = True
                            self.ctx.warn(
                                "runtime.processes: inspection scan budget/deadline reached; "
                                "command-line collection continues without inspection"
                            )
                    if self.inspection_enabled and not inspection_stopped:
                        budget.process_bytes = self.max_inspection_bytes
                        before = self._inspection_identity(directory, budget)
                    fd = os.open("cmdline", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
                    try:
                        raw = os.read(fd, _MAX_CMDLINE_BYTES + 1)
                    finally:
                        os.close(fd)
                    cut = len(raw) > _MAX_CMDLINE_BYTES
                    if cut:
                        # Classify the bounded prefix (argv[0] and the leading
                        # arguments), dropping the final argument the limit may
                        # have cut: a partial name must not match a rule alone.
                        raw = raw[: raw.rfind(b"\0", 0, _MAX_CMDLINE_BYTES) + 1]
                    uid = os.fstat(directory).st_uid
                    if before is not None:
                        inspection = self._inspect(directory, budget)
                        after = self._inspection_identity(directory, budget)
                        if after is None:
                            inspection = None  # Retain independent command-line evidence only.
                        elif after != before:
                            self.ctx.warn(
                                "runtime.processes: process identity changed during inspection; omitted",
                                incomplete=False,
                            )
                            continue
                        else:
                            inspection["identity"] = before
                finally:
                    os.close(directory)
            except FileNotFoundError:
                if self.inspection_enabled:
                    self.ctx.warn(
                        "runtime.processes: process exited during inspection; omitted", incomplete=False
                    )
                continue  # exited while listing
            except OSError:
                unreadable += 1
                continue
            argv = [a.decode("utf-8", "replace") for a in raw.split(b"\0") if a]
            argv, limited = _bounded_argv(argv)
            cut = cut or limited
            match, undecided = classify_command(None, argv)
            if cut:
                truncated += 1
                unread += undecided
            if match is None and not inspection:
                continue
            if uid not in users:
                users[uid] = _user_name(uid)
            record: dict[str, Any] = {
                "host": self.label,
                "user": users[uid],
                "pid": int(entry.name),
                "argv": argv,
                "observed_at": observed_at,
            }
            if inspection is not None:
                record["inspection"] = inspection
            if cut:
                record["argv_truncated"] = True
            yield record
        if truncated:
            self._warn_truncated(truncated, unread)
        if unreadable:
            self.ctx.warn(f"runtime.processes: {unreadable} process(es) could not be read")

    def _warn_truncated(self, truncated: int, unread: int) -> None:
        """One counted warning for command lines cut by a limit or by their source.

        Only a command line whose leading complete arguments leave its tool undecided (none
        retained, or a launcher whose target was cut away) is a coverage gap: arguments after
        the executed tool, or any of a program that is no launcher, cannot change what runs.
        """
        source = "" if not self.offline else " or were truncated by their source export"
        outcome = (
            f"{unread} could not be classified from their leading complete arguments"
            if unread
            else "each was classified from its leading complete arguments"
        )
        self.ctx.warn(
            f"runtime.processes: {truncated} command line(s) exceeded argument/byte limits "
            f"({_MAX_ARGV} arguments, {_MAX_CMDLINE_BYTES:,} bytes){source}; {outcome}",
            incomplete=bool(unread),
        )

    def _inspection_identity(self, directory: int, budget: _InspectionBudget) -> dict[str, str] | None:
        """Unavailable enrichment never erases readable, independent command-line evidence."""
        try:
            return _proc_identity(directory, budget)
        except _KernelThread:
            # Linux returns ESRCH for a kernel thread's environ and similar
            # sources; it runs no user program, so inspection does not apply.
            return None
        except FileNotFoundError:
            # A namespace/stat file can be unavailable on a still-readable PID. Only
            # classify this as process disappearance if its command line also vanished.
            os.stat("cmdline", dir_fd=directory, follow_symlinks=False)
            self.ctx.warn("runtime.processes: inspection identity unavailable; inspection omitted")
        except _InspectionLimit as exc:
            self.ctx.warn(f"runtime.processes: {exc}; inspection omitted")
        except (OSError, ValueError):
            self.ctx.warn(
                "runtime.processes: inspection identity unreadable or malformed; inspection omitted"
            )
        return None

    def _inspect(self, directory: int, budget: _InspectionBudget) -> dict[str, Any]:
        result: dict[str, Any] = {
            "mapped_libraries": [],
            "open_model_formats": [],
            "packaging": [],
            "environment_keys": [],
            "status": {"maps": "not_requested", "fds": "not_requested", "environ": "not_requested"},
        }
        # Whether a read source yielded any indicator.
        found: dict[str, bool] = {}
        for source, enabled in (
            ("maps", self.inspect_maps),
            ("fds", self.inspect_fds),
            ("environ", bool(self.inspect_env_keys)),
        ):
            if not enabled:
                continue
            try:
                if source == "maps":
                    libraries, packaging = _maps(
                        budget.read(directory, "maps", self.max_inspection_bytes), budget, self.max_mappings
                    )
                    result["mapped_libraries"] = libraries
                    result["packaging"].extend(packaging)
                    found[source] = bool(libraries or packaging)
                elif source == "fds":
                    formats, packaging = _fd_indicators(directory, budget, self.max_fds)
                    result["open_model_formats"] = formats
                    result["packaging"].extend(packaging)
                    found[source] = bool(formats or packaging)
                else:
                    raw = budget.read(directory, "environ", self.max_inspection_bytes)
                    names = set()
                    for item in raw.split(b"\0"):
                        budget.entry()
                        name = item.partition(b"=")[0].decode("ascii", "replace")
                        if name in self.inspect_env_keys:
                            names.add(name)
                    result["environment_keys"] = sorted(names)
                    found[source] = bool(names)
                result["status"][source] = "ok"
            except PermissionError:
                result["status"][source] = "denied"
            except ProcessLookupError:
                # ESRCH: no address space. Settled below from the process state.
                result["status"][source] = "not_applicable"
            except FileNotFoundError:
                # The following identity check identifies process exit. A missing source
                # on a still-observable process is unavailable scope, not an exit.
                result["status"][source] = "unreadable"
            except _InspectionLimit:
                result["status"][source] = "truncated"
            except (OSError, ValueError):
                result["status"][source] = "unreadable"
        self._settle_exited_leader(directory, budget, result["status"], found)
        result["packaging"] = sorted(set(result["packaging"]))
        return result

    @staticmethod
    def _settle_exited_leader(
        directory: int, budget: _InspectionBudget, status: dict[str, str], found: dict[str, bool]
    ) -> None:
        """Keep ESRCH and empty reads complete only for a zombie with no threads left.

        A process whose leader thread has exited while other threads still run
        shows state Z with ``num_threads`` above one: its environ reports
        ESRCH and its maps and fd directory read empty, although the live
        threads keep the address space and descriptors (visible only under
        /proc/<pid>/task/<tid>). The start time and namespace are unchanged,
        so the identity re-check cannot tell it from a real zombie. Such
        sources, and ESRCH from a process that is not a zombie or whose
        state is unknown, are unreadable scope; a source that yielded
        indicators was read from the live address space and stays ``ok``.
        """
        try:
            state, threads = _proc_state(directory, budget)
        except (_InspectionLimit, OSError, ValueError):
            state, threads = "", 0
        exited = state in _EXITED_STATES
        threads_left = exited and threads > 1
        for source, outcome in status.items():
            unproven_esrch = outcome == "not_applicable" and not (exited and threads <= 1)
            emptied_by_exit = outcome == "ok" and threads_left and not found.get(source)
            if unproven_esrch or emptied_by_exit:
                status[source] = "unreadable"

    # --------------------------------------------------------------- analyse
    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        runs: dict[tuple[str, str, str], _Run] = {}
        truncated = unread = 0
        for raw in records:
            self.ctx.examined()
            rec = self._normalise(raw)
            if rec is None:
                continue
            match, undecided = classify_command(rec["exe"], rec["argv"])
            # Live collection counts every cut command line itself, AI tool or not.
            if rec["argv_truncated"] and self.offline:
                truncated += 1
                unread += undecided
            if match is None:
                inspection = rec["inspection"]
                if inspection and (inspection["mapped_libraries"] or inspection["open_model_formats"]):
                    yield self._inspection_finding(rec)
                continue
            rule, package = match
            key = (rec["host"], rec["user"], rule.tool)
            run = runs.get(key)
            if run is None:
                run = runs[key] = _Run(rec["host"], rec["user"], rule)
            run.processes += 1
            if isinstance(rec["pid"], int) and len(run.pids) < 10:
                run.pids.append(rec["pid"])
            exe = rec["exe"] or (rec["argv"][0] if rec["argv"] else "")
            if not rec["exe"] and _WHITESPACE.search(exe) and classify(None, rec["argv"]) is None:
                exe = exe.split(None, 1)[0]  # matched as a process title (`npm exec pkg`): its program
            exe = exe.replace("\\", "/").rsplit("/", 1)[-1]
            run.executables[exe[:80]] += 1
            if package:
                run.packages[package[:120]] += 1
            when = rec["started"]
            if when:
                run.first = when if run.first is None or when < run.first else run.first
                run.last = when if run.last is None or when > run.last else run.last
            if rec["observed_at"]:
                run.observed_at = max(run.observed_at or rec["observed_at"], rec["observed_at"])
            if rec["inspection"] and len(run.inspections) < 10:
                run.inspections.append({"pid": rec["pid"], **rec["inspection"]})
            if rec["argv_truncated"]:
                run.truncated += 1
        if truncated:
            self._warn_truncated(truncated, unread)
        for run in sorted(runs.values(), key=lambda r: (r.host, r.user, r.rule.tool)):
            yield self._finding(run)

    def _normalise(self, raw: dict[str, Any]) -> dict[str, Any] | None:
        nested = raw.get("columns")
        row: dict[str, Any] = nested if isinstance(nested, dict) else raw
        if "argv" in row:
            if not isinstance(row["argv"], list) or any(
                not isinstance(arg, (str, int)) or isinstance(arg, bool) for arg in row["argv"]
            ):
                self.ctx.warn("runtime.processes: malformed argument list; process omitted")
                return None
            argv, limited = _bounded_argv([str(arg) for arg in row["argv"]])
        else:
            command = _first(row, _CMD_FIELDS)
            argv, limited = _split_bounded(command) if isinstance(command, str) else ([], False)
        listed = bool(argv)
        exported_cut = row.get("argv_truncated") is True
        if exported_cut and not limited and self.offline:
            # The export cut this command line, possibly inside its final argument. That argument
            # is dropped, as live collection drops the one its byte limit cut, so a partial name
            # never matches a rule and a launcher target it held leaves the tool undecided. A
            # bound applied above has already left the export's final argument out. (A live
            # record's arguments are complete: collect() dropped the cut one.)
            argv = argv[:-1]
        # Counted once per scan in analyze(), which knows whether the cut left the tool undecided.
        truncated = limited or exported_cut
        exe = _first(row, _EXE_FIELDS)
        name = _first(row, _NAME_FIELDS)
        if not isinstance(exe, str) or not exe:
            exe = name if isinstance(name, str) and name else None
        elif (
            isinstance(name, str)
            and name
            and not exe.replace("\\", "/").rstrip("/").lower().endswith(name.lower())
        ):
            # Defender FolderPath is a directory; FileName is the executable.
            exe = f"{exe.rstrip('/').rstrip(chr(92))}/{name}"
        inspection = self._normalise_inspection(row.get("inspection"))
        if not listed and not exe and not inspection:
            self.ctx.warn("runtime.processes: record has no command line or executable")
            return None
        host = _first(raw, ("hostIdentifier", "host_identifier"))
        if host is None:
            host = _first(row, _HOST_FIELDS)
        if host is None:
            host = self.label
        user = _first(row, _USER_FIELDS)
        if user is None and row.get("uid") not in (None, ""):
            user = f"uid-{row['uid']}"
        user = "unknown" if user is None else user
        if any(
            not isinstance(value, str)
            or not value.strip()
            or len(value) > _MAX_IDENTITY_CHARS
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
            for value in (host, user)
        ):
            self.ctx.warn("runtime.processes: invalid or oversized host/user identity; process omitted")
            return None
        pid = _first(row, _PID_FIELDS)
        if inspection is not None and _pid(pid) is None:
            self.ctx.warn("runtime.processes: inspection has no valid PID; indicators omitted")
            inspection = None
        started = parse_timestamp(_first(row, _TIME_FIELDS))
        observed = parse_timestamp(row.get("observed_at"))
        return {
            "host": host,
            "user": user,
            "argv": argv,
            "exe": exe,
            "pid": _pid(pid),
            "started": started.isoformat() if started else None,
            "observed_at": observed.isoformat() if observed else None,
            "inspection": inspection,
            "argv_truncated": truncated,
        }

    def _normalise_inspection(self, raw: Any) -> dict[str, Any] | None:
        if raw is None:
            return None
        if not isinstance(raw, dict):
            self.ctx.warn("runtime.processes: malformed inspection record")
            return None
        result: dict[str, Any] = {}
        for name, allowed in (
            ("mapped_libraries", set(_LIBRARIES)),
            ("open_model_formats", _MODEL_FORMATS),
            ("packaging", {"pyinstaller"}),
            ("environment_keys", _ENV_KEYS),
        ):
            values = raw.get(name, [])
            if (
                not isinstance(values, list)
                or len(values) > 64
                or any(not isinstance(v, str) or v not in allowed for v in values)
            ):
                self.ctx.warn("runtime.processes: malformed or unallowlisted inspection labels")
                return None
            result[name] = sorted(set(values))
        identity = raw.get("identity")
        if not isinstance(identity, dict) or any(
            not isinstance(identity.get(name), str)
            or not identity[name].isascii()
            or not identity[name].isdecimal()
            or len(identity[name]) > 20
            for name in ("pid_namespace", "start_time_ticks")
        ):
            self.ctx.warn("runtime.processes: inspection has no valid process start/namespace identity")
            return None
        result["identity"] = {name: identity[name] for name in ("pid_namespace", "start_time_ticks")}
        status = raw.get("status")
        if not isinstance(status, dict) or any(
            not isinstance(status.get(name), str) or status[name] not in _INSPECTION_STATUSES
            for name in ("maps", "fds", "environ")
        ):
            self.ctx.warn("runtime.processes: inspection has invalid visibility status")
            return None
        result["status"] = {name: status[name] for name in ("maps", "fds", "environ")}
        for source, outcome in result["status"].items():
            if outcome not in _COMPLETE_STATUSES:
                self.ctx.warn(f"runtime.processes: {source} inspection {outcome}; scope incomplete")
        if any(
            result[field_name] and result["status"][source] != "ok"
            for field_name, source in (
                ("mapped_libraries", "maps"),
                ("open_model_formats", "fds"),
                ("environment_keys", "environ"),
            )
        ):
            self.ctx.warn("runtime.processes: inspection labels conflict with visibility status")
            return None
        if result["packaging"] and not any(result["status"][source] == "ok" for source in ("maps", "fds")):
            self.ctx.warn("runtime.processes: packaging indication conflicts with visibility status")
            return None
        return result

    def _inspection_metadata(self, inspections: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "runtime_inspection": inspections,
            "process_identities": [{"pid": item["pid"], **item["identity"]} for item in inspections],
            "inspection_limitations": [
                "Library names and descriptor extensions do not validate file content or agency.",
                "Mappings do not expose arbitrary Python imports or memory-only code.",
                "Process identities lack a boot identifier and are not stable across host restarts.",
                "A process snapshot does not establish activity outside its observation time.",
            ],
        }

    def _inspection_finding(self, rec: dict[str, Any]) -> Finding:
        inspection = rec["inspection"]
        identity = inspection["identity"]
        finding = Finding(
            surface=Surface.RUNTIME,
            connector=self.name,
            kind=Kind.LOCAL_MODEL if inspection["open_model_formats"] else Kind.FRAMEWORK_USAGE,
            title=f"ML runtime indicators on {rec['host']} (PID {rec['pid']})",
            resource=f"runtime:{rec['host']}:{identity['pid_namespace']}:{rec['pid']}:{identity['start_time_ticks']}:ml-runtime",
            resource_type="process/model-runtime-indicator",
            provider="runtime",
            account=rec["host"],
            owner=rec["user"],
            metadata={
                "host": rec["host"],
                "user": rec["user"],
                "role": "model-runtime-indicator",
                "pids": [rec["pid"]],
                "observation_source": "process-inventory" if self.offline else "live-proc",
                **self._inspection_metadata([{"pid": rec["pid"], **inspection}]),
            },
        )
        if rec["observed_at"]:
            finding.metadata["observed_at"] = rec["observed_at"]
        finding.add_evidence(
            Evidence(
                signal="runtime:process:model-runtime-indicator",
                location=rec["host"],
                weight=0.35,
                description="Mapped-library or open-model extension indicators; agent behavior unestablished",
            )
        )
        return finalize(finding, self.index)

    def _finding(self, run: _Run) -> Finding:
        rule = run.rule
        package = run.packages.most_common(1)[0][0] if run.packages else None
        what = f"{rule.product}: {package}" if package else rule.product
        f = Finding(
            surface=Surface.RUNTIME,
            connector=self.name,
            kind=Kind.RUNTIME_PROCESS,
            title=f"{what} running on {run.host} ({run.user})",
            resource=f"runtime:{run.host}:{run.user}:{rule.tool}",
            resource_type=f"process/{rule.role}",
            provider="runtime",
            account=run.host,
            owner=run.user,
            first_seen=run.first,
            last_seen=run.last,
        )
        sig = self.index.get(rule.signature) if rule.signature else None
        if sig is not None:
            if sig.category == "provider":
                f.add_model_provider(sig.id)
            else:
                f.add_framework(sig.id)
            for capability in sig.capabilities:
                f.add_capability(capability)
            if sig.agent_indicator and sig.category != "identity-app":
                f.metadata["agent_indicators"] = 1
        if rule.role == "model-server" and rule.tool in {"ollama", "lm-studio"}:
            provider = "provider.ollama" if rule.tool == "ollama" else "provider.lm-studio"
            if self.index.get(provider) is not None:
                f.add_model_provider(provider)
        f.add_evidence(
            Evidence(
                signal=f"runtime:process:{rule.role}",
                description=(
                    f"{run.processes} running process(es) of {what} ({', '.join(sorted(run.executables))})"
                ),
                location=f"{run.host}",
                weight=0.85,
                signature=rule.signature,
            )
        )
        f.add_tag("observed-running")
        f.metadata.update(
            {
                "tool": rule.tool,
                "product": rule.product,
                "role": rule.role,
                "host": run.host,
                "user": run.user,
                "processes": run.processes,
                "pids": run.pids,
                "executables": dict(run.executables.most_common(5)),
                "mcp_packages": dict(run.packages.most_common(10)),
            }
        )
        f.metadata["observation_source"] = "process-inventory" if self.offline else "live-proc"
        if run.observed_at:
            f.metadata["observed_at"] = run.observed_at
        if run.inspections:
            f.metadata.update(self._inspection_metadata(run.inspections))
        if run.truncated:
            f.metadata["command_lines_truncated"] = run.truncated
            f.metadata.setdefault("limitations", []).append(
                f"{run.truncated} command line(s) were truncated by an argument/byte limit or source export; "
                "only their leading complete arguments were classified."
            )
        return finalize(f, self.index)


def _pid(value: Any) -> int | None:
    """A process id from an export: a non-negative integer below 2**64, as an int or ASCII digits.

    The bound is a width, not a typical pid range: CrowdStrike's TargetProcessId
    is a 64-bit id.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, str) and value.isascii() and value.isdecimal() and len(value) <= 20:
        value = int(value)
    if isinstance(value, int):
        return value if 0 <= value < 2**64 else None
    return None


# include/linux/proc_ns.h: PROC_PID_INIT_INO, the inode of the initial PID namespace.
_INIT_PID_NS_INO = 0xEFFFFFFC
# hidepid values (older kernels print numbers) that the mount's gid= group is exempt
# from; ptraceable hides every process the account may not trace, from root too.
_HIDEPID_OFF = {"0", "off"}
_HIDEPID_GROUP_EXEMPT = {"1", "2", "noaccess", "invisible"}


def _restricted_view(proc: Path) -> str | None:
    """Why this /proc may not list every process on the host, or None when it lists all of them."""
    # /proc/1 is the init of the PID namespace this procfs belongs to; when it
    # is hidden, this process's own namespace stands in. NSpid cannot answer
    # this: it starts at the procfs's namespace, so a container's own /proc
    # shows a single entry, as the host's does.
    for link in (proc / "1" / "ns" / "pid", proc / "self" / "ns" / "pid"):
        try:
            inode = os.stat(link).st_ino
        except OSError:
            continue
        if inode != _INIT_PID_NS_INO:
            return (
                "/proc belongs to a separate PID namespace (a container); processes outside it are not listed"
            )
        break
    else:
        return "the PID namespace of /proc could not be determined"
    options = _proc_mount_options(proc)
    if options is None:
        return "the mount options of /proc could not be read"
    hidepid = options.get("hidepid", "off")
    if hidepid in _HIDEPID_OFF:
        return None  # subset=pid hides only entries that are not processes
    if hidepid in _HIDEPID_GROUP_EXEMPT and options.get("gid", "0") in _own_groups(proc):
        return None  # the mount's gid= group (root's group 0 by default) sees every process
    return f"/proc is mounted with hidepid={hidepid}, so processes this account may not trace are hidden"


def _proc_mount_options(proc: Path) -> dict[str, str] | None:
    """The superblock options of the procfs mounted on /proc; the last mount there is the visible one."""
    try:
        mounts = _proc_text(proc / "self" / "mountinfo")
    except OSError:
        return None
    found: str | None = None
    for line in mounts.splitlines():
        fields = line.split()
        if len(fields) > 4 and fields[4] == "/proc":
            found = fields[-1]
    if found is None:
        return None
    return {name: value for name, _, value in (option.partition("=") for option in found.split(","))}


def _own_groups(proc: Path) -> set[str]:
    """This process's filesystem gid and supplementary groups, when its gids are the host's."""
    try:
        gid_map = _proc_text(proc / "self" / "gid_map").split()
        status = _proc_text(proc / "self" / "status")
    except OSError:
        return set()
    if gid_map != ["0", "0", "4294967295"]:
        return set()  # inside a user namespace, a gid need not be the mount's gid
    groups: set[str] = set()
    for line in status.splitlines():
        parts = line.split()
        if parts[:1] == ["Gid:"] and len(parts) > 4:
            groups.add(parts[4])  # the filesystem gid, which the kernel's in_group_p() checks
        elif parts[:1] == ["Groups:"]:
            groups.update(parts[1:])
    return groups


def _proc_text(path: Path) -> str:
    """Bound the existing proc visibility probes as well as optional inspection."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("not a regular proc visibility file")
        remaining = 256 * 1024
        chunks: list[bytes] = []
        while remaining:
            raw = os.read(fd, min(remaining, 8192))
            if not raw:
                return b"".join(chunks).decode("ascii", "replace")
            chunks.append(raw)
            remaining -= len(raw)
        raise OSError("proc visibility byte limit")
    finally:
        os.close(fd)


def _user_name(uid: int) -> str:
    try:
        import pwd  # POSIX only; live mode runs on Linux

        return pwd.getpwuid(uid).pw_name
    except (ImportError, KeyError):
        return f"uid-{uid}"


def _first(row: dict[str, Any], names: tuple[str, ...]) -> Any:
    for name in names:
        value = row.get(name)
        if value not in (None, "", "-"):
            return value
    return None


_TOKEN = re.compile(r'"((?:[^"\\]|\\.)*)"|\'([^\']*)\'|(\S+)')


def _split(command: str) -> list[str]:
    """Split a command line into arguments, honouring simple quoting on any platform."""
    return _split_bounded(command)[0]


def _bounded_argv(args: list[str]) -> tuple[list[str], bool]:
    """Keep only complete arguments inside the shared count and UTF-8 byte budgets."""
    out: list[str] = []
    remaining = _MAX_CMDLINE_BYTES
    for arg in args[:_MAX_ARGV]:
        # Bound encoding as well as storage; a single input operand may be huge.
        if len(arg) > remaining:
            return out, True
        size = len(arg.encode("utf-8", "replace")) + bool(out)
        if size > remaining:
            return out, True
        remaining -= size
        out.append(arg)
    return out, len(args) > _MAX_ARGV


def _split_bounded(command: str) -> tuple[list[str], bool]:
    """Bound command text without letting a partial final token identify a tool."""
    encoded = command[: _MAX_CMDLINE_BYTES + 1].encode("utf-8", "replace")
    cut = len(command) > _MAX_CMDLINE_BYTES or len(encoded) > _MAX_CMDLINE_BYTES
    prefix = encoded[:_MAX_CMDLINE_BYTES].decode("utf-8", "ignore")
    out: list[str] = []
    for match in _TOKEN.finditer(prefix):
        if cut and match.end() == len(prefix) and not prefix[-1:].isspace():
            break
        out.append(next(group for group in match.groups() if group is not None))
        if len(out) > _MAX_ARGV:
            break
    bounded, limited = _bounded_argv(out)
    return bounded, cut or limited
