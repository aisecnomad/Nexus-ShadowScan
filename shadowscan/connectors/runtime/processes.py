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
from collections.abc import Iterable, Iterator
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
_SKIP_ARGS = {"-y", "--yes", "-q", "--quiet", "x", "dlx", "exec", "run", "tool", "--", "-u", "-b", "-e"}
_PACKAGE_ARGS = 3  # positional arguments of a launcher that may name the package it runs

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
_INSPECTION_STATUSES = {"ok", "denied", "unreadable", "truncated", "not_requested"}
_MAP_LINE = re.compile(
    r"^[0-9a-f]+-[0-9a-f]+\s+[rwxps-]{4}\s+[0-9a-f]+\s+[0-9a-f]+:[0-9a-f]+\s+\d+(?:\s+(.*))?$", re.I
)


class _InspectionLimit(Exception):
    """A fixed, non-sensitive limit reason."""


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


def _proc_identity(directory: int, budget: _InspectionBudget) -> dict[str, str]:
    raw = budget.read(directory, "stat", 4096).decode("ascii", "replace")
    end = raw.rfind(")")
    fields = raw[end + 1 :].split() if end >= 0 else []
    if len(fields) < 20 or not fields[19].isascii() or not fields[19].isdecimal():
        raise ValueError("malformed process stat")
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


def _base(exe: str) -> str:
    """An executable's base name, lower case and without ``.exe``."""
    base = exe.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return base[:-4] if base.endswith(".exe") else base


def _classification_complete(argv: list[str]) -> bool:
    """Whether the leading arguments of a longer command line already decide its classification.

    A launcher is classified by its first positional arguments; until ``_packages``
    has seen them all, the package it runs may still lie past the read limit.
    """
    if not argv:
        return False
    base = _base(argv[0])
    if base not in _LAUNCHERS and not _PYTHON.match(base):
        return True
    return sum(1 for _ in _packages(base, argv[1:])) >= _PACKAGE_ARGS


def classify(executable: str | None, argv: list[str]) -> tuple[ProcessRule, str | None] | None:
    """The AI tool a process runs, and an MCP package name when it is an MCP server."""
    exe = (executable or (argv[0] if argv else "") or "").replace("\\", "/")
    base = _base(exe)
    lowered = exe.lower()
    for name, fragment, rule in DESKTOP_APPS:
        if base == name and fragment in lowered:
            return rule, None
    if base in EXECUTABLES:
        rule = EXECUTABLES[base]
        if base == "ollama" and not any(a in {"serve", "run", "runner"} for a in argv[1:3]):
            return None  # `ollama list` and `ollama pull` do not run a model
        return rule, None
    if base not in _LAUNCHERS and not _PYTHON.match(base):
        return None
    for package in _packages(base, argv[1:]):
        for pattern, rule in PACKAGES:
            if pattern.search(package):
                return rule, None
        if _MCP_PACKAGE.match(package):
            name = (
                package.rsplit("@", 1)[0]
                if package.count("@") > (1 if package.startswith("@") else 0)
                else package
            )
            return ProcessRule(f"mcp:{name.lower()}", "MCP server", "protocol.mcp", "mcp-server"), name
    return None


def _packages(launcher: str, args: list[str]) -> Iterator[str]:
    """Candidate package or module names in a launcher's arguments (the first few positional ones)."""
    seen = 0
    i = 0
    while i < len(args) and seen < _PACKAGE_ARGS:
        arg = args[i]
        i += 1
        if arg in {"-m", "--from", "-p", "--package"} and i < len(args):
            yield args[i]
            seen += 1
            i += 1
            continue
        if arg.startswith("-") or arg in _SKIP_ARGS:
            continue
        if arg in _NOT_RUNNING:
            return
        seen += 1
        name = arg.replace("\\", "/")
        if "/node_modules/" in name:
            # node /usr/lib/node_modules/@scope/pkg/dist/cli.js -> @scope/pkg
            tail = name.split("/node_modules/")[-1].split("/")
            name = "/".join(tail[:2]) if tail and tail[0].startswith("@") else tail[0]
        elif _PYTHON.match(launcher) and name.endswith(".py"):
            continue
        yield name


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
    truncated: int = 0  # processes classified from the leading arguments of a longer command line


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
                        raw = os.read(fd, _MAX_CMDLINE_BYTES)
                    finally:
                        os.close(fd)
                    truncated = len(raw) >= _MAX_CMDLINE_BYTES
                    if truncated:
                        # The leading arguments classify the process; one cut by the limit is dropped.
                        raw = raw[: raw.rfind(b"\0") + 1]
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
            if classify(None, argv) is None:
                if truncated and not _classification_complete(argv):
                    self.ctx.warn(
                        "runtime.processes: command line byte limit reached before a classifying argument"
                    )
                if not inspection:
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
            if truncated:
                record["argv_truncated"] = True
            if inspection is not None:
                record["inspection"] = inspection
            yield record
        if unreadable:
            self.ctx.warn(f"runtime.processes: {unreadable} process(es) could not be read")

    def _inspection_identity(self, directory: int, budget: _InspectionBudget) -> dict[str, str] | None:
        """Unavailable enrichment never erases readable, independent command-line evidence."""
        try:
            return _proc_identity(directory, budget)
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
                elif source == "fds":
                    formats, packaging = _fd_indicators(directory, budget, self.max_fds)
                    result["open_model_formats"] = formats
                    result["packaging"].extend(packaging)
                else:
                    raw = budget.read(directory, "environ", self.max_inspection_bytes)
                    names = set()
                    for item in raw.split(b"\0"):
                        budget.entry()
                        name = item.partition(b"=")[0].decode("ascii", "replace")
                        if name in self.inspect_env_keys:
                            names.add(name)
                    result["environment_keys"] = sorted(names)
                result["status"][source] = "ok"
            except PermissionError:
                result["status"][source] = "denied"
            except FileNotFoundError:
                # The following identity check identifies process exit. A missing source
                # on a still-observable process is unavailable scope, not an exit.
                result["status"][source] = "unreadable"
            except _InspectionLimit:
                result["status"][source] = "truncated"
            except (OSError, ValueError):
                result["status"][source] = "unreadable"
        result["packaging"] = sorted(set(result["packaging"]))
        return result

    # --------------------------------------------------------------- analyse
    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        runs: dict[tuple[str, str, str], _Run] = {}
        for raw in records:
            self.ctx.examined()
            rec = self._normalise(raw)
            if rec is None:
                continue
            match = classify(rec["exe"], rec["argv"])
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
            exe = (
                (rec["exe"] or (rec["argv"][0] if rec["argv"] else "")).replace("\\", "/").rsplit("/", 1)[-1]
            )
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
            if rec["truncated"]:
                run.truncated += 1
        for run in sorted(runs.values(), key=lambda r: (r.host, r.user, r.rule.tool)):
            yield self._finding(run)

    def _normalise(self, raw: dict[str, Any]) -> dict[str, Any] | None:
        nested = raw.get("columns")
        row: dict[str, Any] = nested if isinstance(nested, dict) else raw
        if "argv" in row and isinstance(row["argv"], list):
            argv = [str(a) for a in row["argv"] if isinstance(a, (str, int))]
        else:
            command = _first(row, _CMD_FIELDS)
            argv = _split(command) if isinstance(command, str) else []
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
        if not argv and not exe and not inspection:
            self.ctx.warn("runtime.processes: record has no command line or executable")
            return None
        host = _first(raw, ("hostIdentifier", "host_identifier")) or _first(row, _HOST_FIELDS) or self.label
        user = _first(row, _USER_FIELDS)
        if user is None and row.get("uid") not in (None, ""):
            user = f"uid-{row['uid']}"
        pid = _first(row, _PID_FIELDS)
        if inspection is not None and _pid(pid) is None:
            self.ctx.warn("runtime.processes: inspection has no valid PID; indicators omitted")
            inspection = None
        started = parse_timestamp(_first(row, _TIME_FIELDS))
        observed = parse_timestamp(row.get("observed_at"))
        return {
            "host": str(host)[:120],
            "user": str(user or "unknown")[:120],
            "argv": argv[:64],
            "exe": exe,
            "pid": _pid(pid),
            "started": started.isoformat() if started else None,
            "observed_at": observed.isoformat() if observed else None,
            "inspection": inspection,
            "truncated": row.get("argv_truncated") is True,
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
            if outcome not in {"ok", "not_requested"}:
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
        if rec["truncated"]:
            finding.metadata["truncated_command_lines"] = 1
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
            f.metadata["truncated_command_lines"] = run.truncated
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
    out = []
    for match in _TOKEN.finditer(command[: 64 * 1024]):
        out.append(next(group for group in match.groups() if group is not None))
        if len(out) >= 64:
            break
    return out
