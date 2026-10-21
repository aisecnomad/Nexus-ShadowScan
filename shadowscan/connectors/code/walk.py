"""The code scanner's tree walk: bounded, non-recursive, never following a link.

``TreeWalker`` is the walk collaborator of ``FilesystemConnector`` (ADR-005): it
opens a scan root, applies exclusions and ``include``, lists the files to analyze,
schedules them against the connector deadline and accounts, fail closed, for
every entry it does not cover. Below it: a walk budget that charges every
retained or probed entry against ``max_entries`` and the scan deadline,
project-root marker detection, an iterative ``os.walk`` replacement that never
follows links, and report-safe name handling for paths that are not valid UTF-8.
"""

from __future__ import annotations

import errno
import fnmatch
import json
import os
import re
import stat
import time
import tomllib
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, BinaryIO

from shadowscan.connectors.base import ConnectorContext, ConnectorError, incomplete_reason
from shadowscan.connectors.code.lockfiles import LOCKFILE_NAMES
from shadowscan.connectors.code.manifests import is_manifest_name
from shadowscan.connectors.code.mcp_config import json_readings_declare_mcp
from shadowscan.connectors.code.model_artifacts import ARTIFACT_SUFFIXES
from shadowscan.connectors.code.path_context import _is_test_path, negative_context
from shadowscan.connectors.code.scan_records import (
    _DEDICATED_MCP_CONFIG_NAMES,
    CREDENTIAL_FILE_NAMES,
    _Project,
    _read_issue_reason,
)
from shadowscan.connectors.code.semantic_config import agent_manifest_kind, is_agent_config_path
from shadowscan.connectors.posture import (
    CLIENT_SIGNATURES,
    approval_scopes,
    posture_client,
    unreadable_settings,
)
from shadowscan.coverage import is_vendored_path
from shadowscan.signatures import Match
from shadowscan.signatures.matcher import SOURCE_EXTENSIONS, WALL_BUDGET_FACTOR, MatchTimeoutError
from shadowscan.utils.files import open_confined_directory, open_confined_file, read_policy_text
from shadowscan.utils.git import MAX_GITMODULES_BYTES, declared_submodule_paths, read_gitlink_paths
from shadowscan.utils.redaction import sanitize_text

if TYPE_CHECKING:  # filesystem imports this module
    from shadowscan.connectors.code.filesystem import _ScanState

DEFAULT_MAX_WALK_ENTRIES = 1_000_000

# Entries inspected to decide whether a skipped directory holds any file.
_EMPTY_DIRECTORY_PROBE_ENTRIES = 256

# A name no real file can have (a path component cannot contain NUL), so only
# a wildcard glob segment such as ``**`` matches it.
_ANY_FILE_NAME = "\x00"


PROJECT_ROOT_MARKERS = {
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "setup.py",
    "Pipfile",
    "go.mod",
    "Cargo.toml",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "Gemfile",
    "composer.json",
    "environment.yml",
}

# `setup.py` is also an ordinary module name (a package's `tracing/setup.py`,
# a web app's `controllers/setup.py`). It marks a project only when it builds
# a package; anything that cannot be read keeps the historical marker.
_SETUP_SCRIPT_MAX_BYTES = 256 * 1024
_PACKAGING_SETUP = re.compile(rb"\b(?:setuptools|distutils|skbuild)\b|(?<!def )(?<![.\w])setup\s*\(")


def _packaging_setup_script(path: Path) -> bool:
    try:
        with open_confined_file(path, label="setup.py") as (stream, _):
            head = stream.read(_SETUP_SCRIPT_MAX_BYTES)
    except (OSError, ValueError):
        return True
    return _PACKAGING_SETUP.search(head) is not None


def _marks_project(directory: Path, names: Iterable[str]) -> bool:
    """True when ``names`` in ``directory`` include a project manifest."""
    return any(
        name in PROJECT_ROOT_MARKERS and (name != "setup.py" or _packaging_setup_script(directory / name))
        for name in names
    )


# Template syntax in a path segment: cookiecutter and copier (``{{cookiecutter.slug}}``,
# ``{% if x %}``) and shell-style (``${name}``) placeholders a generator fills in.
_TEMPLATE_SYNTAX = re.compile(r"\{\{|\{%|\$\{")
# A manifest larger than this is not read to tell whether it parses: it counts as one.
_MANIFEST_PROBE_BYTES = 1024 * 1024
_JSON_MANIFESTS = frozenset({"package.json", "composer.json"})
_TOML_MANIFESTS = frozenset({"pyproject.toml", "Cargo.toml", "Pipfile"})


def _refuse_constant(value: str) -> float:
    raise ValueError(f"JSON constant {value} is not a manifest value")


def _manifest_parses(path: Path, name: str) -> bool:
    """Whether the manifest ``name`` at ``path`` parses as its tool reads it.

    Only JSON and TOML manifests are checked; any other, or one that cannot be
    read or is over the probe size, counts as parsing. A JSON manifest is read
    as npm and Composer read it: a repeated key is accepted (the last counts),
    ``NaN`` and ``Infinity`` are not. Whether the scanner's own analysis accepts
    it is another question; it reads manifests strictly and records a gap.
    """
    if name not in _JSON_MANIFESTS and name not in _TOML_MANIFESTS:
        return name != "setup.py" or _packaging_setup_script(path)
    try:
        with open_confined_file(path, label=name) as (stream, _):
            data = stream.read(_MANIFEST_PROBE_BYTES + 1)
    except (OSError, ValueError):
        return True
    if len(data) > _MANIFEST_PROBE_BYTES:
        return True
    try:
        text = data.decode("utf-8-sig")
        if name in _JSON_MANIFESTS:
            document = json.loads(text, parse_constant=_refuse_constant)
        else:
            document = tomllib.loads(text)
    except (UnicodeDecodeError, ValueError, RecursionError):  # TOMLDecodeError is a ValueError
        return False
    return not _templated_project_name(document)


def _templated_project_name(document: object) -> bool:
    """Whether a parsed manifest names its project with template syntax (``name = "{{folder_name}}"``).

    No package index or build backend accepts such a name, so the manifest is a
    generator's template rendered elsewhere, as one that does not parse is.
    """
    if not isinstance(document, dict):
        return False
    names = [document.get("name")]
    for table, key in (("project", "name"), ("package", "name")):
        section = document.get(table)
        if isinstance(section, dict):
            names.append(section.get(key))
    tool = document.get("tool")
    poetry = tool.get("poetry") if isinstance(tool, dict) else None
    if isinstance(poetry, dict):
        names.append(poetry.get("name"))
    return any(isinstance(value, str) and _TEMPLATE_SYNTAX.search(value) for value in names)


def _marks_deployable_project(directory: Path, rel_dir: str, names: Iterable[str]) -> bool:
    """Whether the project root ``rel_dir`` that ``names`` mark is a deployable project's.

    A template's directory (template syntax in its path, as in a cookiecutter
    ``{{cookiecutter.slug}}/pyproject.toml``) is not, nor is one none of whose
    manifests parses (a templated ``package.json``): the ``ci`` profile judges
    the documentation and example paths in it below the project around it.
    """
    if _TEMPLATE_SYNTAX.search(rel_dir):
        return False
    return any(_manifest_parses(directory / name, name) for name in names if name in PROJECT_ROOT_MARKERS)


def _holds_file(directory: Path, budget: _WalkBudget | None = None) -> bool:
    """Whether a skipped ``directory`` holds anything that is not a directory.

    Probes at most ``_EMPTY_DIRECTORY_PROBE_ENTRIES`` entries without following
    a link (a link in place of the directory is not listed at all). A tree the
    probe cannot finish or cannot list counts as non-empty, so the omission is
    disclosed rather than assumed to be nothing.
    """
    try:
        if directory.is_symlink():
            return False
    except OSError:
        return True
    pending = [directory]
    inspected = 0
    budget = budget or _WalkBudget()
    while pending:
        budget.check()
        try:
            with os.scandir(pending.pop()) as entries:
                for entry in entries:
                    budget.count_entry()
                    inspected += 1
                    if inspected > _EMPTY_DIRECTORY_PROBE_ENTRIES or not entry.is_dir(follow_symlinks=False):
                        return True
                    pending.append(Path(entry.path))
        except OSError:
            return True
    return False


class _WalkLimitError(ValueError):
    """A bounded enumeration stopped; retain findings and report incomplete coverage."""


@dataclass
class _WalkBudget:
    """Bound retained directory names and all auxiliary listings within one source-tree scan."""

    maximum: int = DEFAULT_MAX_WALK_ENTRIES
    check_deadline: Callable[[], None] | None = None
    entries: int = 0

    def check(self) -> None:
        if self.check_deadline is not None:
            # Completion failures use the connector's single canonical error.
            # Only entry exhaustion is recoverable inside the directory walk.
            self.check_deadline()

    def count_entry(self) -> None:
        self.check()
        self.entries += 1
        if self.entries > self.maximum:
            raise _WalkLimitError(f"max_entries ({self.maximum}) reached during directory enumeration")


@dataclass
class _WalkCounters:
    """What one directory walk has examined so far, shared with its link checks."""

    examined: int = 0  # files and links counted toward max_files
    non_regular: int = 0  # entries named like analyzable content that are not regular files
    stop_at: float | None = None  # monotonic time after which link checks stop (deadline minus margin)
    # Monotonic time after which listing stops, so the files already listed
    # can still be scanned before the deadline (see enumeration_deadline).
    enumerate_until: float | None = None
    # Directory (POSIX, relative to the root) -> project root of the files in
    # it, so a directory holding many links lists its ancestors once.
    project_roots: dict[str, str] = field(default_factory=dict)
    budget: _WalkBudget = field(default_factory=_WalkBudget)
    link_gaps: int = 0  # links whose target the walk does not scan (each a coverage gap)


def _project_root(
    root: Path,
    rel: str,
    cache: dict[str, str] | None = None,
    *,
    budget: _WalkBudget | None = None,
) -> str:
    """The project a file at ``rel`` belongs to, as ``_iter_entries`` assigns it.

    That is the deepest ancestor directory below the scan root holding a
    project marker, or ``"."``. Used for the symlink checks only; ``cache``
    remembers the answer for every directory the lookup passed through, so a
    tree planted with links costs one listing per directory, not per link.
    """
    directory = PurePosixPath(rel).parent.as_posix()
    if cache is not None and directory in cache:
        return cache[directory]
    passed: list[str] = []
    result = "."
    budget = budget or _WalkBudget()
    for parent in PurePosixPath(rel).parents:
        ancestor = parent.as_posix()
        if ancestor == ".":
            break
        passed.append(ancestor)
        try:
            budget.check()
            names = []
            with os.scandir(root / ancestor) as entries:
                for entry in entries:
                    budget.count_entry()
                    names.append(entry.name)
        except OSError:
            continue
        if _marks_project(root / ancestor, names):
            result = ancestor
            break
    if cache is not None:
        # Every directory between the file and its project root (or the scan
        # root) shares the answer: no marker was found below the result.
        for ancestor in passed:
            cache.setdefault(ancestor, result)
    return result


def _walk_directories(
    top: Path, onerror: Callable[[OSError], None], *, budget: _WalkBudget | None = None
) -> Iterator[tuple[str, list[str], list[str]]]:
    """Walk ``top`` top-down like ``os.walk(top, followlinks=False, onerror=onerror)``, without recursion.

    ``os.walk`` recurses before Python 3.12, so a tree about a thousand directories
    deep ends in a RecursionError that discards every finding. This keeps its
    contract: a directory is yielded before its children, a link to a directory is
    listed in ``dirnames`` but never entered, the caller may prune or reorder
    ``dirnames`` in place, and a directory that cannot be listed is passed to
    ``onerror`` and skipped. Every name is charged before retention, including
    names the caller later excludes. The shared budget also checks cancellation
    and deadlines, and bounds auxiliary coverage probes.
    """
    stack = [os.fspath(top)]
    budget = budget or _WalkBudget()
    while stack:
        budget.check()
        current = stack.pop()
        dirs: list[str] = []
        files: list[str] = []
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    budget.count_entry()
                    try:
                        is_dir = entry.is_dir()
                    except OSError:
                        is_dir = False
                    (dirs if is_dir else files).append(entry.name)
        except OSError as error:
            onerror(error)
            continue
        yield current, dirs, files
        for name in reversed(dirs):
            budget.check()
            child = os.path.join(current, name)
            if not os.path.islink(child):
                stack.append(child)


def _report_name(name: str) -> str:
    """A report-safe form of a path or path component read from disk.

    ``os.walk`` returns the bytes of a name that is not UTF-8 as lone surrogates,
    which no reporter can encode: each becomes a ``\\xNN`` escape. Valid names are
    returned unchanged; I/O keeps using the ``Path`` that holds the on-disk name.
    """
    if name.isascii():
        return name
    try:
        name.encode("utf-8")
    except UnicodeEncodeError:
        try:
            raw = name.encode("utf-8", errors="surrogateescape")
        except UnicodeEncodeError:
            raw = name.encode("utf-8", errors="backslashreplace")
        return raw.decode("utf-8", errors="backslashreplace")
    return name


def _nearest_root(rel_dir: str, roots: list[str]) -> str:
    """Discard completed branches from the active root stack during the walk."""
    while len(roots) > 1 and rel_dir != roots[-1] and not rel_dir.startswith(roots[-1] + "/"):
        roots.pop()
    return roots[-1]


DEFAULT_EXCLUDES = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "bower_components",
    ".venv",
    "venv",
    ".virtualenv",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".hypothesis",
    ".tox",
    ".nox",
    "site-packages",
    "dist",
    "build",
    "out",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".turbo",
    ".parcel-cache",
    "target",
    "vendor",
    ".terraform",
    ".serverless",
    ".gradle",
    ".idea",
    ".vs",
    "bin",
    "obj",
    "Pods",
    ".dart_tool",
    "coverage",
    ".coverage",
    ".cache",
    ".yarn",
    ".pnpm-store",
    "third_party",
    "thirdparty",
    "external",
}
# The walk skips every DEFAULT_EXCLUDES name at any depth unless the connector
# option `default_excludes` is false. Most are tool metadata, caches,
# virtualenvs, dependency trees and IDE state that never hold a project's own
# source: those are skipped without comment. The names here are build output or
# vendored code by convention, but projects also keep first-party code in them
# (scripts in bin/, an agent under vendor/ or build/). A directory with these
# names that holds a file is reported as a scan warning (not incomplete) so the
# omission is visible. This is the one definition of the split.
DISCLOSED_DEFAULT_EXCLUDES = frozenset(
    {
        "bin",
        "build",
        "dist",
        "out",
        "target",
        "obj",
        "coverage",
        "vendor",
        "third_party",
        "thirdparty",
        "external",
    }
)
# Version-control metadata is never project content (its index and objects are
# binary, so each would be a coverage gap): it stays excluded even when
# `default_excludes` is false.
VCS_METADATA_EXCLUDES = frozenset({".git", ".hg", ".svn"})

# Non-regular entries named individually per root, before the rest are summarized.
_MAX_NON_REGULAR_NOTES = 10

LOCK_FILES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "uv.lock",
    "pdm.lock",
    "Pipfile.lock",
    "Cargo.lock",
    "go.sum",
    "composer.lock",
    "Gemfile.lock",
    "packages.lock.json",
    "flake.lock",
    "bun.lockb",
    "bun.lock",
    "gradle.lockfile",
    "Package.resolved",
    "Cartfile.resolved",
    "deno.lock",
    "pubspec.lock",
    "mix.lock",
}

DEFAULT_OVERSIZE_SKIP_GLOBS: tuple[str, ...] = (
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "Pipfile.lock",
    "Cargo.lock",
    "Gemfile.lock",
    "composer.lock",
    "go.sum",
    "gradle.lockfile",
    "Package.resolved",
    "Cartfile.resolved",
    "deno.lock",
    "pubspec.lock",
    "mix.lock",
    "bun.lock",
    "*.lockb",
    "flake.lock",
    "*.log",
    "*.har",
    "*.snap",
    "*.min.js",
    "*.min.css",
    "*.map",
    "*.svg",
    "*.csv",
    "*.parquet",
    "*.wasm",
    "*.so",
    "*.dylib",
    "*.dll",
    "*.pdf",
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.gif",
    "*.woff",
    "*.woff2",
    "*.ttf",
    "*.zip",
    "*.gz",
    "*.tar",
    "*.jar",
    "*.pyc",
    "*.class",
)
# Path.is_file() treats these as "not a file"; keep that for a vanished entry.
_IGNORED_STAT_ERRNOS = frozenset({errno.ENOENT, errno.ENOTDIR, errno.EBADF, errno.ELOOP})
# Per-file matching budget: `scan_timeout` covers the first 256 KiB and one
# more budget is added per further 256 KiB, capped so a hostile file still
# fails fast. The final 64 KiB of the first band receives the next budget
# early; this avoids a sharp, scheduler-sensitive timeout cliff for the
# mid-sized source files most likely to sit just below the first boundary.
# A 971 KB JSON index still gets four default budgets (8 s).
SCAN_TIMEOUT_STEP_BYTES = 256 * 1024
SCAN_TIMEOUT_BAND_HEADROOM_BYTES = 64 * 1024
SCAN_TIMEOUT_CAP_SECONDS = 10.0
# Stop the walk this far before the connector deadline so the findings
# collected so far are emitted, sanitized and accepted by the engine, which
# discards a result that arrives after the deadline.
DEADLINE_MARGIN_FRACTION = 0.05
DEADLINE_MARGIN_MIN_SECONDS = 0.25
# Re-export binding and emission after the walk cost about 2.3 ms per scanned
# file (llama_index, uncontended): the walk keeps back twice that, capped at a
# quarter of its window so a huge tree still spends most of the deadline walking.
POST_WALK_SECONDS_PER_FILE = 0.005
POST_WALK_RESERVE_FRACTION = 0.25
# The walk lists every entry before it scans any. Listing may use this share
# of the time in which a file can still start; the rest scans what it listed.
ENUMERATION_DEADLINE_SHARE = 0.5

# Generated or locked files the walker never reads at any size.
_NEVER_READ_SUFFIXES = (".min.js", ".min.css", ".map", ".pyc", ".lock", ".lockb")
# Prose the content passes never read (see _scan_content): matched by file name only.
_DOCUMENTATION_EXTENSIONS = frozenset({".md", ".mdc", ".mdx", ".txt"})

# The manifest that declares a supported lockfile's direct dependencies, in the
# same directory. A lockfile beside it adds locked (largely transitive)
# inventory; without it the lockfile is the directory's only dependency record.
_LOCKFILE_MANIFESTS = {
    "uv.lock": "pyproject.toml",
    "poetry.lock": "pyproject.toml",
    "pnpm-lock.yaml": "package.json",
    "cargo.lock": "Cargo.toml",
}


def _never_read_by_name(name: str) -> bool:
    """Whether the walker skips ``name`` silently because it never carries evidence."""
    return name.lower() not in LOCKFILE_NAMES and (name in LOCK_FILES or name.endswith(_NEVER_READ_SUFFIXES))


def _special_file_kind(mode: int) -> str:
    """Name the kind of a non-regular, non-directory entry for diagnostics."""
    for test, kind in (
        (stat.S_ISFIFO, "FIFO"),
        (stat.S_ISSOCK, "socket"),
        (stat.S_ISCHR, "character device"),
        (stat.S_ISBLK, "block device"),
    ):
        if test(mode):
            return kind
    return "special file"


TEXT_CONFIG_EXTENSIONS = {
    ".json",
    ".jsonc",
    ".json5",
    ".yaml",
    ".yml",
    ".toml",
    ".md",
    ".mdc",
    ".mdx",
    ".txt",
    ".xml",
    ".cfg",
    ".ini",
    ".conf",
    ".env",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".bat",
    ".cmd",
    ".tf",
    ".tfvars",
    ".hcl",
    ".bicep",
    ".prompty",
    ".prompt",
    ".sql",
    ".graphql",
    ".proto",
    ".html",
    ".vue",
    ".svelte",
    ".astro",
    ".lua",
    ".pl",
    ".r",
    ".jl",
    ".ex",
    ".exs",
    ".clj",
    ".groovy",
    ".gradle",
    ".properties",
    ".plist",
    ".nix",
    ".dockerfile",
    ".csv",
}

MCP_CONFIG_NAMES = {
    ".mcp.json",
    "mcp.json",
    "mcp-config.json",
    "mcp_config.json",
    "mcp-servers.json",
    "claude_desktop_config.json",
    "cline_mcp_settings.json",
    "mcp_settings.json",
    "config.toml",  # codex, only when it has [mcp_servers.*]
    "settings.json",  # .gemini / .vscode when it has mcpServers / servers
    "config.yaml",  # continue
    "config.json",  # continue
    "opencode.json",
    "server.json",  # MCP registry manifest
    "smithery.yaml",
}


def _analyzed_by_name(name: str) -> bool:
    """Whether the name alone makes a file source or configuration that the walker reads."""
    ext = Path(name).suffix.lower()
    return (
        ext in SOURCE_EXTENSIONS
        or ext in TEXT_CONFIG_EXTENSIONS
        or name.lower().startswith(".env")
        or name.lower() in CREDENTIAL_FILE_NAMES
        or is_manifest_name(name)
        or "." not in name
    )


def _scan_priority(rel: str, name: str) -> int:
    """Deadline-ordering rank: the highest-signal files are scanned first.

    Dependency manifests, MCP configurations and coding-agent configuration
    files establish what a repository integrates with at a fraction of the
    cost of source analysis, so a connector deadline must never spend its
    budget on alphabetically-earlier source files instead. Configuration and
    data files (flow exports, IaC) come second; source files come last.
    """
    if is_manifest_name(name) or name in MCP_CONFIG_NAMES or is_agent_config_path(rel):
        return 0
    if Path(name).suffix.lower() in SOURCE_EXTENSIONS:
        return 2
    return 1


# Coding-agent sub-agent and rule definitions (Markdown with YAML front matter).
_AGENT_DEFINITION_DIRS = (".claude/agents/", ".github/agents/", ".cursor/rules/", ".windsurf/rules/")


def _exception_name(exc: Exception) -> str:
    return type(exc).__name__


def _file_failure_reason(exc: Exception) -> str:
    """Describe why one file's analysis stopped without echoing hostile input.

    Only the scanner's own limit messages are static text; never echo
    exception text that could be derived from hostile input.
    """
    reason = f"{type(exc).__name__}: {exc}" if isinstance(exc, MatchTimeoutError) else type(exc).__name__
    return sanitize_text(reason)[:200]


# A link in the root's path fails its no-follow directory open as ENOTDIR or ELOOP.
_ROOT_OPEN_REASONS = {
    errno.EACCES: "permission denied",
    errno.EPERM: "permission denied",
    errno.ENOENT: "not found",
    errno.ENOTDIR: "a path component is a link or not a directory",
    errno.ELOOP: "a path component is a link or not a directory",
}


def _root_open_failure(exc: OSError | ValueError) -> str:
    """Say why a scan root could not be opened without echoing its path.

    A ``ValueError`` from the confined opener carries only its own fixed text.
    """
    if isinstance(exc, ValueError):
        return str(exc)
    return _ROOT_OPEN_REASONS.get(exc.errno or 0) or errno.errorcode.get(exc.errno or 0, type(exc).__name__)


_CODING_AGENT_DOC_NAMES = frozenset(
    {
        "agents.md",
        "agent.md",
        "claude.md",
        "claude.local.md",
        "gemini.md",
        "copilot-instructions.md",
    }
)


def _is_coding_agent_doc(name: str) -> bool:
    return name.lower() in _CODING_AGENT_DOC_NAMES


def _echo_name(name: str) -> str:
    """``_report_name`` with control characters escaped, for a path a diagnostic quotes.

    A hostile name could otherwise break a report line or a terminal.
    """
    name = _report_name(name)
    if name.isprintable():
        return name
    return "".join(c if c.isprintable() else repr(c)[1:-1] for c in name)


def _link_lookup_failed(link: Path) -> bool:
    """Whether looking up the target of ``link`` fails (``EACCES``, say) rather than resolving outside."""
    try:
        link.resolve(strict=True)
    except (OSError, ValueError, RuntimeError):
        return True
    return False


def _resolved_link_target(link: Path, resolved_root: Path) -> Path | None:
    """Resolve only to classify a link; never open it through the link path."""
    try:
        target = link.resolve(strict=True)
    except (OSError, ValueError, RuntimeError):
        return None
    return target if target == resolved_root or resolved_root in target.parents else None


def scan_timeout_for_size(base: float, size: int) -> float:
    """Return the matching budget in seconds for one file of ``size`` bytes.

    ``base`` is the configured ``scan_timeout``. Each further 256 KiB adds
    one more ``base`` so ordinary large text files finish on an idle core; the
    final 64 KiB of the first band receives that next slice early. The result
    is capped at 10 seconds, or at ``base`` when that is higher.
    """
    size = max(size, 0)
    steps = size // SCAN_TIMEOUT_STEP_BYTES
    if steps == 0 and size >= SCAN_TIMEOUT_STEP_BYTES - SCAN_TIMEOUT_BAND_HEADROOM_BYTES:
        steps = 1
    return min(base * (1 + steps), max(base, SCAN_TIMEOUT_CAP_SECONDS))


def deadline_margin(remaining: float, scanned: int = 0) -> float:
    """Return the safety margin kept before a connector deadline.

    Five percent of the budget that remained when the walk started, and at
    least 250 ms, covers the engine's own sanitization before it compares
    completion to the deadline. Re-export binding and finding emission grow
    with the ``scanned`` files, so the margin also reserves
    ``POST_WALK_SECONDS_PER_FILE`` for each, up to ``POST_WALK_RESERVE_FRACTION``
    of ``remaining``: a result that arrives after the deadline loses the walk's
    accounting ("after N of M files") to the engine's cut.
    """
    reserve = min(POST_WALK_SECONDS_PER_FILE * scanned, POST_WALK_RESERVE_FRACTION * remaining)
    return max(DEADLINE_MARGIN_MIN_SECONDS, DEADLINE_MARGIN_FRACTION * remaining, reserve)


def enumeration_deadline(now: float, deadline: float, margin: float, scan_timeout: float) -> float:
    """Return the monotonic time after which the walk stops listing entries.

    A large tree, a slow filesystem or a root inheriting a nearly spent
    deadline must not spend it all on listing, leaving no file scanned.
    Listing takes ``ENUMERATION_DEADLINE_SHARE`` of the time in which a
    file's matching budget still fits before the margin. When no file can
    start any more, nothing is listed: listing and sorting entries that
    cannot be scanned would only spend the margin, and a result that then
    arrives after the deadline is discarded with the earlier roots' findings.
    """
    window = deadline - margin - scan_timeout - now
    return now + ENUMERATION_DEADLINE_SHARE * window if window > 0 else now


def _note_unread_settings(proj: _Project, rel: str) -> None:
    """Record that a settings file of an approval-reading client could not be read.

    The entry records no gate on its own and keeps a gate from the client's readable settings
    at ``some-actions``, because the unread file could loosen it (openclaw has no approvals).
    """
    client = posture_client(rel)
    if client is None:
        return
    unread = unreadable_settings(client)
    if not approval_scopes(client, unread.setting, unread.value):
        return
    sig_id = CLIENT_SIGNATURES[client]
    entry = {**unread.as_dict(), "file": rel}
    if entry not in proj.approvals.setdefault(sig_id, []):
        proj.approvals[sig_id].append(entry)


def _check_enumeration_time(walk: _WalkCounters) -> None:
    """Stop listing at ``walk.enumerate_until``; the entries listed so far are still scanned."""
    if walk.enumerate_until is not None and time.monotonic() >= walk.enumerate_until:
        raise _WalkLimitError(f"connector deadline: listing stopped after {walk.examined} entries")


def _below_root(rel: str) -> bool:
    """Whether ``rel`` names a file below the scan root: a relative posix path with no ``..`` or drive.

    A remote tree path reaches ``_project_root`` and the manifest probes under it as
    ``root / rel``; an absolute path, a ``..`` component, a backslash (a separator on
    Windows) or a drive-like first component could list or read outside the tree.
    """
    path = PurePosixPath(rel)
    parts = path.parts
    return (
        bool(parts)
        and not path.is_absolute()
        and ".." not in parts
        and "\\" not in rel
        and "\x00" not in rel
        and ":" not in parts[0]
    )


@contextmanager
def isolated(
    walker: TreeWalker,
    rel: str,
    analysis: str,
    reason: Callable[[Exception], str] = _exception_name,
    *,
    by_content: Callable[[], bool] | None = None,
) -> Iterator[None]:
    """Contain a failure while analyzing ``rel`` to one diagnostic so other findings survive.

    A ConnectorError always propagates: cancellation or an exhausted
    deadline ends the walk and must not become one "incomplete" error per
    file, project or finding.

    ``by_content`` says, once a failure is recorded, whether the file is an
    MCP configuration by its content (``TreeWalker._mcp_by_content``): its gap
    then has full weight and the ``ci`` profile never declares it, as it never
    declares agent configuration by its name (``_declared_omission``).
    """
    try:
        yield
    except ConnectorError:
        raise
    except Exception as exc:  # noqa: BLE001 - isolate hostile input and retain other findings
        walker._gap(
            rel,
            f"code.filesystem: {rel}: {analysis} incomplete ({reason(exc)})",
            error=True,
            full_weight=by_content is not None and by_content(),
        )


class TreeWalker:
    """Walks one scan root at a time and accounts for what it does not cover (ADR-005).

    The filesystem connector's walk collaborator. ``walk`` opens the root, lists every
    file to analyze without following a link (``_iter_entries``), hands each to
    ``scan_file`` while its matching budget fits before the connector deadline
    (``_walk_entries``), and reports, fail closed, what it skipped: links, oversize and
    non-regular entries, directories it could not list, submodules, unread settings
    files and the limits it reached.
    """

    def __init__(
        self,
        ctx: ConnectorContext,
        *,
        max_file_size: int,
        max_files: int,
        max_entries: int,
        max_notebook_size: int,
        scan_timeout: float,
        oversize_skip_globs: list[str],
        scan_secrets: bool,
        inspect_model_artifacts: bool,
        model_metadata_bytes: int,
        use_git: bool,
        strict_coverage: bool,
        include_tests: bool,
        default_excludes: bool,
        exclude_names: set[str],
        explicit_exclude_names: frozenset[str],
        exclude_globs: list[str],
        include_paths: frozenset[str],
        root_prefix: Callable[[str], str],
        profile: str,
        zero_budget: bool,
    ) -> None:
        self.ctx = ctx
        self.index = ctx.index
        self.max_file_size = max_file_size
        self.max_files = max_files
        self.max_entries = max_entries
        self.max_notebook_size = max_notebook_size
        self.scan_timeout = scan_timeout
        self.oversize_skip_globs = oversize_skip_globs
        self.scan_secrets = scan_secrets
        self.inspect_model_artifacts = inspect_model_artifacts
        self.model_metadata_bytes = model_metadata_bytes
        self.use_git = use_git
        self.strict_coverage = strict_coverage
        self.include_tests = include_tests
        self.default_excludes = default_excludes
        self.exclude_names = exclude_names
        self._explicit_exclude_names = explicit_exclude_names
        self.exclude_globs = exclude_globs
        self.include_paths = include_paths
        # The coverage profile (``default`` or ``ci``) and whether the gap budget is 0, which with
        # strict_coverage makes the accounting strict (see ``_strict_accounting``).
        self.profile = profile
        self._zero_budget = zero_budget
        # Names the scan root in a diagnostic when the connector scans several roots
        # (``FilesystemConnector._root_prefix``, which reads the connector's configuration).
        self._root_prefix = root_prefix
        # Default-excluded directory names the current walk skipped, with counts.
        self._default_skipped: dict[str, int] = {}
        # Files that were read but not as clean text, by what was done to them (see ``note_file``).
        self._file_notes: dict[str, list[str]] = {}
        # Defects in content no client reads as written, by why (``budget_defects``).
        self._budgeted_defects: dict[str, str] = {}
        self._symlink_warnings: set[Path] = set()
        self._declared_link_notes: set[Path] = set()
        self._blinding_link_notes: set[Path] = set()
        self._configuration_link_notes: set[Path] = set()
        self._alias_link_notes: set[Path] = set()
        self._agent_directories: _AgentGlobs | None = None
        # Whether the file under analysis is an MCP configuration by its content,
        # once _detect_mcp has decided it; None before (_mcp_by_content).
        self._content_mcp: bool | None = None
        # Files of the current root's walk -> the project root it assigned them,
        # which decides whether the ci profile declares a gap there (``_declared_omission``).
        self._entry_projects: dict[str, str] = {}
        # Project roots of the current root's walk that are not deployable projects (a template's,
        # or one whose manifests do not parse) -> the root the ci profile judges paths in them by.
        self._declaring_roots: dict[str, str] = {}
        # Supported lockfiles of the current root's walk -> whether their own
        # manifest sits beside them (see lockfile_gap).
        self._lockfile_governed: dict[str, bool] = {}
        # (project root, path) of settings files the walk skipped (a link gap or a non-regular entry).
        self._unread_settings: list[tuple[str, str]] = []
        # Whether the listing of the root being scanned is incomplete: the connector sets it for
        # every root from a remote API listing (``tree_listing_incomplete``), and the walk sets it
        # when max_files, max_entries, the deadline or a directory it could not list stopped it.
        # Reset for every root, so one root's truncation never weakens another's gates.
        self.root_listing_incomplete = False
        self._checked_submodules: set[tuple[Path, str]] = set()
        self._gitlink_roots: set[Path] = set()
        # Oversize files under test paths skipped with a warning (include_tests false).
        self.skipped_oversize_test_fixtures = 0

    def _excluded(self, rel: str, name: str) -> bool:
        """Directory exclusion: configured names and globs."""
        return name in self.exclude_names or self._excluded_file(rel)

    def included(self, rel: str) -> bool:
        """Whether ``rel`` is one of the configured include paths or sits below one (all, when unset)."""
        if not self.include_paths:
            return True
        return any(rel == p or rel.startswith(p + "/") for p in self.include_paths)

    def _leads_to_include(self, rel: str) -> bool:
        """Whether the walk must enter directory ``rel`` to reach a configured include path."""
        return self.included(rel) or any(p.startswith(rel + "/") for p in self.include_paths)

    def _include_behind_link(self, link: Path, rel: str) -> bool:
        """Whether a configured include path below directory link ``rel`` exists through it.

        Only metadata is looked up through the link; nothing behind it is
        listed or read. A lookup that fails for any reason other than absence
        counts as present, so the link stays a coverage gap.
        """
        for selected in self.include_paths:
            if not selected.startswith(rel + "/"):
                continue
            try:
                os.lstat(link / selected[len(rel) + 1 :])
            except (FileNotFoundError, NotADirectoryError):
                continue
            except OSError:
                return True
            return True
        return False

    def _excluded_file(self, rel: str) -> bool:
        """File exclusion: globs only, so a file named like an excluded directory is still scanned."""
        for g in self.exclude_globs:
            if PurePosixPath(rel).match(g) or PurePosixPath(rel).match(g.rstrip("/") + "/*"):
                return True
        return False

    def _analyzed_name(self, rel: str, name: str) -> bool:
        """Whether the scanner would read a regular file called ``name`` for evidence.

        Names without an extension count only when they are manifests, MCP
        configuration or carry a file-name signature; other extensionless
        entries (executables, sockets) are not analyzable by name.
        """
        ext = Path(name).suffix.lower()
        return (
            self.model_artifact_name(name)
            or ext in SOURCE_EXTENSIONS
            or ext in TEXT_CONFIG_EXTENSIONS
            or is_manifest_name(name)
            or name in MCP_CONFIG_NAMES
            or bool(self.index.match_file(rel))
        )

    def model_artifact_name(self, name: str) -> bool:
        return self.inspect_model_artifacts and (
            Path(name).suffix.lower() in ARTIFACT_SUFFIXES or "." not in name
        )

    def _named_by_signature(self, rel: str, file_matches: list[Match]) -> bool:
        """Whether a file-name signature selects ``rel`` by its name, not only by its directory.

        A signal that also matches a name no file can have, in the same
        directory, comes from a directory-wide glob such as ``.cursor/rules/**``:
        it says nothing about this file, which may be an image kept beside the
        rules. A literal name such as ``.cursorrules`` selects the file itself.
        """
        parent = rel.rpartition("/")[0]
        probe = f"{parent}/{_ANY_FILE_NAME}" if parent else _ANY_FILE_NAME
        directory_wide = {(m.signature.id, id(m.signal)) for m in self.index.match_file(probe)}
        return any((m.signature.id, id(m.signal)) not in directory_wide for m in file_matches)

    def _disclosed_default_exclusion(self, rel: str, name: str) -> bool:
        """Whether only a built-in exclusion of a disclosed name skips this directory.

        A quiet name (``DISCLOSED_DEFAULT_EXCLUDES`` lists the others), and a
        name or glob the operator excluded explicitly, skip without comment.
        """
        return (
            self.default_excludes
            and name in DISCLOSED_DEFAULT_EXCLUDES
            and name not in self._explicit_exclude_names
            and not self._excluded_file(rel)
        )

    def note_file(self, rel: str, note: str) -> None:
        """Record how a file that was analyzed in full had to be read.

        These are reported once per kind, after the walk (``_report_file_notes``): hundreds of legacy-encoded
        files must not fill the capped diagnostic channel and bury the reason a scan is incomplete.
        Strict accounting (``_strict_accounting``) treats each as a coverage gap, as the reader did before
        it read such files.
        """
        if self._strict_accounting():
            self.ctx.error(
                f"code.filesystem: {rel}: {note}; strict accounting treats this as a gap",
                reason="unparsed-input",
            )
        else:
            self._file_notes.setdefault(note, []).append(rel)

    def _report_file_notes(self, scan: _ScanState) -> None:
        """Warn once per kind of note about the files it touched; the scan stays complete."""
        notes, self._file_notes = self._file_notes, {}
        where = self._root_prefix(scan.label)
        for note, files in sorted(notes.items()):
            shown = ", ".join(files[:5]) + (f" and {len(files) - 5} more" if len(files) > 5 else "")
            self.ctx.warn(
                f"code.filesystem: {where}{len(files)} file(s) analyzed in full with a note "
                f"({note}): {shown}",
                incomplete=False,
            )

    def _report_default_excluded(self, scan: _ScanState) -> None:
        """Warn once per root about the non-empty built-in-excluded directories the walk skipped."""
        skipped, self._default_skipped = self._default_skipped, {}
        if not skipped:
            return
        named = ", ".join(f"{name} ({count})" for name, count in sorted(skipped.items()))
        where = self._root_prefix(scan.label)
        self.ctx.warn(
            f"code.filesystem: {where}default-excluded directories not scanned: {named}; "
            "set default_excludes: false to scan them",
            incomplete=False,
        )

    def size_limit(self, name: str) -> int:
        """Bytes the reader accepts for ``name``: notebooks may carry large saved outputs."""
        if name.lower().endswith(".ipynb"):
            return max(self.max_file_size, self.max_notebook_size)
        return self.max_file_size

    def _oversize_skippable(self, rel: str, name: str) -> bool:
        """Whether an oversize file is generated, locked or binary content per ``oversize_skip_globs``."""
        lower = name.lower()
        for pattern in self.oversize_skip_globs:
            if "/" in pattern:
                if PurePosixPath(rel.lower()).match(pattern):
                    return True
            elif fnmatch.fnmatchcase(lower, pattern):
                return True
        return False

    def lockfile_gap(self, rel: str, reason: str) -> None:
        """Report a supported lockfile that was not inventoried, scoped to that lockfile.

        ``reason`` is fixed text (a lockfiles.py reason or a walker condition),
        never file content. Beside the manifest that declares its direct
        dependencies, the manifest is still scanned and only the locked
        inventory is missing: a warning that leaves the scan complete, as an
        unread lockfile always did. Without that manifest the lockfile is the
        directory's only dependency record, so the failure hides dependency
        evidence and leaves coverage incomplete, as an unparseable manifest
        does.
        """
        manifest = _LOCKFILE_MANIFESTS[PurePosixPath(rel).name.lower()]
        if self._lockfile_governed.get(rel, False):
            self.ctx.warn(
                f"code.filesystem: {rel}: lockfile inventory skipped ({reason}); the dependencies "
                f"declared in the adjacent {manifest} are still scanned, locked versions and "
                "transitive dependencies are not inventoried",
                incomplete=False,
            )
        else:
            self.ctx.error(
                f"code.filesystem: {rel}: lockfile parsing failed ({reason}); no adjacent {manifest} "
                "declares these dependencies, so they are unscanned",
                # Classified from the fixed reason text alone, never the lockfile's path.
                reason=incomplete_reason(f"lockfile parsing failed ({reason})"),
            )

    def _lockfile_manifest_beside(self, rel_dir: str, lockfile: str, filenames: Iterable[str]) -> bool:
        """Whether the walk selects ``lockfile``'s own manifest in the same directory."""
        manifest = _LOCKFILE_MANIFESTS[lockfile.lower()].lower()
        for name in filenames:
            if name.lower() != manifest:
                continue
            shown = _report_name(name)
            rel = shown if rel_dir == "." else f"{rel_dir}/{shown}"
            if not self._excluded_file(rel) and self.included(rel):
                return True
        return False

    def _skip_oversize(self, rel: str, size: int, reason: str | None = None) -> None:
        reason = reason or "generated or binary content is never analyzed"
        self.ctx.warn(
            f"code.filesystem: {rel}: skipped {size} byte file over max_file_size ({self.max_file_size}); "
            f"{reason}",
            incomplete=False,
        )

    def _content_bearing(self, rel: str, name: str) -> bool:
        """Whether the technology passes read the body of ``name``, so an unread copy is a coverage gap.

        Credential detection is judged by the caller: it reads every file. Prose
        (``.md``, ``.mdc``, ``.mdx``, ``.txt`` that is not a manifest) is
        matched by file name only (see ``_scan_content``), unless it is a
        coding-agent instruction document, an agent definition under
        ``.claude/agents/`` and the like, or a file a file-name signature
        selects: those are parsed, so they stay content-bearing.
        """
        ext = Path(name).suffix.lower()
        if ext not in _DOCUMENTATION_EXTENSIONS or is_manifest_name(name):
            return True
        return (
            _is_coding_agent_doc(name)
            or any(directory in rel for directory in _AGENT_DEFINITION_DIRS)
            or bool(self.index.match_file(rel))
        )

    def _skipped_oversize(self, rel: str, name: str, size: int) -> bool:
        """Whether an oversize file is skipped here, with a warning that leaves the scan complete.

        False means the file is yielded so the reader records the coverage gap
        (``_read_source``): analyzable content the scan did not read. A name in
        ``oversize_skip_globs`` (generated, locked or binary content) is always
        disclosed without a gap. Two more kinds are, but only while
        ``scan_secrets`` is off: a documentation file, whose body the
        technology passes never read, and, when ``include_tests`` is false, a
        file under a test path (a recorded cassette, a fixture), whose evidence
        is discounted and cannot establish a deployment; the latter is counted
        in ``skipped_oversize_test_fixtures``. Agent configuration there is not
        discounted (``_discounted_test_path``) and stays a gap, and a JSON, TOML
        or YAML fixture is left to the reader, which skips it only when its bytes
        name no MCP server table (``_oversize_gap``). With credential detection on
        (the default) every read file, prose and fixtures included, is scanned
        for credentials, so an unread copy may hide a real key and stays a gap
        (fail closed). Strict accounting keeps the test-path case a gap too.
        A file the scanner never reads at any size is yielded and ignored, as
        before. A coding-agent settings file skipped here is still recorded as
        unread for its project's approval gate (``_iter_entries``).
        """
        # Selected inventories must be checked or explicitly incomplete. Binary
        # payload size is unrelated to the bounded metadata read budget.
        if self.model_artifact_name(name):
            return False
        if name.lower() in LOCKFILE_NAMES:
            self.lockfile_gap(rel, "file exceeds max_file_size")
            return True
        if self._oversize_skippable(rel, name):
            self._skip_oversize(rel, size)
            return True
        if not (_analyzed_by_name(name) or self.index.match_file(rel)):
            return False
        if self.scan_secrets:
            # Documentation and fixtures are read for credentials: unread,
            # they could hide one, so the reader records the gap, which the
            # ci profile never declares (_declared_omission).
            return False
        if not self._content_bearing(rel, name):
            self._skip_oversize(
                rel,
                size,
                "documentation is matched by file name only and credential detection is off, "
                "so its text is not read",
            )
            return True
        if self._discounted_test_path(rel) and not self._strict_accounting():
            if _guessed_mcp_name(rel, name):
                # A server table in it keeps the gap: the reader reads its bytes for one (_oversize_gap).
                return False
            self._skip_oversize_test_fixture(rel, size)
            return True
        return False

    def _file_scanned_at_real_path(self, target: Path, root: Path) -> bool:
        """Whether ``target``, a resolved link target below ``root``, is a regular file the walk reads there.

        Every directory above it must be one the walk enters, and the file must
        be neither excluded nor outside the selected paths nor a name the walk
        never reads. ``_link_target_is_scanned`` and the link diagnostic share
        this test, so a message never claims coverage the walk did not give.
        """
        parts = target.relative_to(root).parts
        for depth, name in enumerate(parts[:-1], start=1):
            if self._excluded(PurePosixPath(*parts[:depth]).as_posix(), name):
                return False
        target_rel = PurePosixPath(*parts).as_posix()
        return (
            target.is_file()
            and not self._excluded_file(target_rel)
            and self.included(target_rel)
            and not _never_read_by_name(target.name)
        )

    def _directory_scanned_at_real_path(self, target: Path, root: Path) -> bool:
        """Whether ``target``, a directory below ``root``, is one the walk enters and selects.

        Every directory on its path must be one the walk enters (not excluded,
        by default or by ``exclude``) and it must lie within the selected
        paths. ``_alias_of_scanned_directory`` builds on this test.
        """
        if not target.is_dir():
            return False
        parts = target.relative_to(root).parts
        for depth, name in enumerate(parts, start=1):
            if self._excluded(PurePosixPath(*parts[:depth]).as_posix(), name):
                return False
        return self.included(PurePosixPath(*parts).as_posix() if parts else "")

    def _unscanned_link_message(self, rel: str, link: Path, target: Path | None, root: Path) -> str:
        """The diagnostic of a link the walk does not follow, stating what its target was found to be.

        ``target`` is the link's resolved target when it lies below ``root``
        (``_resolved_link_target``), else None. Only such an in-tree target is
        named, relative to the root and escaped (``_echo_name``): a path
        outside the tree is never echoed, since it would disclose the
        operator's filesystem or carry hostile text. A lookup that fails for
        any reason but absence or a loop (``EACCES``) is reported as
        unresolvable, never as outside the tree. Whether the target is walked
        at its own path uses the very tests the walk applies.
        """
        prefix = f"code.filesystem: skipped symbolic link {rel}"
        if target is None:
            kind = _link_target_kind(link)
            if kind == "missing":
                return f"{prefix} whose target does not exist or forms a link loop"
            if kind == "other" and _link_lookup_failed(link):
                return f"{prefix} whose target cannot be resolved"
            return f"{prefix} whose target is outside the scanned tree"
        shown = _echo_name(target.relative_to(root).as_posix() or ".")
        scanned = self._file_scanned_at_real_path(target, root) or self._directory_scanned_at_real_path(
            target, root
        )
        if scanned:
            return f"{prefix} to {shown}, which is walked at its own path but not assessed as the link path"
        return f"{prefix} to {shown}, which the walk does not scan (excluded or outside the selected paths)"

    def _link_target_is_scanned(
        self, rel: str, target: Path, root: Path, walk: _WalkCounters | None = None
    ) -> bool:
        """Whether skipping the (never followed) link at ``rel`` loses no coverage.

        Coverage is kept when nothing would ever be read at the alias path, or
        when the real target is walked and analyzed with the same semantics the
        alias path would have had: same project, same test classification, same
        source type and no file-name signal that only the alias name carries.
        Directory links, links into excluded, unselected (outside ``include``)
        or unread content and config or document aliases (whose parsing can
        depend on their path) are gaps. A coding-agent instruction document
        linked to another one is the exception: the target keeps the alias's
        project and test classification.
        """
        relative = target.relative_to(root)
        target_rel = relative.as_posix()
        budget = walk.budget if walk is not None else None
        if target.is_dir():
            # A directory alias changes every descendant's path. Even an
            # included target cannot prove that path-based signals at the
            # alias were assessed without walking the link (which we forbid).
            return False
        link_name = PurePosixPath(rel).name
        link_ext = Path(link_name).suffix.lower()
        alias_signals = {(m.signature.id, id(m.signal)) for m in self.index.match_file(rel)}
        link_read = bool(alias_signals) or _analyzed_by_name(link_name) or self.model_artifact_name(link_name)
        if _never_read_by_name(link_name) or not link_read:
            # The walker would skip this name silently even as a regular
            # file, whatever it points at: the alias hides nothing.
            return True
        # An include walk never reaches a target outside the selected paths,
        # however equivalent the alias is.
        if not self._file_scanned_at_real_path(target, root):
            return False
        # Coding-agent instruction aliases (CLAUDE.md -> AGENTS.md) are the
        # same document family. The real file is scanned and the alias hides no
        # second agent definition, so the alias-only file-name signal is not a
        # gap. Project ownership and test classification must still match.
        if _is_coding_agent_doc(link_name) and _is_coding_agent_doc(target.name):
            return _project_root(root, rel, budget=budget) == _project_root(
                root, target_rel, budget=budget
            ) and _is_test_path(rel) == _is_test_path(target_rel)
        # Only source and model-artifact aliases are equivalent without opening
        # the link: config and document parsing can depend on the file name and
        # directory. A model artifact with an artifact suffix is inspected by
        # that suffix and its content alone, so an alias such as latest.gguf to
        # a scanned model-q4.gguf hides nothing.
        same_kind = link_ext in SOURCE_EXTENSIONS or (
            link_ext in ARTIFACT_SUFFIXES
            and self.model_artifact_name(link_name)
            and not _analyzed_by_name(link_name)
        )
        if not same_kind or Path(target.name).suffix.lower() != link_ext:
            return False
        # The real path must keep the alias's project ownership and evidence
        # weight; another project or a test directory would change both.
        cache = walk.project_roots if walk is not None else None
        if _project_root(root, rel, cache, budget=budget) != _project_root(
            root, target_rel, cache, budget=budget
        ) or _is_test_path(rel) != _is_test_path(target_rel):
            return False
        # File-name signatures can apply to the alias but not the real file.
        target_signals = {(m.signature.id, id(m.signal)) for m in self.index.match_file(target_rel)}
        return alias_signals <= target_signals

    def check_gitlink_coverage(self, root: Path) -> None:
        """Check committed gitlinks where Git is authorized: a clone or use_git=True.

        Default local scans never invoke Git, and instead inspect declarations
        as the walk reaches .gitmodules. Gitlinks lacking that declaration
        require clone mode or the existing local metadata opt-in to discover.
        """
        if root in self._gitlink_roots:
            return
        self._gitlink_roots.add(root)
        self.ctx.check_deadline()
        remaining = self.ctx.deadline - time.monotonic() if self.ctx.deadline is not None else 10.0
        diagnostics: list[str] = []
        paths = read_gitlink_paths(root, timeout=remaining, diagnostics=diagnostics)
        self.ctx.check_deadline()
        if paths is None:
            reason = f" ({diagnostics[0]})" if diagnostics else ""
            self._submodule_gap(f"could not inventory gitlinks safely; submodule coverage unknown{reason}")
            return
        self._check_submodule_paths(root, paths)

    def _submodule_gap(self, message: str) -> None:
        if self.strict_coverage:
            self.ctx.error(f"code.filesystem: {message}")
        else:
            self.ctx.warn(f"code.filesystem: {message}")

    def _check_submodule_paths(self, root: Path, paths: Iterable[str]) -> None:
        """Missing/empty modules are gaps; operator-excluded paths remain out of scope.

        Each directory component is opened without following symlinks. We only
        test materialization here; the ordinary bounded walker scans its files.
        A nonempty directory is not proof of a complete or authentic checkout.
        """
        for rel in paths:
            self.ctx.check_deadline()
            parts = PurePosixPath(rel).parts
            if any(
                self._excluded(PurePosixPath(*parts[:depth]).as_posix(), name)
                for depth, name in enumerate(parts, 1)
            ):
                continue
            key = (root, rel)
            if key in self._checked_submodules:
                continue
            self._checked_submodules.add(key)
            materialized = False
            try:
                anchor = open_confined_directory(root / rel)
                try:
                    # The confined anchor may be O_PATH, which cannot enumerate.
                    directory = os.open(".", os.O_RDONLY | os.O_DIRECTORY, dir_fd=anchor)
                finally:
                    os.close(anchor)
                try:
                    with os.scandir(directory) as entries:
                        materialized = any(entry.name != ".git" for entry in entries)
                finally:
                    os.close(directory)
            except (OSError, ValueError):
                pass
            if not materialized:
                self._submodule_gap(
                    f"submodule {rel}: checkout is missing, empty or unsafe; source coverage incomplete"
                )

    def _check_submodule_declarations(self, root: Path, rel_dir: str) -> None:
        rel = ".gitmodules" if rel_dir == "." else f"{rel_dir}/.gitmodules"
        if self._excluded_file(rel) or not self.included(rel):
            return
        try:
            text = read_policy_text(root / rel, MAX_GITMODULES_BYTES)
            paths = declared_submodule_paths(text)
        except (OSError, ValueError, UnicodeError):
            self._submodule_gap(f"{rel}: cannot read submodule declarations safely; coverage unknown")
            return
        self._check_submodule_paths(root, (path if rel_dir == "." else f"{rel_dir}/{path}" for path in paths))

    def _iter_entries(self, root: Path) -> Iterator[tuple[str, Path, str, int]]:
        """Yield (relpath, path, project_root_rel, size) for every regular file to analyze.

        A file over ``max_file_size`` whose name matches ``oversize_skip_globs``
        or, while credential detection is off, whose body the technology passes
        never read (documentation) or that sits under a test path while test
        code is excluded is reported as a warning and never yielded
        (``_skipped_oversize``); the scan stays complete.
        Every other oversize file is yielded so the reader records incomplete
        coverage for analyzable files; types that the scanner never reads are
        still ignored.
        """
        # os.walk visits descendants before siblings. Keep only active project
        # ancestors, so assigning a project is amortized constant time even in
        # monorepos with thousands of sibling projects.
        roots: list[str] = ["."]
        # Files and links both count toward max_files: a link is never
        # followed, but deciding whether skipping it loses coverage costs a
        # project lookup and file-name matching. Link checks also stop at the
        # connector deadline, as file analysis does in _walk_entries, so a tree
        # planted with links cannot hold the walk past it.
        deadline = self.ctx.deadline
        walk = _WalkCounters(budget=_WalkBudget(self.max_entries, self.ctx.check_deadline))
        if deadline is not None:
            now = time.monotonic()
            margin = deadline_margin(deadline - now)
            walk.stop_at = deadline - margin
            walk.enumerate_until = enumeration_deadline(now, deadline, margin, self.scan_timeout)

        resolved_root = Path(os.path.realpath(root))

        if root.is_file():
            yield from self._single_file_entry(root, walk)
            return

        def walk_error(exc: OSError) -> None:
            self.ctx.error(f"code.filesystem: could not enumerate a directory under {root}")
            self.root_listing_incomplete = True

        # A gitfile or symlink also signals a checkout, but cannot authorize
        # reading external metadata. The checker reports that unknown coverage
        # even when this source tree produces no findings (and no enrichment).
        if self.use_git and os.path.lexists(root / ".git"):
            self.check_gitlink_coverage(root)
        # A root that starts when no file can start any more does not even
        # read its top directory.
        _check_enumeration_time(walk)
        for dirpath, dirnames, filenames in _walk_directories(root, walk_error, budget=walk.budget):
            walk.budget.check()
            _check_enumeration_time(walk)
            rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
            rel_dir = "." if rel_dir == "." else _report_name(rel_dir)
            if ".gitmodules" in filenames:
                self._check_submodule_declarations(root, rel_dir)
            kept = self._walked_directories(root, resolved_root, dirpath, rel_dir, dirnames, walk)
            if kept is None:
                return
            dirnames[:] = kept
            proj = _nearest_root(rel_dir, roots)
            included_names = (
                name for name in filenames if self.included(name if rel_dir == "." else f"{rel_dir}/{name}")
            )
            if rel_dir != "." and _marks_project(Path(dirpath), included_names):
                roots.append(rel_dir)
                self._note_declaring_root(Path(dirpath), rel_dir, proj, filenames)
                proj = rel_dir
            for fn in sorted(filenames):
                walk.budget.check()
                _check_enumeration_time(walk)
                shown = _report_name(fn)
                rel = shown if rel_dir == "." else f"{rel_dir}/{shown}"
                if self._excluded_file(rel) or not self.included(rel):
                    continue
                self._entry_projects[rel] = proj
                p = Path(dirpath) / fn
                if fn.lower() in LOCKFILE_NAMES:
                    self._lockfile_governed[rel] = self._lockfile_manifest_beside(rel_dir, fn, filenames)
                try:
                    if p.is_symlink():
                        gaps = walk.link_gaps
                        if not self._skip_link(root, resolved_root, rel, p, walk):
                            return
                        if walk.link_gaps != gaps:
                            self._unread_settings.append((proj, rel))
                        continue
                    info = p.stat()
                except OSError as exc:
                    if exc.errno in _IGNORED_STAT_ERRNOS:
                        continue
                    self.ctx.error(f"code.filesystem: could not inspect {rel}", reason="unscanned-input")
                    continue
                if not stat.S_ISREG(info.st_mode):
                    if self._analyzed_name(rel, fn):
                        self._skip_non_regular(walk, root, rel, _special_file_kind(info.st_mode))
                        self._unread_settings.append((proj, rel))
                    continue
                if info.st_size > self.size_limit(fn) and self._skipped_oversize(rel, fn, info.st_size):
                    if posture_client(rel) is not None:
                        # Skipped without a coverage gap (a fixture, or a name in
                        # oversize_skip_globs), but an unread settings file could still
                        # loosen the approval gate its readable siblings set.
                        self._unread_settings.append((proj, rel))
                    continue
                if _never_read_by_name(fn):
                    continue
                if not self._count_entry(walk, root):
                    return
                yield rel, p, proj, info.st_size

    def _walked_directories(
        self,
        root: Path,
        resolved_root: Path,
        dirpath: str,
        rel_dir: str,
        dirnames: list[str],
        walk: _WalkCounters,
    ) -> list[str] | None:
        """Return the subdirectories of ``dirpath`` the walk descends into, in name order.

        None means the walk must stop: a directory link reached ``max_files``
        or the connector deadline (see ``_skip_link``). Directory-link checks
        are listing work, so they also stop at ``walk.enumerate_until``.
        """
        kept = []
        for name in sorted(dirnames):
            walk.budget.check()
            _check_enumeration_time(walk)
            shown = _report_name(name)
            rel = shown if rel_dir == "." else f"{rel_dir}/{shown}"
            path = Path(dirpath) / name
            if not self._leads_to_include(rel):
                continue
            if self._excluded(rel, name):
                if self._disclosed_default_exclusion(rel, name) and _holds_file(path, walk.budget):
                    self._default_skipped[name] = self._default_skipped.get(name, 0) + 1
                continue
            try:
                if path.is_symlink():
                    if not self.included(rel) and not self._include_behind_link(path, rel):
                        # The link only lies on the way to selected paths, and
                        # none of them exists through it: nothing is lost.
                        continue
                    if not self._skip_link(root, resolved_root, rel, path, walk):
                        return None
                    continue
            except OSError:
                self.ctx.error(f"code.filesystem: could not inspect {rel}", reason="unscanned-input")
                continue
            if name in MCP_CONFIG_NAMES:
                # The walk descends into it, but no client reads a directory
                # as the configuration file its name implies. A file-signature
                # glob is not such a name: ``.roo/**`` or ``.clinerules`` also
                # match directories that their clients read as directories.
                self._skip_non_regular(walk, root, rel, "directory")
            kept.append(name)
        return kept

    def _skip_non_regular(self, walk: _WalkCounters, root: Path, rel: str, kind: str) -> None:
        """Record an entry the scanner cannot read as a file although its name says it would.

        Like a link, such an entry hides whatever a client would find there:
        coverage is incomplete. The first few are named; the rest are counted.
        A FIFO, socket or device in place of agent configuration
        (``.mcp.json``, ``.claude/settings.json``) is blinding, as an oversize
        copy of it is (``_agent_configuration``); a directory of that name is
        walked, so it costs one entry, and so does any other entry, a FIFO
        named ``.env`` or ``Dockerfile`` among them.
        """
        if self._walk_declared(root, rel, walk):
            # Declared, counted and named in full: it does not take the gap budget below.
            self._gap(
                rel, f"code.filesystem: {rel}: skipped, not a regular file ({kind})", reason="unscanned-input"
            )
            return
        walk.non_regular += 1
        # Only the diagnostics are bounded: past them the budget still counts
        # every entry, via quiet ledger entries, as it does for links.
        quiet = walk.non_regular > _MAX_NON_REGULAR_NOTES + 1
        blinding = kind != "directory" and self._agent_configuration(rel)
        if walk.non_regular == _MAX_NON_REGULAR_NOTES + 1:
            message = f"code.filesystem: further non-regular entries under {root} not listed"
        else:
            named = "agent configuration" if blinding else "analyzable content"
            message = f"code.filesystem: {rel}: skipped, not a regular file ({kind}) but named like {named}"
        if self.strict_coverage:
            if not quiet:
                self.ctx.error(f"{message}; coverage incomplete", reason="unscanned-input")
            else:
                self.ctx.count_incomplete("unscanned-input")
        else:
            # Otherwise one entry of known, bounded lost coverage: budgeted, not fatal.
            suffix = "coverage incomplete" if blinding else "coverage gap"
            self._ledger_gap(
                rel, f"{message}; {suffix}", blinding=blinding, quiet=quiet, reason="unscanned-input"
            )

    def _count_entry(self, walk: _WalkCounters, root: Path) -> bool:
        """Count one examined entry (a file or a link); False once ``max_files`` is reached."""
        walk.examined += 1
        # The denominator of the coverage-gap ratio: entries the walk reached,
        # not findings, so a gap is judged against the tree it occurred in.
        # Summed across roots, because walk counters restart at each one.
        self.ctx.add_coverage_examined(1)
        if walk.examined > self.max_files:
            self.ctx.error(f"code.filesystem: max_files ({self.max_files}) reached under {root}")
            self.root_listing_incomplete = True
            return False
        return True

    def _skip_link(self, root: Path, resolved_root: Path, rel: str, link: Path, walk: _WalkCounters) -> bool:
        """Record the coverage gap of a symbolic link, which the walk never follows.

        Returns False, with the reason recorded as an error, when the walk
        must stop: the link reached ``max_files`` or the connector deadline.
        """
        if not self._count_entry(walk, root):
            return False
        if walk.stop_at is not None and time.monotonic() >= walk.stop_at:
            self.ctx.error(
                f"code.filesystem: connector deadline reached while checking symbolic links under {root}; "
                "results incomplete"
            )
            self.root_listing_incomplete = True
            return False
        # A link that resolves inside the scan root loses no coverage only if
        # the target is scanned at its real path.
        target = _resolved_link_target(link, resolved_root)
        if target is not None and self._link_target_is_scanned(rel, target, resolved_root, walk):
            return True
        if PurePosixPath(rel).name.lower() in LOCKFILE_NAMES:
            # Never followed; scoped like any other lockfile that was not inventoried.
            self.lockfile_gap(rel, "symbolic link is not followed")
            return True
        message = self._unscanned_link_message(rel, link, target, resolved_root)
        alias = target is not None and self._alias_of_scanned_directory(rel, target, resolved_root)
        agent = self._agent_configuration_link(rel, link, target if alias else None)
        if not agent and self._walk_declared(root, rel, walk):
            # One representative note per root, like the gap below, and it
            # leaves that gap's own representative slot for an undeclared link.
            # Every declared link is counted, as the budget counts every other.
            if root not in self._declared_link_notes:
                self._declared_link_notes.add(root)
                self._gap(rel, message, reason="unresolved-link")
            else:
                self.ctx.count_declared_omissions()
            return True
        # A single representative diagnostic per root keeps hostile trees
        # from filling the report with thousands of link names. The budget
        # still counts every one of them, via the quiet ledger entries.
        walk.link_gaps += 1
        # The target's bytes exist and other tools may read them, so an
        # unscanned target is lost coverage a repository could hide behind —
        # not a file-attributable input defect.
        if self.strict_coverage:
            # One named error per root; every further link is counted under its reason.
            if root not in self._symlink_warnings:
                self._symlink_warnings.add(root)
                self.ctx.error(f"{message}; coverage incomplete", reason="unresolved-link")
            else:
                self.ctx.count_incomplete("unresolved-link")
            return True
        self._budgeted_link_gap(root, rel, link, message, agent=agent, alias=alias)
        return True

    def _reserved_budget(self, rel: str, path: Path, size: int, budget: float) -> float:
        """Return the share of ``budget`` a file must have left before the walk may start it.

        Files the reader never opens (over ``max_file_size``, which only
        records an error, or neither source, configuration nor a file-name
        signal) reserve nothing, so they cannot end the walk under a short
        deadline.
        """
        if self.model_artifact_name(path.name):
            return scan_timeout_for_size(self.scan_timeout, min(size, self.model_metadata_bytes))
        if size > self.size_limit(path.name):
            return 0.0
        will_read = _analyzed_by_name(path.name) or bool(self.index.match_file(rel))
        return budget if will_read else 0.0

    def _stop_at_deadline(self, root: Path, examined: int, remaining: int) -> None:
        """Record one error naming exactly how much of the tree the deadline left unread.

        The walk buffers its entries up front, so the remainder is exact
        arithmetic, never the budgeted re-count (and its ``at least N``
        truncation) that the lazy walk needed.
        """
        self.ctx.error(
            f"code.filesystem: connector deadline reached after {examined} of {examined + remaining} "
            f"files under {root}; results incomplete",
        )

    def walk(
        self,
        scan: _ScanState,
        scan_file: Callable[[_ScanState, str, Path, str], None],
        unread_settings: list[str],
    ) -> None:
        """Analyze every file under the scan root, each in its own failure isolation.

        Files are read relative to the root directory opened here, with no
        link followed in any component below it. The listing itself uses
        paths, so a directory replaced by a link after it was listed fails
        that file's read (incomplete coverage) instead of redirecting it.
        """
        # A single-file root is read relative to its (equally checked) parent.
        base = scan.root.parent if scan.root.is_file() else scan.root
        scan.base = base
        try:
            scan.root_fd = open_confined_directory(base)
        except (OSError, ValueError) as exc:
            # Named by its label, like the findings: a labeled root is not exposed.
            reason = _root_open_failure(exc)
            self.ctx.error(f"code.filesystem: {scan.label}: could not open the scan root safely ({reason})")
            return
        self._default_skipped = {}
        fixtures_before = self.skipped_oversize_test_fixtures
        self._file_notes = {}
        self._budgeted_defects = {}
        try:
            self._walk_entries(scan, scan_file, unread_settings)
        except _WalkLimitError as exc:
            self.ctx.error(f"code.filesystem: {scan.label}: {exc}; results incomplete")
            self.root_listing_incomplete = True
        self._report_default_excluded(scan)
        skipped_fixtures = self.skipped_oversize_test_fixtures - fixtures_before
        if skipped_fixtures:
            self.ctx.warn(
                f"code.filesystem: {scan.label}: {skipped_fixtures} oversize test fixture(s) skipped unread "
                "(include_tests and scan_secrets are off); set either, or strict_coverage, to make them "
                "coverage gaps",
                incomplete=False,
            )
        self._report_file_notes(scan)

    def _walk_entries(
        self,
        scan: _ScanState,
        scan_file: Callable[[_ScanState, str, Path, str], None],
        unread_settings: list[str],
    ) -> None:
        """Start each file only while its matching budget fits before the connector deadline.

        Entries are buffered (bounded by ``max_files``) and ordered by
        ``_scan_priority`` — manifests and agent/MCP configuration first,
        source last — with smaller files before larger within each class and
        the deterministic walk order breaking ties. A deadline therefore
        degrades predictably: whatever is cut is the largest, lowest-signal
        tail, and the remainder is reported exactly. Listing itself stops at
        ``enumeration_deadline``, leaving time to scan the listed entries.
        Each entry carries its own project root, so ordering never changes
        attribution.
        """
        deadline = self.ctx.deadline
        window = deadline - time.monotonic() if deadline is not None else 0.0
        margin = scan.margin = deadline_margin(window) if deadline is not None else 0.0
        entries: list[tuple[str, Path, str, int]] = []
        try:
            self._unread_settings = []
            self._lockfile_governed = {}
            self._entry_projects = {}
            self._declaring_roots = {}
            entries.extend(self._iter_entries(scan.root))
        except _WalkLimitError as exc:
            # Enumeration hit max_entries or its share of the deadline: the
            # files already enumerated are still scanned (in priority order)
            # so partial findings survive, and the limit is recorded.
            self.ctx.error(f"code.filesystem: {scan.label}: {exc}; results incomplete")
            self.root_listing_incomplete = True
        if (diff_files := scan.diff_files) is not None:
            # Filtered up front so the deadline remainder counts only files the walk would read.
            entries = [entry for entry in entries if self._diff_included(entry[0], diff_files)]
        entries.sort(key=lambda entry: (_scan_priority(entry[0], entry[1].name), entry[3]))
        examined = 0
        for index, (rel, path, proj_root, size) in enumerate(entries):
            analysis_size = (
                min(size, self.model_metadata_bytes) if self.model_artifact_name(path.name) else size
            )
            budget = scan_timeout_for_size(self.scan_timeout, analysis_size)
            wall_cap = budget * WALL_BUDGET_FACTOR
            reserve = self._reserved_budget(rel, path, size, budget)
            if deadline is not None:
                remaining = deadline - time.monotonic()
                margin = deadline_margin(window, examined)
                # The wall cap never runs into the connector deadline's margin.
                wall_cap = max(budget, min(wall_cap, remaining - margin))
                if remaining < reserve + margin:
                    if remaining > margin + self.scan_timeout:
                        # Only this file's size-scaled budget does not fit; the
                        # walk can still cover ordinary files, so record the
                        # gap for this file alone and keep going.
                        self.ctx.error(
                            f"code.filesystem: {rel}: skipped; the remaining connector deadline cannot cover "
                            f"its {reserve:.0f}s matching budget",
                        )
                        self._unread_settings.append((proj_root, rel))
                        continue
                    # Cooperative deadline: never start a file whose budget
                    # could run into the margin. Findings collected so far are
                    # returned and the engine keeps them; only a result that
                    # arrives after the deadline is discarded.
                    self._stop_at_deadline(scan.root, examined, len(entries) - index)
                    self._unread_settings.extend((root, name) for name, _, root, _ in entries[index:])
                    break
            examined += 1
            self._content_mcp = None
            with (
                isolated(
                    self,
                    rel,
                    "file analysis",
                    _file_failure_reason,
                    by_content=partial(self._mcp_by_content, scan, rel, path),
                ),
                self.index.scan_budget(seconds=budget, chars=size, wall_seconds=wall_cap),
            ):
                scan_file(scan, rel, path, proj_root)
        # A settings file the walk skipped can only loosen the gate of a project it read.
        for rel in unread_settings:
            if not _below_root(rel):
                # The snapshot writer refuses such a path before this point; a path that is not
                # confined to the tree must drive no listing or manifest probe outside it, and a
                # listing that names one is not trusted to be complete.
                self.ctx.warn(
                    f"code.filesystem: {scan.label}: unread settings path outside the scanned tree "
                    "ignored; coverage incomplete",
                    incomplete=True,
                )
                self.root_listing_incomplete = True
            elif scan.root.is_dir():
                self._unread_settings.append((_project_root(scan.root, rel), rel))
        for proj_root, rel in self._unread_settings:
            if (proj := scan.projects.get(proj_root)) is not None:
                _note_unread_settings(proj, rel)
        self._unread_settings = []

    @staticmethod
    def _diff_included(rel: str, diff_files: frozenset[str]) -> bool:
        """Whether a file should be scanned in diff mode.

        Always included: files in the diff set, dependency manifests,
        ``.env*`` files and coding-agent settings files, whose content
        contextualizes code changes. A settings file left out could loosen an
        approval gate that a changed one sets.
        """
        if rel in diff_files or posture_client(rel) is not None:
            return True
        name = rel.rsplit("/", 1)[-1]
        lower = name.lower()
        if lower.startswith(".env"):
            return True
        if is_manifest_name(name):
            return True
        return False

    def _strict_accounting(self) -> bool:
        """Whether every coverage gap counts: ``strict_coverage``, or a gap budget of 0.

        The one rule (docs/scanning.md#coverage-budget-and-strict-accounting): no gap is
        tolerated by the budget, discounted as test code (``include_tests``
        off) or declared by the ``ci`` profile, which refuses both settings.
        The budget is this connector's own ``max_coverage_gap``, else the
        scan-wide one, or the policy the context holds: a nested connector
        (``code.github``, ``code.gitlab``) is judged by its parent's. Either
        source of a 0 makes the accounting strict. ``strict_coverage`` also
        reports each gap as an error where it happens; a budget of 0 charges
        the ledger instead, whose verdict is then an error naming each gap's
        reason, so ``stats.coverage`` still lists them.
        """
        return self.strict_coverage or self._zero_budget or self.ctx.coverage_policy.max_gap_ratio <= 0.0

    def _declared_omission(
        self, rel: str, *, full_weight: bool = False, unread_credentials: bool = False
    ) -> bool:
        """Whether a coverage gap at ``rel`` is one the ``ci`` profile declared in advance.

        The profile accepts gaps in the paths whose evidence is already
        discounted (``negative_context`` and the test-path policy): recorded
        cassettes, fixtures, tutorials, samples and generated files. Test paths
        count only while ``include_tests`` is false, when their evidence is
        discounted; with it set they are source like any other.

        Documentation and example directories count as ``negative_context``
        counts them, below the file's project root: a project under ``demo/``
        or ``examples/svc/`` holds its own manifest and is reported at full
        weight, so its gaps are not declared either. The project root is the
        one the walk assigned to ``rel`` (``_entry_projects``); a path the walk
        assigned none, a project root itself among them, is not declared for
        its directory names.

        Agent configuration, whose findings keep their full weight wherever it
        lies, is never declared (``_agent_configuration``): an MCP
        configuration (by a dedicated name, or by the structure a caller
        found, ``full_weight``), a coding-agent instruction, rule or settings
        file, an agent manifest or card. A client started under ``tests/`` or
        ``docs/`` reads it there, so the profile cannot have accepted its gap.
        Strict accounting declares nothing (``_strict_accounting``).

        Nor is a gap that left the file's bytes unread by credential detection
        (``unread_credentials``: a file over ``max_file_size``, a notebook's
        saved outputs) while ``scan_secrets`` is on: credentials are never
        declared without a read, so the gap is recorded as without the profile.
        """
        if self.profile != "ci" or full_weight or self._strict_accounting():
            return False
        if unread_credentials and self.scan_secrets:
            return False
        if _is_test_path(rel):
            declared = not self.include_tests
        else:
            project_root = self._entry_projects.get(rel, rel)
            project_root = self._declaring_roots.get(project_root, project_root)
            declared = rel != project_root and negative_context(rel, project_root) is not None
        return declared and not self._agent_configuration(rel)

    def _note_declaring_root(self, directory: Path, rel_dir: str, parent: str, filenames: list[str]) -> None:
        """Record which root ``_declared_omission`` judges paths in the project root ``rel_dir`` by.

        A deployable project is judged by itself. A template's directory or one
        whose manifests do not parse is judged by ``parent``'s root, so the
        profile still declares the gaps a template's unparsed sources leave.
        Only the ``ci`` profile reads this, so no other scan probes a manifest.
        """
        if self.profile != "ci":
            return
        manifests = [
            name for name in filenames if name in PROJECT_ROOT_MARKERS and self.included(f"{rel_dir}/{name}")
        ]
        if not _marks_deployable_project(directory, rel_dir, manifests):
            self._declaring_roots[rel_dir] = self._declaring_roots.get(parent, parent)

    def _gap(
        self,
        rel: str,
        message: str,
        *,
        error: bool = False,
        suffix: bool = True,
        reason: str | None = None,
        full_weight: bool = False,
        unread_credentials: bool = False,
    ) -> None:
        """Record a coverage gap at ``rel``.

        An error, or a warning that leaves the scan incomplete (``suffix``
        appends the usual ``; coverage incomplete``), unless the ``ci`` profile
        declared the gap: then a warning that leaves the scan complete, counted
        in the report's ``declared_omissions``, so a profile scan is never read
        as one that read everything.

        ``reason`` is the ``INCOMPLETE_REASONS`` category it is counted under;
        without one it is classified from ``message`` with ``rel`` left out, so
        a file called ``http_client.py`` does not make the gap an upstream error.
        ``full_weight`` says the file is an MCP configuration by its structure,
        and ``unread_credentials`` that credential detection did not read its
        bytes; the profile declares neither (``_declared_omission``).
        """
        reason = reason or incomplete_reason(message, path=rel)
        if self._declared_omission(rel, full_weight=full_weight, unread_credentials=unread_credentials):
            self.ctx.warn(
                f"{message}; declared omission (profile ci)", incomplete=False, declared=True, path=rel
            )
        elif error:
            self.ctx.error(message, reason=reason)
        else:
            self.ctx.warn(
                f"{message}; coverage incomplete" if suffix else message, incomplete=True, reason=reason
            )

    def _budgeted_gap(
        self,
        rel: str,
        message: str,
        *,
        declared: str | None = None,
        blinding: bool = False,
        full_weight: bool = False,
        reason: str | None = None,
        unread_credentials: bool = False,
        configuration: bool = False,
    ) -> None:
        """Charge a gap at ``rel`` to the coverage budget, unless the ``ci`` profile declared it.

        A declared omission is recorded as ``_gap`` records one (with
        ``declared`` as its message when given) and is never also charged to
        the budget, so a gap is counted once: in ``declared_omissions`` or in
        ``stats.coverage``. ``reason`` and ``unread_credentials`` are passed on
        to either. ``full_weight`` charges the gap a whole entry whatever its
        path; ``configuration`` says a caller found the file to declare MCP
        servers by its content, which the profile never declares.
        """
        if self._declared_omission(rel, full_weight=configuration, unread_credentials=unread_credentials):
            self._gap(rel, declared or message, reason=reason, unread_credentials=unread_credentials)
            return
        self._ledger_gap(rel, message, blinding=blinding, full_weight=full_weight, reason=reason)

    def _ledger_gap(
        self,
        rel: str,
        message: str,
        *,
        blinding: bool = False,
        quiet: bool = False,
        full_weight: bool = False,
        reason: str | None = None,
    ) -> None:
        """Charge one entry at ``rel`` to the coverage ledger, weighed as this connector reads the path.

        Every gap of this connector reaches the ledger here, so each is weighed
        by ``_gap_relevance`` rather than by ``CoverageGap.relevance``'s own
        segment list, which knows neither ``include_tests`` nor test file names.
        """
        self.ctx.coverage_gap(
            message,
            path=rel,
            entries=1,
            blinding=blinding,
            quiet=quiet,
            full_weight=full_weight,
            reason=reason,
            relevance=self._gap_relevance(rel),
        )

    def _gap_relevance(self, rel: str) -> str:
        """``low`` when a gap at ``rel`` is weighed down in the budget, else ``high``.

        Decided as the rest of the scan reads the path: a vendored directory
        (``node_modules``, ``vendor``, ...) is low, and so is a test path as
        ``_is_test_path`` names it (``testing/``, ``e2e/``, ``cassettes/``,
        ``test_*.py``, ``*.test.ts``, ``conftest.py``, ...) while
        ``include_tests`` is off and its evidence is discounted. With
        ``include_tests`` a test path is source and its gaps weigh in full,
        and so does agent configuration under a test path
        (``_agent_configuration``: ``tests/.mcp.json``, ``tests/CLAUDE.md``):
        the discount, the declaration and the budget read it alike
        (``_discounted_test_path``).
        """
        if is_vendored_path(rel) or self._discounted_test_path(rel):
            return "low"
        return "high"

    def _single_file_entry(self, root: Path, walk: _WalkCounters) -> Iterator[tuple[str, Path, str, int]]:
        """Yield a single-file root as ``_iter_entries`` yields a file, counted as one examined entry.

        Counted like every file a directory walk reaches, so a single-file root
        of a multi-root scan is judged against the one entry it examined, in a
        plain run as in an incremental run of that root alone (whose only part
        the connector run would otherwise floor at the objects it examined).
        """
        try:
            size = root.stat().st_size
        except OSError:
            self.ctx.error(f"code.filesystem: could not inspect {root.name}")
            return
        self._entry_projects[root.name] = "."
        if size > self.size_limit(root.name) and self._skipped_oversize(root.name, root.name, size):
            return
        if self._count_entry(walk, root):
            yield root.name, root, ".", size

    def _walk_declared(self, root: Path, rel: str, walk: _WalkCounters) -> bool:
        """``_declared_omission`` for an entry the walk is listing.

        A file's project is recorded before the walk examines it. A directory
        entry (a directory link, a directory named like a configuration file)
        has none, so the walker's lookup assigns it the project of the directory
        that lists it, and the record keeps the gap ``_gap`` then records
        consistent with this answer.
        """
        if self.profile == "ci" and rel not in self._entry_projects:
            self._entry_projects[rel] = _project_root(root, rel, walk.project_roots, budget=walk.budget)
        return self._declared_omission(rel)

    def _budgeted_link_gap(
        self, root: Path, rel: str, link: Path, message: str, *, agent: bool, alias: bool
    ) -> None:
        """Charge an unscanned symbolic link at ``rel`` to the budget, or fail closed if it cannot be bounded.

        A dangling link, or one to a regular file, costs one entry. So does an
        alias of a directory the walk scans at its real path inside the root
        (``lib_alias -> lib``, ``docs/_static -> ../assets``): its files are
        read and counted there, and only the paths below the alias go
        unassessed (``_alias_of_scanned_directory``). Any other link to a
        directory (or to a target the lookup cannot classify) can stand for any
        number of files, a whole service outside the tree among them: the
        scanner cannot bound what it hides, so no budget applies. Nor does a
        link that stands for agent configuration (``agent``, see
        ``_agent_configuration_link``): a file named like it (``.mcp.json``,
        ``.claude/settings.json``, ``CLAUDE.md`` pointing outside the tree),
        judged as an oversize copy of that file is, or a directory an agent
        reads its configuration from (``.claude``, ``.cursor``, ``.vscode``),
        even an alias of a scanned one when a file it holds would be
        configuration at the alias path, since there it is read without the
        path that makes it configuration. A link named like a manifest or a
        build file (``Dockerfile``, ``package.json``, ``.env``) costs one
        entry, as any other does. One representative diagnostic per root and
        kind; the budget still counts every link.
        """
        if agent:
            noted, blinding = self._configuration_link_notes, True
            where = (
                "at the link path its files are agent configuration (named like agent configuration)"
                if alias
                else "it is named like agent configuration"
            )
            message = f"{message}; {where}; coverage incomplete"
        elif _link_names_one_file(link):
            noted, blinding = self._symlink_warnings, False
            message = f"{message}; coverage gap"
        elif alias:
            noted, blinding = self._alias_link_notes, False
            message = (
                f"code.filesystem: skipped symbolic link {rel}, an alias of a scanned directory; "
                "paths below it not assessed; coverage gap"
            )
        else:
            noted, blinding = self._blinding_link_notes, True
            message = (
                f"code.filesystem: skipped symbolic link {rel} whose target may hold any number of "
                "files and is unscanned; coverage incomplete"
            )
        first = root not in noted
        noted.add(root)
        self._ledger_gap(rel, message, blinding=blinding, quiet=not first, reason="unresolved-link")

    def _discounted_test_gap(self, rel: str, *, full_weight: bool = False) -> bool:
        """Whether a coverage gap in ``rel`` is in test code whose evidence the scan discounts.

        With ``include_tests`` off, test and fixture code establishes no agent at
        full weight, and deliberately malformed fixtures are ordinary there:
        syntax-highlighting samples, binary attachments, invalid manifests. A gap
        in such a file is a warning that leaves the scan complete, as an oversize
        test fixture or test code that does not parse already is. Credentials are
        never discounted: a fixture that cannot be decoded is still read for them
        (``_scan_undecodable_file``). Strict accounting keeps every gap, and
        so does agent configuration, whose evidence is not discounted in test
        code either (``_agent_configuration``, or ``full_weight`` from a caller
        that found an MCP configuration by its structure).
        """
        return not full_weight and not self._strict_accounting() and self._discounted_test_path(rel)

    def _discounted_test_path(self, rel: str) -> bool:
        """Whether the evidence passes discount ``rel`` as test code, whatever the accounting.

        ``include_tests`` off, a test path, and not agent configuration
        (``_agent_configuration``), whose findings keep their full weight in
        ``tests/`` as anywhere else: a client started there reads
        ``tests/.mcp.json``, Claude Code reads ``testing/CLAUDE.md``. Such a
        file that cannot be decoded is read for credentials under every
        accounting (``_read_source``): strict accounting decides how its gap
        is recorded, never whether its credentials are read.
        """
        return not self.include_tests and _is_test_path(rel) and not self._agent_configuration(rel)

    def budget_defects(self, rel: str, why: str) -> None:
        """Record that the defects of ``rel`` are in content no client reads as written, and ``why``.

        The file scanner, which holds the text, decides this: a template that
        parses once its placeholders are filled in
        (``template_source.unrendered_template``), or JSON whose repeated keys
        neither reading makes MCP configuration
        (``mcp_config.json_readings_declare_mcp``). A gap recorded for ``rel``
        afterwards is charged to the budget (``_template_source_gap``).
        """
        self._budgeted_defects[rel] = why

    def _template_source_gap(self, rel: str, *, full_weight: bool = False) -> str | None:
        """Why a gap in ``rel`` is in content no client reads as written, such as unrendered template source.

        Template syntax in a directory name (cookiecutter's
        ``{{cookiecutter.package_name}}/pyproject.toml``, copier's ``{% if %}``
        paths, a shell-style ``${name}``) means no tool reads the file where it
        is: the generator fills in its placeholders, and its Jinja blocks
        (``{%- if cookiecutter.depends_on_core -%}``) are not TOML, JSON or
        YAML. A file under an ordinary name is template source when it fails
        to parse only because of its placeholders (``budget_defects``):
        crewAI's ``templates/crew/crew.py`` declares ``class {{crew_name}}():``.
        So is the ambiguity of a JSON data file whose duplicate keys neither
        reading makes MCP configuration (a provider catalog that lists one
        provider twice). None when the gap is not one of these.
        Such a file that does not parse is charged to the coverage budget
        as one partial gap, like a malformed test fixture, instead of failing
        the scan outright; a tree seeded with them still exhausts the budget.
        Agent configuration is never discounted (``_agent_configuration``): a
        client started in the rendered project reads it as written. Strict
        accounting, and a caller that found MCP servers by structure
        (``full_weight``), keep the gap.
        """
        if full_weight or self._strict_accounting() or self._agent_configuration(rel):
            return None
        if _TEMPLATE_SYNTAX.search(rel.rpartition("/")[0]):
            return "unrendered template source (template syntax in its directory)"
        return self._budgeted_defects.get(rel)

    def _discounted_gap(
        self,
        rel: str,
        message: str,
        *,
        error: bool = True,
        suffix: bool = True,
        full_weight: bool = False,
        reason: str | None = None,
        charged_in_full: bool = False,
    ) -> None:
        """Record ``message`` about ``rel`` as a gap (``_gap``), or charge it to the budget in test code
        or unrendered template source (``_template_source_gap``, a whole entry).

        A ``ci`` profile declaration takes precedence over the discount, so the
        omission is counted in ``declared_omissions`` like every other one the
        profile accepts; ``error``, ``suffix`` and ``reason`` are passed on to ``_gap``.
        ``full_weight`` keeps the discount off (see ``_discounted_test_gap``).

        Discounted is not dropped: the gap is a partial one in the coverage
        budget, at the quarter weight of a test path (``_gap_relevance``), and
        is listed in ``stats.coverage.details`` with the discount named in its
        detail. A fixture records one such gap per defect: invalid XML one,
        a structured file that fails the integrity checks two (its excerpts
        withheld, then its ambiguous data), such a dependency manifest three.
        Against the default 2% budget a root therefore tolerates them up to
        about 8% of its entries when each records one, 4% when each records
        two; a tree seeded with them exhausts it.
        ``charged_in_full`` keeps the path weighting off, for a fixture that
        could not be decoded at all: undecodable bytes hide a definition in a
        fixture as easily as anywhere, so they cost a whole entry, and about 2%
        of a root's entries in them exhaust its budget.
        """
        if self._discounted_test_gap(rel, full_weight=full_weight) and not self._declared_omission(rel):
            self._ledger_gap(
                rel,
                f"{message}; test code is discounted evidence (include_tests is false); coverage gap",
                full_weight=charged_in_full,
                reason=reason,
            )
        elif (template := self._template_source_gap(rel, full_weight=full_weight)) and not (
            self._declared_omission(rel)
        ):
            self._ledger_gap(
                rel,
                f"{message}; {template}; coverage gap",
                full_weight=True,
                reason=reason,
            )
        else:
            self._gap(rel, message, error=error, suffix=suffix, reason=reason, full_weight=full_weight)

    def _unreadable_gap(self, rel: str, issue: str, *, by_content: bool = False) -> None:
        """Charge content of ``rel`` that the scanner could not read or decode to the coverage budget.

        Editors and runtimes tolerate bytes the scanner cannot decode, so
        undecodable content is how a definition would be hidden from it: a NUL
        in a settings.json, an agent document or a Dockerfile. That stays
        fail-closed.

        The exception is test code whose evidence the walk discounts
        (include_tests off, as _credential_only_read decides it), where a file of
        deliberately invalid bytes is ordinary and no deployed agent lives. A
        vendored directory is no exception: the walk skips those by name,
        case-sensitively, while default_excludes is on, so what it reads under
        one (Vendor/, or vendor/ with default_excludes off) is source to it.
        Exceptions are charged to the budget at full weight -- never discounted
        the way an unreadable fixture is -- so a tree seeded with them still
        exhausts it. ``by_content`` says the caller found the file to declare
        MCP servers: agent configuration, which is no exception there and is
        never declared (``_agent_configuration``). Content that reaches this
        gap was not read for credentials (a file that could not be opened or
        read, or undecodable bytes left to no credential-only read), so the
        ``ci`` profile does not declare it either (``unread_credentials``).
        """
        incidental = self._discounted_test_gap(rel, full_weight=by_content)
        self._budgeted_gap(
            rel,
            f"code.filesystem: {rel}: {issue}",
            blinding=not incidental,
            full_weight=True,
            reason=_read_issue_reason(issue),
            configuration=by_content,
            unread_credentials=True,
        )

    def _strict_gap_warning(self, message: str, *, reason: str) -> None:
        """Warn about content the default accounting does not count as a gap; strict accounting does.

        Under strict accounting the warning marks the scan incomplete, under
        ``reason``, and ends in ``coverage incomplete``, so it reads as the gap
        it is counted as rather than as a note.
        """
        strict = self._strict_accounting()
        self.ctx.warn(
            f"{message}; coverage incomplete" if strict else message, incomplete=strict, reason=reason
        )

    def _skip_oversize_test_fixture(self, rel: str, size: int | None) -> None:
        """Skip an oversize file of discounted test code with a counted warning, credentials not scanned.

        Agent configuration is not discounted test code (``_discounted_test_path``),
        so ``tests/.mcp.json`` or ``tests/CLAUDE.md`` never comes here: it stays a gap.
        """
        self.skipped_oversize_test_fixtures += 1
        over = f"{size} bytes over" if size is not None else "over"
        self.ctx.warn(
            f"code.filesystem: {rel}: skipped oversize test fixture ({over} max_file_size "
            f"{self.max_file_size}); test code is discounted evidence, include_tests is false and "
            "credential detection is off",
            incomplete=False,
        )

    def _alias_of_scanned_directory(self, rel: str, target: Path, resolved_root: Path) -> bool:
        """Whether directory link ``rel`` names ``target``, a directory inside the root the walk scans whole.

        ``target`` is the link's resolved target below ``resolved_root`` (see
        ``_resolved_link_target``). Every directory on its path must be one the
        walk enters (not excluded, by default or by ``exclude``) and the
        target must lie within the selected paths, so its files are read and
        counted at their real paths. Nor may the alias read as product code
        what the walk discounts as test code there (``src/lib -> ../tests``),
        which would weaken the evidence the alias path would carry.
        """
        if not self._directory_scanned_at_real_path(target, resolved_root):
            return False
        target_rel = target.relative_to(resolved_root).as_posix()
        return not (
            _is_test_path(f"{target_rel}/{_ANY_FILE_NAME}") and not _is_test_path(f"{rel}/{_ANY_FILE_NAME}")
        )

    def _agent_configuration_link(self, rel: str, link: Path, alias_of: Path | None = None) -> bool:
        """Whether a symbolic link at ``rel`` stands for agent configuration, which no budget may absorb.

        A link named like an agent configuration file (``_agent_configuration``),
        or one to a directory, or dangling, whose path can hold such a file
        (``_agent_directory_path``): it is, or lies on the way to or within, a
        directory an agent configuration glob names (``tests/e2e/.claude``,
        ``docs/.vscode``, ``.cursor/rules/team``, ``.github/instructions``),
        not merely below a generic dot-directory (``.github/actions/setup``).
        An alias of a directory the walk scans (``alias_of``, its target) is
        then judged by what it holds: it stands for agent configuration when a
        file below it would be configuration at the alias path
        (``_alias_holds_agent_configuration``), so ``web/public/.well-known``
        aliasing a directory without an MCP manifest or agent card is an
        ordinary alias. A link to a single file is judged by its own name:
        ``.github/CODEOWNERS`` is not configuration because ``.github`` is.
        """
        if self._agent_configuration(rel, link.name):
            return True
        if _link_target_kind(link) == "file" or not self._agent_directory_path(rel):
            return False
        return alias_of is None or self._alias_holds_agent_configuration(rel, alias_of)

    def _agent_directory_path(self, rel: str) -> bool:
        """Whether a directory at ``rel`` can hold a file an agent configuration glob selects.

        Some trailing run of its components (``.claude``, ``.github/instructions``)
        lies along the directory part of a glob (``_agent_directory_globs``),
        compared case-insensitively, or reaches a wildcard there
        (``.cursor/rules/**`` holds ``.cursor/rules/team``). One generic
        dot-directory on the path does not make it so: ``.github/actions/setup``
        and ``.github/workflows`` hold no file ``.github/copilot-instructions.md``
        or ``.github/agents/*.md`` names.
        """
        parts = rel.lower().split("/")
        by_first, wildcard_first = self._agent_directory_globs()
        for start in range(len(parts)):
            window = parts[start:]
            for components in (*by_first.get(window[0], ()), *wildcard_first):
                if _on_glob_directory(window, components):
                    return True
        return False

    def _agent_directory_globs(self) -> _AgentGlobs:
        """Agent configuration globs below a dot-directory, as lower-cased components.

        Every coding-agent and MCP file-name signature glob (custom packs
        included) whose directory part names a dot-directory, without its
        leading ``**/``; the settings directories the posture reader knows
        (``.claude/**``, ``.codex/**``, ...), the agent definition directories,
        the clients' own settings files and the agent cards a site serves
        (``.well-known/agent.json``). Keyed by a literal first component, the
        rest listed apart. Computed once per connector.
        """
        if self._agent_directories is None:
            globs = {
                *(f"{name}/**" for name in (".claude", ".codex", ".gemini", ".openclaw", ".clawdbot")),
                *(f"{directory}**" for directory in _AGENT_DEFINITION_DIRS),
                *(f"{directory}/{name}" for directory, name in _CLIENT_SETTINGS_FILES),
                *(f".well-known/{name}" for name in ("agent.json", "agent-card.json", "agent_card.json")),
            }
            for signature, signal in self.index.signals_of_type("file"):
                if signature.category == "coding-agent" or signature.id == "protocol.mcp":
                    globs.update(signal.globs)
            by_first: dict[str, list[tuple[str, ...]]] = {}
            wildcard_first: list[tuple[str, ...]] = []
            for glob in sorted(globs):
                components = tuple(glob.lower().removeprefix("**/").split("/"))
                if len(components) < 2 or not any(part.startswith(".") for part in components[:-1]):
                    continue
                if _GLOB_CHARACTERS.search(components[0]):
                    wildcard_first.append(components)
                else:
                    by_first.setdefault(components[0], []).append(components)
            self._agent_directories = (by_first, wildcard_first)
        return self._agent_directories

    def _alias_holds_agent_configuration(self, rel: str, target: Path) -> bool:
        """Whether a file below ``target`` would be agent configuration at the alias path ``rel``.

        ``target`` is a directory the walk scans at its real path, where such a
        file is read without the path that makes a client read it. Its tree is
        listed, without following links, up to ``_MAX_ALIAS_ENTRIES`` entries;
        a longer one, or one that cannot be listed, is taken to hold some, and
        so is a directory link below it whose alias path could.
        """
        seen = 0
        failed: list[OSError] = []
        for directory, dirnames, filenames in os.walk(target, onerror=failed.append):
            below = Path(directory).relative_to(target).as_posix()
            prefix = rel if below == "." else f"{rel}/{below}"
            links = [name for name in dirnames if os.path.islink(os.path.join(directory, name))]
            seen += len(filenames) + len(links)
            if seen > _MAX_ALIAS_ENTRIES or failed:
                return True
            if any(self._agent_configuration(f"{prefix}/{name}", name) for name in filenames):
                return True
            if any(self._agent_directory_path(f"{prefix}/{name}") for name in links):
                return True
        return bool(failed)

    def _credential_only_read(self, rel: str) -> bool:
        """Whether an undecodable ``rel`` is read for credentials alone before its gap is recorded.

        So it is when that gap would be discounted as test code
        (``_discounted_test_path``, under every accounting) or declared by the
        ``ci`` profile (``_declared_omission``: a documentation, example or
        generated file), since credentials are never discounted or declared
        without a read. Any other undecodable file is a blinding gap.
        """
        return self._discounted_test_path(rel) or self._declared_omission(rel)

    def _mcp_by_content(self, scan: _ScanState, rel: str, path: Path) -> bool:
        """Whether ``rel``, whose analysis failed, is an MCP configuration by its content.

        As ``_detect_mcp`` decided it when it got that far; before that (a
        failure in credential detection, or earlier), by the file's bytes, as
        an oversize file's are read (``_file_may_declare_mcp``), for a file the
        MCP parser decides by its content (``_guessed_mcp_name``).
        """
        if self._content_mcp is not None:
            return self._content_mcp
        if not _guessed_mcp_name(rel, path.name):
            return False
        on_disk = PurePosixPath(path.relative_to(scan.base).as_posix()) if scan.base else PurePosixPath(rel)
        return self._file_may_declare_mcp(on_disk, scan.root_fd)

    def _oversize_gap(self, rel: str, name: str, on_disk: PurePosixPath, root_fd: int) -> None:
        """Record a file over ``max_file_size``: blinding when it hides agent configuration, else one entry.

        Incidental content (generated source, a data export) costs one entry of
        the budget. Agent configuration does not (``_agent_configuration``): by
        its name, or, for a file the MCP parser decides by its content, when its
        bytes may name a server table (``_file_may_declare_mcp``), so padding a
        ``deploy/tools.json`` that holds ``mcpServers`` hides it no better than
        padding a ``.mcp.json``. Nor does a file that exists to hold credentials
        while they are scanned: a dotenv file, unread, hides one. A file whose
        bytes may name a server table is charged a whole entry and never
        declared by the ``ci`` profile, with credential detection off too
        (``configuration``): ``docs/.continue/mcpServers/evil.yaml`` or a
        padded ``tests/fixtures/servers.json``.

        While ``scan_secrets`` is on, none of the file's bytes was read for
        credentials, so its gap is never declared and never weighed down by its
        path: a fixture or cassette under ``tests/`` costs a whole entry, as one
        in ``src/`` does. Reading oversize content for credentials alone is not
        done; a key in it is the trade-off the budget accepts (SECURITY.md).
        """
        named = self._agent_configuration(rel, name)
        by_content = (
            not named and _guessed_mcp_name(rel, name) and self._file_may_declare_mcp(on_disk, root_fd)
        )
        selected = named or by_content or (self.scan_secrets and _dotenv_name(name))
        if not selected and not self.scan_secrets and self._discounted_test_gap(rel):
            # A test fixture the walk left to this content check, which found no server table.
            self._skip_oversize_test_fixture(rel, None)
            return
        issue = "file exceeds max_file_size"
        self._budgeted_gap(
            rel,
            f"code.filesystem: {rel}: skipped, {issue}; "
            + ("coverage incomplete" if selected else "coverage gap"),
            declared=f"code.filesystem: {rel}: skipped, {issue}",
            blinding=selected,
            full_weight=self.scan_secrets or by_content,
            reason="oversize-file",
            unread_credentials=True,
            # Bytes that may name a server table make the file MCP configuration
            # by its content, which the ci profile never declares, whatever
            # credential detection read (_declared_omission).
            configuration=by_content,
        )

    @staticmethod
    def _file_may_declare_mcp(on_disk: PurePosixPath, root_fd: int) -> bool:
        """Whether a file's bytes may name an MCP server table key (``_may_declare_mcp``), unanalyzed.

        The file is opened as the reader opens it, confined below the scan root,
        and read in chunks up to ``_MCP_CHECK_BYTES``, lower-cased and without
        NUL bytes (a UTF-16 copy then reads as ASCII), so a key anywhere in it
        is found, behind any padding. Only this check reads it: nothing is
        analyzed or excerpted. An MCP registry manifest (``server.json``)
        declares its server without such a key, and a file the check cannot
        read, or one longer than the bytes it reads, may declare servers too.

        A JSON file of at most ``_MCP_STRUCTURE_BYTES`` whose bytes name a key
        is then decided by its structure, under both readings of a repeated
        key (``json_readings_declare_mcp``): an OpenAPI snapshot that describes
        an ``mcp_servers`` field holds no server table. One that does not
        parse as UTF-8 JSON keeps the byte check's answer.
        """
        if on_disk.name.lower() == "server.json":
            return True
        structured = on_disk.name.lower().endswith(".json")
        try:
            with open_confined_file(on_disk, label="file", dir_fd=root_fd) as (fh, _):
                window, read, kept = b"", 0, bytearray()
                while read < _MCP_CHECK_BYTES:
                    chunk = fh.read(_MCP_CHECK_CHUNK)
                    if not chunk:
                        return False
                    read += len(chunk)
                    if structured and read <= _MCP_STRUCTURE_BYTES:
                        kept += chunk
                    window = window[-_MCP_CHECK_OVERLAP:] + chunk.replace(b"\x00", b"").lower()
                    if _may_declare_mcp(window):
                        return not (structured and _json_holds_no_server_table(fh, kept, read))
        except (OSError, ValueError):
            pass
        return True

    def _agent_configuration(
        self,
        rel: str,
        name: str | None = None,
        file_matches: list[Match] | None = None,
        *,
        by_content: bool = False,
    ) -> bool:
        """Whether ``rel`` is agent, MCP or coding-agent configuration the scanner reports at full weight.

        The one predicate every coverage gap site reads -- a link, a FIFO or
        other non-regular entry, an oversize, undecodable or unreadable file,
        content that did not parse -- and so do the ``ci`` declaration
        (``_declared_omission``), the test-code discount
        (``_discounted_test_path``) and the budget's path weighting: such a
        file is never budgeted, discounted or declared away. However it goes
        unread, padded, linked, NUL-poisoned or renamed in case, it hides a
        definition, so a link and an oversize copy of one file are judged
        alike. It is:

        * a dedicated MCP configuration name, a coding-agent settings path, a
          client's own settings file under a shared name
          (``.vscode/settings.json``, ``_CLIENT_SETTINGS_FILES``), a
          coding-agent instruction document, an agent manifest or card, each
          compared case-insensitively, as the detectors and a case-insensitive
          file system compare them (``.MCP.JSON``, ``.claude/Settings.json``);
        * a file in an agent definition directory (``.cursor/rules/``) or that
          a coding-agent or MCP file-name signature selects, its
          directory-wide globs included (``.continue/mcpServers/*.yaml``,
          ``.roo/rules/*.md``, ``.kiro/steering/*``), whatever its suffix
          (``.cursor/rules/deploy.rule``, ``.clinerules/01.rules``,
          ``.windsurf/rules/x.rst``): only a binary asset kept beside the
          rules (``_BINARY_ASSET_SUFFIXES``: an image, a font, an archive) is not;
        * a file whose content a caller found to declare MCP servers
          (``by_content``).

        Generic manifests and build files are not (``requirements.txt``,
        ``Dockerfile``, ``*.tf``, ``package.json``, ``.env``,
        ``docker-compose.yml``), nor shared client names such as
        ``config.json`` or ``settings.json`` outside their client's directory,
        which are MCP configuration only by their content: their gaps are
        ordinary, budgeted ones. ``file_matches`` saves a caller that holds
        the file-name matches another lookup.
        """
        if by_content:
            return True
        name = PurePosixPath(rel).name if name is None else name
        lower = rel.lower()
        if (
            name.lower() in _DEDICATED_MCP_CONFIG_NAMES
            or _is_coding_agent_doc(name)
            or is_agent_config_path(lower)
            or _client_settings_file(lower)
            or posture_client(rel) is not None
            or agent_manifest_kind(lower) is not None
        ):
            return True
        matches = self.index.match_file(rel) if file_matches is None else file_matches
        if not any(_agent_file_signal(m) for m in matches) and not any(
            directory in lower for directory in _AGENT_DEFINITION_DIRS
        ):
            return False
        return PurePosixPath(name).suffix.lower() not in _BINARY_ASSET_SUFFIXES


def _link_names_one_file(link: Path) -> bool:
    """Whether a link the walk does not follow stands for one file at most: dangling, or to a regular file.

    Anything else (``_link_target_kind`` ``other``) can stand for any number
    of files, inside the scan root or outside it.
    """
    return _link_target_kind(link) != "other"


# Binary assets a repository keeps beside its coding-agent rules (images, fonts,
# archives, audio and video): no agent reads one as configuration, so an unread
# copy there is an ordinary gap. Any other suffix in a rule directory is
# configuration (``.rule``, ``.rules``, ``.markdown``, ``.rst``), read or not.
_BINARY_ASSET_SUFFIXES = frozenset(
    {
        *(".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".tif", ".tiff", ".avif", ".heic"),
        *(".svg", ".psd", ".woff", ".woff2", ".ttf", ".otf", ".eot"),
        *(".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".zst", ".jar"),
        *(".mp3", ".wav", ".ogg", ".flac", ".m4a", ".mp4", ".mov", ".webm", ".avi", ".mkv"),
    }
)


# Shared client names (MCP_CONFIG_NAMES) in the directory of the client that
# reads its servers from them: VS Code's workspace settings (an ``mcp`` table),
# Gemini CLI's settings, Continue's configuration, Codex's ``[mcp_servers]``.
# Elsewhere such a name is generic (a root ``settings.json`` or ``config.json``)
# and the file is MCP configuration only by its content; here it is the
# client's own settings file, however it goes unread.
_CLIENT_SETTINGS_FILES = frozenset(
    {
        (".vscode", "settings.json"),
        (".gemini", "settings.json"),
        (".continue", "config.json"),
        (".continue", "config.yaml"),
        (".codex", "config.toml"),
    }
)


# Any spelling of an MCP server table key, in bytes lower-cased and stripped of NUL
# bytes: the check of content whose structure cannot be read (an oversize file, a
# binary one, one whose parse failed). ``mcpServers`` and ``mcp_servers`` however
# quoted, spaced, made explicit (``? mcpServers``) or dotted (``['mcp_servers'.e]``);
# an ``mcp`` key (``"mcp":``, ``mcp =``, a ``[mcp]`` table, ``mcp.servers``). It is
# searched after ``_unescaped_key_bytes`` has written each escaped key character
# as itself and joined a quoted key folded across a line break, so no encoding
# the parser would undo hides the key. A quoted token that starts an ``mcp`` key
# and folds into 256 blanks or more is a candidate too, since the join is bounded.
_MCP_KEY_BYTES = re.compile(
    rb"mcp(?:[_-]?servers|[\"']?\s{0,256}(?:[:=]|\.\s{0,256}[\"']?servers)|[\"']?\s{1,256}#|[\"']?\s{256})"
    rb"|(?:^|\n)[ \t]{0,256}\[[ \t]{0,256}[\"']?mcp[\"']?[ \t]{0,256}\]"
    rb"|\"(?:m(?:c(?:p[_-]?[a-z]{0,7})?)?)?\\\r?\n[ \t]{256}"
)


# An escape of an ASCII character as JSON (``m``), TOML (``\U0000006D``) and
# YAML (``\x6d``) write one, lower-cased: the 8-digit form is tried first.
_KEY_ESCAPE_BYTES = re.compile(rb"\\(?:u0{6}([0-9a-f]{2})|u00([0-9a-f]{2})|x([0-9a-f]{2}))")


# Characters a server table key is spelled with: only their escapes are decoded.
_KEY_CHARACTERS = frozenset(b"abcdefghijklmnopqrstuvwxyz0123456789_-.")


# A YAML double-quoted token folded across a line break by an escaped newline
# (``"mcp\`` then ``Servers"`` on the next line), as ``yaml.dump`` writes a long key.
# The escaped break and the next line's indentation are no part of the scalar.
_FOLD_BYTES = rb"\\\r?\n[ \t]{0,256}"


_FOLDED_TOKEN_BYTES = re.compile(rb"\"(?:[a-z0-9_.-]{0,64}" + _FOLD_BYTES + rb")+[a-z0-9_.-]{0,64}")


_FOLD = re.compile(_FOLD_BYTES)


# Bytes of an oversize file read for that check, in chunks: more than any file a
# Git host stores outside LFS (GitHub refuses one over 100 MiB). Past them the
# file is taken to declare servers, since the check cannot rule it out.
_MCP_CHECK_BYTES = 128 * 1024 * 1024


_MCP_CHECK_CHUNK = 1024 * 1024


# What a chunk keeps of the one before it, so a key cut at a chunk boundary is
# still seen whole: an escaped, folded spelling of the longest key, each of its
# eleven characters written as a ten-byte escape after a 256-blank fold, is
# shorter than 3,200 bytes.
_MCP_CHECK_OVERLAP = 4096


# Bytes of an oversize JSON file parsed to decide by its structure whether it
# holds a server table (``_file_may_declare_mcp``); a larger one keeps the byte check's answer.
_MCP_STRUCTURE_BYTES = 8 * 1024 * 1024


def _json_holds_no_server_table(fh: BinaryIO, kept: bytearray, read: int) -> bool:
    """Whether a JSON file, of which ``kept`` holds the first ``read`` bytes, provably holds no server table.

    The rest of the file is read up to ``_MCP_STRUCTURE_BYTES``; a longer file,
    or one that is not UTF-8 JSON, is not proven to hold none.
    """
    if read > _MCP_STRUCTURE_BYTES:
        return False
    rest = fh.read(_MCP_STRUCTURE_BYTES - read + 1)
    if len(kept) + len(rest) > _MCP_STRUCTURE_BYTES:
        return False
    try:
        text = (bytes(kept) + rest).decode("utf-8-sig")
    except UnicodeDecodeError:
        return False
    return json_readings_declare_mcp(text) is False


def _escaped_key_character(match: re.Match[bytes]) -> bytes:
    """The key character an escape writes, lower-cased; any other escape is kept as written."""
    character = bytes([int(match.group(match.lastindex or 1), 16)]).lower()
    return character if character[0] in _KEY_CHARACTERS else match.group()


def _unfolded_key(match: re.Match[bytes]) -> bytes:
    """A folded double-quoted token joined when it then starts an ``mcp`` key; any other is kept."""
    joined = _FOLD.sub(b"", match.group())
    return joined if joined.startswith(b'"mcp') else match.group()


def _unescaped_key_bytes(data: bytes) -> bytes:
    """``data`` (lower-cased) with escaped key characters written as themselves and folded keys joined.

    Only a double-quoted token whose joined text starts an ``mcp`` key is
    joined, so a cassette's folded strings or a shell script's line
    continuations, which spell no key, stay as they are.
    """
    if b"\\" not in data:
        return data
    return _FOLDED_TOKEN_BYTES.sub(_unfolded_key, _KEY_ESCAPE_BYTES.sub(_escaped_key_character, data))


def _may_declare_mcp(data: bytes) -> bool:
    """Whether ``data`` (lower-cased, without NUL bytes) may name an MCP server table key."""
    return _MCP_KEY_BYTES.search(_unescaped_key_bytes(data)) is not None


# Suffixes of a file whose structure can make it an MCP configuration whatever its name.
_MCP_STRUCTURE_SUFFIXES = (".json", ".toml", ".yaml", ".yml")


def _guessed_mcp_name(rel: str, name: str) -> bool:
    """Whether ``_looks_like_mcp_config`` decides by its content if ``rel`` is MCP configuration."""
    lower = name.lower()
    if "{{" in rel or lower.endswith((".lock.yml", ".lock.yaml")):
        return False
    return lower in MCP_CONFIG_NAMES or rel.endswith(_MCP_STRUCTURE_SUFFIXES)


def _dotenv_name(name: str) -> bool:
    """Whether ``name`` is a dotenv file (``.env``, ``.env.production``), which exists to hold credentials.

    An oversize one was a gap before the coverage budget existed, as any oversize
    analyzable file was, and stays one no budget absorbs. A tool credential file
    (``CREDENTIAL_FILE_NAMES``) has been read only since the credential pass took
    it up, as one entry of the budget when oversize, like other unread content.
    """
    return name.lower().startswith(".env")


def _client_settings_file(lower: str) -> bool:
    """Whether ``lower`` (lower-cased) names a client's own settings file: ``_CLIENT_SETTINGS_FILES``."""
    path = PurePosixPath(lower)
    return (path.parent.name, path.name) in _CLIENT_SETTINGS_FILES


def _agent_file_signal(match: Match) -> bool:
    """Whether ``match`` is a coding-agent or MCP file-name signal: one that selects agent configuration."""
    return match.signal.type == "file" and (
        match.signature.category == "coding-agent" or match.signature_id == "protocol.mcp"
    )


def _link_target_kind(link: Path) -> str:
    """``file``, ``missing`` or ``other``: what a link the walk does not follow names.

    Its target is looked up, never opened. A loop resolves to nothing at all,
    like a dangling link. A directory, any other kind of entry, or a lookup
    that fails for a reason other than absence is ``other``.
    """
    try:
        return "file" if stat.S_ISREG(os.stat(link).st_mode) else "other"
    except (FileNotFoundError, NotADirectoryError):
        return "missing"
    except OSError as exc:
        return "missing" if exc.errno == errno.ELOOP else "other"


_GLOB_CHARACTERS = re.compile(r"[*?\[]")


# Agent configuration globs as components: keyed by a literal first one, and the rest.
_AgentGlobs = tuple[dict[str, list[tuple[str, ...]]], list[tuple[str, ...]]]


# Entries an alias of a scanned directory is listed for before it is taken to
# hold agent configuration (``_alias_holds_agent_configuration``).
_MAX_ALIAS_ENTRIES = 1000


def _on_glob_directory(window: list[str], components: tuple[str, ...]) -> bool:
    """Whether a directory whose trailing components are ``window`` can hold a file the glob selects.

    ``components`` is the glob split at ``/``. Each component of ``window`` must
    match the glob's at the same depth within its directory part; a component
    with a ``*``, which spans ``/`` as ``fnmatch`` reads it, holds any
    directory whose name starts with its literal prefix.
    """
    for depth, part in enumerate(window):
        if depth >= len(components):
            return False
        pattern = components[depth]
        if "*" in pattern:
            return part.startswith(_GLOB_CHARACTERS.split(pattern, maxsplit=1)[0])
        if depth == len(components) - 1 or not fnmatch.fnmatchcase(part, pattern):
            # A literal file name holds no directory; a component that differs leaves the glob.
            return False
    return True
