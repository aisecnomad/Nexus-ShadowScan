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
import os
import re
import stat
import time
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from shadowscan.connectors.base import ConnectorContext, ConnectorError
from shadowscan.connectors.code.lockfiles import LOCKFILE_NAMES
from shadowscan.connectors.code.manifests import is_manifest_name
from shadowscan.connectors.code.model_artifacts import ARTIFACT_SUFFIXES
from shadowscan.connectors.code.path_context import _is_test_path
from shadowscan.connectors.code.scan_records import _Project
from shadowscan.connectors.code.semantic_config import is_agent_config_path
from shadowscan.connectors.posture import (
    CLIENT_SIGNATURES,
    approval_scopes,
    posture_client,
    unreadable_settings,
)
from shadowscan.signatures.matcher import SOURCE_EXTENSIONS, WALL_BUDGET_FACTOR, MatchTimeoutError
from shadowscan.utils.files import open_confined_directory, open_confined_file, read_policy_text
from shadowscan.utils.git import MAX_GITMODULES_BYTES, declared_submodule_paths, read_gitlink_paths
from shadowscan.utils.redaction import sanitize_text

if TYPE_CHECKING:  # filesystem imports this module
    from shadowscan.connectors.code.filesystem import _ScanState

DEFAULT_MAX_WALK_ENTRIES = 1_000_000

# Entries inspected to decide whether a skipped directory holds any file.
_EMPTY_DIRECTORY_PROBE_ENTRIES = 256


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

# A file over max_file_size that the scanner would read leaves coverage
# incomplete: unread content could hide agent configuration. Names matching
# these globs hold generated, locked or binary content that is explicitly
# outside the scan scope, so skipping them is a warning and the scan stays
# complete. The connector's `oversize_skip_globs` replaces the list.
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


def deadline_margin(remaining: float) -> float:
    """Return the safety margin kept before a connector deadline.

    Five percent of the budget that remained when the walk started, and at
    least 250 ms, covers emitting the collected project findings and the
    engine's own sanitization before it compares completion to the deadline.
    """
    return max(DEADLINE_MARGIN_MIN_SECONDS, DEADLINE_MARGIN_FRACTION * remaining)


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
    ctx: ConnectorContext,
    rel: str,
    analysis: str,
    reason: Callable[[Exception], str] = _exception_name,
) -> Iterator[None]:
    """Contain a failure while analyzing ``rel`` to one diagnostic so other findings survive.

    A ConnectorError always propagates: cancellation or an exhausted
    deadline ends the walk and must not become one "incomplete" error per
    file, project or finding.
    """
    try:
        yield
    except ConnectorError:
        raise
    except Exception as exc:  # noqa: BLE001 - isolate hostile input and retain other findings
        ctx.error(f"code.filesystem: {rel}: {analysis} incomplete ({reason(exc)})")


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
        # Names the scan root in a diagnostic when the connector scans several roots
        # (``FilesystemConnector._root_prefix``, which reads the connector's configuration).
        self._root_prefix = root_prefix
        # Default-excluded directory names the current walk skipped, with counts.
        self._default_skipped: dict[str, int] = {}
        # Files that were read but not as clean text, by what was done to them (see ``note_file``).
        self._file_notes: dict[str, list[str]] = {}
        self._symlink_warnings: set[Path] = set()
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
        ``strict_coverage`` treats each as a coverage gap, as the reader did before it read such files.
        """
        if self.strict_coverage:
            self.ctx.error(f"code.filesystem: {rel}: {note}; strict_coverage treats this as a gap")
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
                "declares these dependencies, so they are unscanned"
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
        in ``skipped_oversize_test_fixtures``. With credential detection on
        (the default) every read file, prose and fixtures included, is scanned
        for credentials, so an unread copy may hide a real key and stays a gap
        (fail closed). ``strict_coverage`` keeps the test-path case a gap too.
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
            # they could hide one, so the reader records the gap.
            return False
        if not self._content_bearing(rel, name):
            self._skip_oversize(
                rel,
                size,
                "documentation is matched by file name only and credential detection is off, "
                "so its text is not read",
            )
            return True
        if not self.include_tests and _is_test_path(rel):
            if self.strict_coverage:
                return False
            self.skipped_oversize_test_fixtures += 1
            self.ctx.warn(
                f"code.filesystem: {rel}: skipped oversize test fixture ({size} bytes over max_file_size "
                f"{self.max_file_size}); test code is discounted evidence, include_tests is false and "
                "credential detection is off",
                incomplete=False,
            )
            return True
        return False

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
        parts = relative.parts
        for depth, name in enumerate(parts[:-1], start=1):
            if self._excluded(PurePosixPath(*parts[:depth]).as_posix(), name):
                return False
        # An include walk never reaches a target outside the selected paths,
        # however equivalent the alias is.
        if (
            not target.is_file()
            or self._excluded_file(target_rel)
            or not self.included(target_rel)
            or _never_read_by_name(target.name)
        ):
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
            try:
                size = root.stat().st_size
            except OSError:
                self.ctx.error(f"code.filesystem: could not inspect {root.name}")
                return
            if size > self.size_limit(root.name) and self._skipped_oversize(root.name, root.name, size):
                return
            yield root.name, root, ".", size
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
                proj = rel_dir
            for fn in sorted(filenames):
                walk.budget.check()
                _check_enumeration_time(walk)
                shown = _report_name(fn)
                rel = shown if rel_dir == "." else f"{rel_dir}/{shown}"
                if self._excluded_file(rel) or not self.included(rel):
                    continue
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
                    self.ctx.error(f"code.filesystem: could not inspect {rel}")
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
                self.ctx.error(f"code.filesystem: could not inspect {rel}")
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
        """
        walk.non_regular += 1
        if walk.non_regular > _MAX_NON_REGULAR_NOTES + 1:
            return
        if walk.non_regular == _MAX_NON_REGULAR_NOTES + 1:
            message = f"code.filesystem: further non-regular entries under {root} not listed"
        else:
            message = (
                f"code.filesystem: {rel}: skipped, not a regular file ({kind}) but named like "
                "analyzable content"
            )
        if self.strict_coverage:
            self.ctx.error(f"{message}; coverage incomplete")
        else:
            self.ctx.warn(f"{message}; coverage incomplete", incomplete=True)

    def _count_entry(self, walk: _WalkCounters, root: Path) -> bool:
        """Count one examined entry (a file or a link); False once ``max_files`` is reached."""
        walk.examined += 1
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
        # A single representative diagnostic per root keeps hostile trees
        # from filling the report with thousands of link names.
        walk.link_gaps += 1
        if root not in self._symlink_warnings:
            self._symlink_warnings.add(root)
            # Stays fail-closed: the target's bytes exist and other tools may
            # read them, so an unscanned target is lost coverage a repository
            # could hide behind — not a file-attributable input defect.
            message = f"code.filesystem: skipped symbolic link {rel} whose target is unavailable or unscanned"
            if self.strict_coverage:
                self.ctx.error(f"{message}; coverage incomplete")
            else:
                self.ctx.warn(f"{message}; coverage incomplete", incomplete=True)
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
        return budget if will_read or self.model_artifact_name(path.name) else 0.0

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
        margin = deadline_margin(deadline - time.monotonic()) if deadline is not None else 0.0
        scan.margin = margin
        entries: list[tuple[str, Path, str, int]] = []
        try:
            self._unread_settings = []
            self._lockfile_governed = {}
            entries.extend(self._iter_entries(scan.root))
        except _WalkLimitError as exc:
            # Enumeration hit max_entries or its share of the deadline: the
            # files already enumerated are still scanned (in priority order)
            # so partial findings survive, and the limit is recorded.
            self.ctx.error(f"code.filesystem: {scan.label}: {exc}; results incomplete")
            self.root_listing_incomplete = True
        entries.sort(key=lambda entry: (_scan_priority(entry[0], entry[1].name), entry[3]))
        examined = 0
        for index, (rel, path, proj_root, size) in enumerate(entries):
            if scan.diff_files is not None and not self._diff_included(rel, scan.diff_files):
                continue
            analysis_size = (
                min(size, self.model_metadata_bytes) if self.model_artifact_name(path.name) else size
            )
            budget = scan_timeout_for_size(self.scan_timeout, analysis_size)
            wall_cap = budget * WALL_BUDGET_FACTOR
            reserve = self._reserved_budget(rel, path, size, budget)
            if deadline is not None:
                remaining = deadline - time.monotonic()
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
            with (
                isolated(self.ctx, rel, "file analysis", _file_failure_reason),
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
