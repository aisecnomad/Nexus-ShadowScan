"""The records the code scan's collaborators share, and helpers that need no scanner state.

``_Project`` gathers what the file scan observes for one project of the walk,
``_SourceFile`` one file under analysis and ``_MatchedSource`` a source file's
lexical evidence until its import-bound analysis; the findings collaborator
builds findings from them. ``FindingBase`` types the connector's finding
constructor that the file scan and the findings collaborators are handed, and
``_MCP_TRANSPORTS`` names the MCP server transports both read from code
matches. The functions decide from their arguments alone: whether a parsed
document configures MCP servers (beside the file names that always do), whether
a signature ships with the scanner, and whether an import names a module of the
scanned tree. The module imports none of the collaborators, so each of them can
import it (ADR-005).
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

import yaml

from shadowscan.connectors.base import incomplete_reason
from shadowscan.connectors.code.excerpts import _ExcerptSource, _Snippet
from shadowscan.connectors.code.import_provenance import local_module_conflict
from shadowscan.connectors.code.instruction_content import ContentHit
from shadowscan.connectors.code.manifests import Dep
from shadowscan.connectors.code.mcp_config import mcp_server_holders
from shadowscan.connectors.code.skill_audit import InstructionAudit
from shadowscan.connectors.code.source_text import _YAML_SUFFIXES, _CellSpans
from shadowscan.models import Finding, Kind
from shadowscan.signatures import Match, Signature
from shadowscan.signatures.loader import builtin_signature_dir
from shadowscan.signatures.matcher import LiteralScan
from shadowscan.utils.text import BINARY_CONTENT_ERROR

# The transport an MCP server code match names (metadata.mcp_server.transports).
_MCP_TRANSPORTS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("stdio", re.compile(r"\b(?:stdio_server|StdioServerTransport)\s*\(")),
    ("http", re.compile(r"\b(?:StreamableHTTP\w*|SseServerTransport|SSEServerTransport)\s*\(")),
)


# File names that only ever hold MCP client/server configuration. Any other
# file is MCP configuration only when its parsed structure configures a server.
_DEDICATED_MCP_CONFIG_NAMES = frozenset(
    {
        ".mcp.json",
        "mcp.json",
        "mcp-config.json",
        "mcp_config.json",
        "mcp-servers.json",
        "claude_desktop_config.json",
        "cline_mcp_settings.json",
        "mcp_settings.json",
        "smithery.yaml",
    }
)


def _document_declares_mcp(document: Any) -> bool | None:
    """Whether a parsed JSON/TOML/YAML document configures MCP servers, wherever the table sits.

    Decided from the structure, not a text prefix (``mcp_server_holders``): a key
    named ``mcpServers`` or ``mcp_servers``, or an ``mcp`` mapping with a
    ``servers`` key, at the top level, nested within a client's section or in a
    mapping inside a list (an Ansible task that writes ``~/.cursor/mcp.json``
    from structured ``content``, a list of client profiles), where it must hold
    a mapping of servers or a list of server records (Continue's
    ``mcpServers: [{name, command}]``), not a transcript's status list. The
    walk is bounded in depth and breadth so a hostile document cannot make it
    expensive; None when those bounds stopped it before it found a table, so
    the caller decides from the text instead of taking the file to declare none.
    """
    holders, truncated = mcp_server_holders(document, first=True)
    if holders:
        return True
    return None if truncated else False


@dataclass
class _Project:
    root: str  # relative posix path ("." for scan root)
    files: int = 0
    matches: list[tuple[Match, str, _Snippet]] = field(default_factory=list)  # match, relpath, snippet
    example_credentials: list[tuple[Match, str, str]] = field(default_factory=list)  # match, relpath, reason
    deps: list[Dep] = field(default_factory=list)
    languages: set[str] = field(default_factory=set)
    coding_agent_files: dict[str, list[str]] = field(default_factory=dict)  # sig id -> files
    coding_agent_matches: dict[str, list[tuple[Match, str, _Snippet]]] = field(default_factory=dict)
    instruction_hits: dict[str, list[ContentHit]] = field(default_factory=dict)
    skill_audits: dict[str, InstructionAudit] = field(default_factory=dict)
    agent_defs: list[dict[str, Any]] = field(default_factory=list)
    seen: set[tuple[str, int, str, str, int | None]] = field(default_factory=set)
    mcp_tools: dict[str, str] = field(default_factory=dict)  # registered MCP tool name -> relpath
    detection_rules: dict[str, int] = field(default_factory=dict)  # rule-pack format -> files
    detection_rule_files: list[str] = field(default_factory=list)  # the first, in walk order
    # Data files that declare what a deployment or a job runs with: never catalogs.
    configuration_files: set[str] = field(default_factory=set)
    # Data files the project's code, notebooks and shell scripts load by name: never catalogs.
    referenced_data_files: set[str] = field(default_factory=set)
    # Loader files whose reference list was truncated, with the limit messages:
    # a coverage gap only if the project discounts a data file (see _emit_project).
    reference_limits: list[tuple[str, list[str]]] = field(default_factory=list)
    mcp_tools_limited: bool = False
    # MCP server constructions (file, line, construct, language, bound), in walk order.
    mcp_server_constructions: list[dict[str, Any]] = field(default_factory=list)
    mcp_server_constructions_limited: bool = False
    # Coding-agent signature id -> posture issues read from its settings files.
    posture: dict[str, list[dict[str, str]]] = field(default_factory=dict)
    # Coding-agent signature id -> settings that make a person approve actions.
    approvals: dict[str, list[dict[str, str]]] = field(default_factory=dict)


@dataclass
class _SourceFile:
    """One file under analysis and the state its analysis passes share."""

    rel: str
    path: Path
    proj_root: str
    proj: _Project
    text: str  # analyzed text; a notebook's code cells
    lang: str | None
    file_matches: list[Match]
    nul_text: str | None = None  # the text as read, when its NUL bytes were removed from ``text``
    raw_notebook: str | None = None  # a notebook's raw document, scanned for credentials
    # Credential context for excerpt redaction (see _structured_context).
    # None withholds every excerpt of the file.
    structure: Any = None
    structure_strict: bool = False  # the structure is the strict-JSON parse of the text
    # The text and context excerpts are cut from; created with the file (see _ExcerptSource).
    excerpts: _ExcerptSource = field(default_factory=lambda: _ExcerptSource("", Path(), None, None))
    literals: LiteralScan | None = None  # the signature literals found in ``text``, scanned once
    card_kind: str | None = None  # agent manifest kind suggested by the path
    card_valid: bool = False
    card_incomplete: bool = False  # a recognizable card that misses required declarations
    is_mcp: bool = False
    mcp_servers: list[dict[str, Any]] = field(default_factory=list)
    mcp_active: bool = False  # at least one MCP server is configured, enabled or declared disabled
    cells: _CellSpans = ()  # a notebook's code cells, which Jupyter runs one at a time
    # Notebook cells declared another language (a non-Python kernel or cell magic): bound when
    # they parse as Python; when they do not, lexical evidence only, and not a coverage gap.
    foreign: _CellSpans = ()
    unparsed: _CellSpans = ()  # syntax the import binder could not read; lexical evidence only
    source_agent_regions: list[tuple[int, int, str]] = field(default_factory=list)
    reexport_pending: bool = False  # queued for re-export analysis after the walk
    # Tool regions a project-level construction, registration or dispatch path may also reach.
    project_tool_regions: list[tuple[int, int]] = field(default_factory=list)

    @property
    def name(self) -> str:
        # The path a client reads: an agent-configuration link is read at its own name.
        return PurePosixPath(self.rel).name

    @property
    def ext(self) -> str:
        return PurePosixPath(self.rel).suffix.lower()


@dataclass
class _MatchedSource:
    """A source file's lexical evidence, awaiting its import-bound analysis.

    The imports are already recorded; the code patterns are recorded with the
    binder's result, whose evidence replaces their lexical matches.
    """

    file: _SourceFile
    text: str  # the analyzed content text
    ignored: list[tuple[int, int]]
    is_local_module: Callable[[str], bool]
    imports: list[Match]
    code_matches: list[Match]


# A signature's source names its pack file (as the validator's namespace check reads it).
_BUNDLED_PACKS = os.path.join(os.path.abspath(builtin_signature_dir()), "")


def _bundled_signature(signature: Signature) -> bool:
    """Whether ``signature`` comes from the packs that ship with the scanner, not a custom pack."""
    return signature.source is not None and signature.source.startswith(_BUNDLED_PACKS)


def _on_disk_project(root: Path, path: Path, proj_root: str) -> Path:
    """The project directory of ``path`` under its on-disk name; ``proj_root`` is the report-safe form.

    A file read at a link path (``TreeWalker._alias_entries``) is ``path`` on disk but
    belongs to the link's project, which ``path`` need not lie in: its own directory
    stands in, so no unrelated ancestor of it is probed for local modules.
    """
    parts = path.relative_to(root).parts
    depth = len(PurePosixPath(proj_root).parts)
    if depth >= len(parts) or PurePosixPath(*parts[:depth]) != PurePosixPath(proj_root):
        return path.parent
    return root.joinpath(*parts[:depth])


def _local_module_predicate(root: Path, path: Path, proj_root: str) -> Callable[[str], bool]:
    """Return a cached check whether an import in ``path`` names a module of the scanned tree."""
    local_modules: dict[str, bool] = {}

    def is_local_module(module: str) -> bool:
        # Resolve only within the supplied directory scope.
        # A standalone file has no sibling/module inventory.
        if root.is_file():
            return False
        name = module.split(".", 1)[0]
        if name not in local_modules:
            local_modules[name] = local_module_conflict(
                module,
                scan_root=root,
                source_path=path,
                project_root=root if proj_root == "." else _on_disk_project(root, path, proj_root),
            )
        return local_modules[name]

    return is_local_module


class FindingBase(Protocol):
    """The connector's finding constructor (``FilesystemConnector._base``)."""

    def __call__(
        self,
        label: str,
        root: Path,
        rel: str,
        kind: Kind,
        title: str,
        resource_type: str,
        *,
        identity_discriminator: str = "",
    ) -> Finding: ...


# Tool credential files whose whole purpose is to hold a token or password:
# package-registry, HTTP and cloud client configuration that a repository or
# a home-directory checkout can commit by mistake. They have no suffix (or a
# leading dot only), so the suffix rules below never select them; the
# credential pass is what reads them.
CREDENTIAL_FILE_NAMES = frozenset(
    {
        ".npmrc",  # npm: //registry/:_authToken=...
        ".yarnrc",  # Yarn 1: registry tokens
        ".netrc",  # curl, pip, git: machine/login/password
        "_netrc",  # the same on Windows
        ".pypirc",  # twine: repository password or token
        ".git-credentials",  # git credential store: one URL per line with its user and token
        ".boto",  # legacy boto: aws_access_key_id / aws_secret_access_key
        ".s3cfg",  # s3cmd: access_key / secret_key
    }
)


# The incomplete-reason categories of the reasons ``read_text`` and
# ``read_credential_text`` give for not reading a file. Any other reason is
# classified from its own fixed text, never from the file's path.
_READ_ISSUE_REASONS = {
    "file exceeds max_file_size": "oversize-file",
    BINARY_CONTENT_ERROR: "unparsed-input",
    "not a regular file": "unscanned-input",
}


def _read_issue_reason(issue: str) -> str:
    """The ``INCOMPLETE_REASONS`` category of a read failure the reader described as ``issue``."""
    return _READ_ISSUE_REASONS.get(issue) or incomplete_reason(issue)


# Words that make an env file's name a template's (.env.example, .env.sample,
# config/.env.template, .env.dist): its values are samples to replace.
_ENV_TEMPLATE_WORDS = frozenset({"example", "sample", "template", "tmpl", "dist", "default", "defaults"})


def _env_values_file(name: str) -> bool:
    """Whether a file holds environment or tool credential values themselves, not a template of them.

    A ``.env`` file (``.env``, ``.env.local``, ``prod.env``) other than a
    template, or a tool credential file (``CREDENTIAL_FILE_NAMES``). Only
    there is a PASSWORD value never the name of another setting.
    """
    lower = name.lower()
    if lower in CREDENTIAL_FILE_NAMES:
        return True
    if not (lower.startswith(".env") or lower.endswith(".env")):
        return False
    return _ENV_TEMPLATE_WORDS.isdisjoint(re.split(r"[._-]", lower))


def _escaped_key(key: str) -> str:
    """A pattern for ``key`` with any of its characters written as a JSON or TOML ``\\u`` escape."""
    parts = []
    for character in key:
        digits = "".join(f"[{d.lower()}{d.upper()}]" if d.isalpha() else d for d in f"{ord(character):02x}")
        parts.append(f"(?:{re.escape(character)}|\\\\(?:u00|U000000){digits})")
    return "".join(parts)


_TABLE_KEYS = f"(?:{_escaped_key('mcpServers')}|{_escaped_key('mcp_servers')})"


# A key, not text: an unescaped double quote opens it (inside a JSON string every
# quote is escaped) and a colon follows its closing quote.
_JSON_TABLE_KEY = re.compile(rf'(?<!\\)"{_TABLE_KEYS}"\s*:')


_JSON_MCP_KEY = re.compile(rf'(?<!\\)"{_escaped_key("mcp")}"\s*:')


_JSON_SERVERS_KEY = re.compile(rf'(?<!\\)"{_escaped_key("servers")}"\s*:')


# A TOML key at the start of a line or after an inline table's brace or comma: a
# table header (``[mcp_servers.e]``, ``[tool.mcp_servers]``), a dotted key
# (``mcp_servers.e.command =``) or an inline table (``mcp_servers = {``), bare or quoted.
_TOML_TABLE_KEY = re.compile(
    # A dotted prefix starts with a key character, so it cannot also take the
    # blanks before it: one way to read each line, linear in its length.
    r"(?:^|[{,])[ \t]*(?:\[\[?[ \t]*)?(?:[^\n=#\[\]{},\s][^\n=#\[\]{},]*\.[ \t]*)?"
    rf"[\"']?{_TABLE_KEYS}[\"']?[ \t]*[.=\]]",
    re.MULTILINE,
)


_YAML_SCAN_LOADER: Any = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


def _yaml_names_mcp_key(text: str) -> bool:
    """Whether a YAML mapping key in ``text`` names a server table, however the key is quoted or escaped.

    Read from the scanner's tokens, which undo quoting and escapes as the
    loader does, so a key is told from text in a string value (a heredoc, an
    OpenAPI description quoting a client's configuration). Text the scanner
    cannot read is taken to name one.
    """
    keys: set[str] = set()
    key = False
    try:
        for token in yaml.scan(text, Loader=_YAML_SCAN_LOADER):
            if key and isinstance(token, yaml.ScalarToken):
                if token.value in ("mcpServers", "mcp_servers"):
                    return True
                keys.add(token.value)
            key = isinstance(token, yaml.KeyToken)
    except yaml.YAMLError:
        return True
    return {"mcp", "servers"} <= keys


def _names_mcp_key(rel: str, text: str) -> bool:
    """Whether ``text`` spells a server table key as a key, not as text in a string value.

    The check of a document whose parse the walk's bounds cut
    (``mcp_server_holders``): a JSON key opened by an unescaped quote and
    followed by a colon, a YAML mapping key (``_yaml_names_mcp_key``), a TOML
    key, any of them with its characters written as escapes. A key past the
    bounds keeps the file MCP configuration, so its unread table is recorded;
    an issue export or an OpenAPI document that quotes a client's
    configuration in a string is not.
    """
    if rel.endswith(_YAML_SUFFIXES):
        return _yaml_names_mcp_key(text)
    if rel.endswith(".toml"):
        return _TOML_TABLE_KEY.search(text) is not None
    return _JSON_TABLE_KEY.search(text) is not None or (
        _JSON_MCP_KEY.search(text) is not None and _JSON_SERVERS_KEY.search(text) is not None
    )


@dataclass(frozen=True)
class _UndecodableFile:
    """A binary or undecodable file whose gap is discounted or declared, read for credentials only.

    ``on_disk`` is its name below the open scan root, as ``_read_source`` read it.
    """

    on_disk: PurePosixPath
