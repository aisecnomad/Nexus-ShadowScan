"""Scan a local directory tree (a checked-out repository, a monorepo, a laptop).

Produces:

* one ``agent`` / ``framework-usage`` finding per project (nearest manifest
  root) summarising frameworks, model providers, capabilities and evidence;
  opt-in ``agent_granularity: source`` separately inventories unique named
  Python constructions and their local registered-tool evidence;
* one ``mcp-server`` finding per MCP client/server configuration file;
* one ``agent-config`` finding per coding-agent product per project
  (Claude Code, Copilot, Cursor, Codex... including sub-agent definitions);
* one ``agent`` finding per A2A agent card / declarative agent manifest;
* one ``workflow`` finding per exported low-code flow (n8n, Flowise, Langflow,
  Dify, Make, Power Automate, Logic Apps);
* one ``infra`` finding per IaC / container file provisioning agent platforms;
* one ``secret`` finding per file containing LLM-provider credentials (redacted).

Precision safeguards
--------------------
* A credential whose value looks like a documentation placeholder (see
  ``shadowscan.connectors.common.placeholder_reason``) never becomes a
  ``secret`` finding. It is attached to the project finding as low-weight
  ``example-credential`` evidence (tag ``example-credential``) so analysts
  still see that a sample key exists, without a high-risk alert.
* A credential alone does not establish LLM usage: secret matches only join
  the project finding when the project has another technology observation.
* Vendor-neutral heuristics (agent loops, autonomy flags, shell execution)
  only count when the project also matches a framework, provider, platform,
  protocol or cloud-service signature; on their own they describe ordinary
  automation code and are dropped.
* When every technology observation other than those heuristics is an
  environment-variable or display-name reference, the heuristics are dropped
  and the finding is built from the name references alone: evidence weights
  are halved, the finding is tagged ``env-names-only`` and confidence is
  capped below the ``strong`` band.
* A detection-rule pack (a ShadowScan signature pack, Semgrep or Sigma rules,
  a gitleaks configuration; see ``rule_packs``) lists the names and hosts it
  detects. Its content is never usage or configuration evidence; the project
  finding lists such files under ``detection_rule_files``. File-name signals
  and credentials in them are still reported.
* A data or prose file that only lists products (a blocklist, a vendor
  policy, a copy of the signature packs: four or more products by domain or
  variable name, no import, dependency, code or other structural evidence) is
  a catalog. Its mentions count only for a signature with library evidence
  elsewhere in the project (``shadowscan.connectors.code.catalogs``).
* A lexical code pattern (no import binder for the language, or a framework
  pattern the binder did not claim) whose signature has no import, dependency,
  file, image, IaC, model, bound-call, configuration or strong-mention
  evidence in the project, and a signature known only from mentions below
  ``WEAK_MENTION_WEIGHT``, are kept as evidence but establish nothing: they
  are listed under ``metadata.potential_frameworks`` /
  ``metadata.potential_providers`` and anchor no finding
  (``_uncorroborated_signatures``, ``_weak_mention_signatures``).
* Model identifiers found as literals are medium-weight evidence (at most
  0.5 each, ``_scan_model_literals``); a project known only from them is
  tagged ``model-ids-only`` and capped at 0.6, and a model id in a data file
  is a mention. A mention in a test path and a CI job image anchor nothing.
  A project dropped for any of these reasons is named in a scan note.
"""

from __future__ import annotations

# Every name importable from this module before its helpers moved into
# path_context, project_evidence, model_identifiers, source_text and excerpts
# (ADR-005) stays importable: the imports marked `noqa: F401 - re-exported`
# carry names this module does not use itself. Patch such a name in its
# defining module; rebinding it here does not change what the helpers use.
import ast  # noqa: F401 - re-exported
import errno
import fnmatch
import hashlib
import os
import re
import stat
import time
import tomllib  # noqa: F401 - re-exported
from bisect import bisect_right
from collections.abc import Callable, Iterable, Iterator, Sequence
from collections.abc import Set as AbstractSet
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath
from typing import Any, ClassVar

import regex
import yaml

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError, _positive_limit
from shadowscan.connectors.code.catalogs import (  # noqa: F401 - re-exported
    _PIPELINE_DIRECTORIES,
    _PIPELINE_NAMES,
    CATALOG_MIN_SIGNATURES,
    LOADER_EXTENSIONS,
    HostLineFilter,
    catalog_metadata,
    configuration_document,
    deny_list_file,
    project_catalog_files,
    referenced_data_files,
    references_could_change,
)
from shadowscan.connectors.code.dotnet_semantics import microsoft_tool_loop_matches
from shadowscan.connectors.code.excerpts import _excerpt, _ExcerptSource, _LazyExcerpt, _Snippet
from shadowscan.connectors.code.go_semantics import langchaingo_agent_matches
from shadowscan.connectors.code.import_provenance import local_module_conflict
from shadowscan.connectors.code.instruction_content import (
    MAX_TEXT_BYTES as MAX_INSTRUCTION_TEXT_BYTES,
)
from shadowscan.connectors.code.instruction_content import (
    ContentHit,
    inspect_instruction_text,
)
from shadowscan.connectors.code.java_semantics import spring_tool_registration_matches
from shadowscan.connectors.code.lockfiles import LOCKFILE_NAMES, LockInventory
from shadowscan.connectors.code.manifests import (
    Artifact,
    Dep,
    _pattern_timeout,
    is_manifest_name,
    manifest_comment_projection,
    parse_manifest,
)
from shadowscan.connectors.code.mcp_config import _mcp_client_for, _parse_mcp_servers
from shadowscan.connectors.code.mcp_tools import MCPToolLimitError, mcp_tool_capabilities, mcp_tool_names
from shadowscan.connectors.code.model_artifacts import (
    ARTIFACT_SUFFIXES,
    ArtifactBudgetExhausted,
    inspect_artifact,
)
from shadowscan.connectors.code.model_identifiers import (  # noqa: F401 - re-exported
    _MODEL_FAMILY_SHAPES,
    _MODEL_FILE_NAME_RE,
    _MODEL_KEY_VALUE_RE,
    _MODEL_LITERAL_CONFIG_EXTENSIONS,
    _MODEL_QUOTED_RE,
    _MODEL_ROUTE_PREFIXES,
    _MODEL_SEGMENT_RE,
    _MODEL_STEM_RE,
    _MODEL_STEMS,
    _MODEL_TOOLING_NAMES,
    _MODEL_TOOLING_SEGMENTS,
    MAX_MODEL_LITERALS_PER_FILE,
    MAX_MODEL_MATCHES_PER_SIGNATURE,
    MODEL_IDS_ONLY_MAX_CONFIDENCE,
    MODEL_LITERAL_MAX_WEIGHT,
    _has_model_stem,
    _model_lookalike,
)
from shadowscan.connectors.code.ownership import (  # noqa: F401 - re-exported
    _MAX_GIT_AUTHOR_CHARS,
    _MAX_GIT_EMAIL_CHARS,
    _MAX_GIT_TIMESTAMP_CHARS,
    MAX_OWNERSHIP_STEPS,
    MAX_PATTERN_LENGTH,
    MAX_ROOT_OWNERSHIP_STEPS,
    MAX_RULES,
    OwnershipBudget,
    OwnershipLimitError,
    OwnershipResolver,
)
from shadowscan.connectors.code.ownership import (  # noqa: F401 - re-exported
    codeowners_match as _codeowners_match,
)
from shadowscan.connectors.code.path_context import (  # noqa: F401 - re-exported
    _DOCS_DIR_NAMES,
    _EXAMPLE_DIR_NAMES,
    _GENERATED_FILE_RE,
    _TEST_DIR_NAMES,
    _TEST_FILE_RE,
    DOCS_MAX_CONFIDENCE,
    DOCS_WEIGHT_SCALE,
    EXAMPLE_PATH_MAX_CONFIDENCE,
    EXAMPLE_PATH_WEIGHT_SCALE,
    GENERATED_MAX_CONFIDENCE,
    GENERATED_WEIGHT_SCALE,
    NEGATIVE_CONTEXT_TAGS,
    NegativeContext,
    _is_docs_path,
    _is_example_path,
    _is_generated_path,
    _is_pipeline_file,
    _is_test_path,
    negative_context,
)
from shadowscan.connectors.code.project_evidence import (  # noqa: F401 - re-exported
    _CORROBORATING_SIGNALS,
    _MENTION_SIGNAL_TYPES,
    ENV_ONLY_MAX_CONFIDENCE,
    ENV_ONLY_WEIGHT_SCALE,
    WEAK_MENTION_WEIGHT,
    _corroborates,
    _mention,
    _Observation,
    _ProjectEvidence,
    _uncorroborated_signatures,
    _weak_mention_signatures,
)
from shadowscan.connectors.code.python_reexports import (
    MAX_PENDING_BYTES,
    MAX_PENDING_FILES,
    ImportResolver,
    PythonReexports,
    ReexportLimitError,
    has_local_import,
    project_path,
)
from shadowscan.connectors.code.rule_packs import detection_rule_format
from shadowscan.connectors.code.semantic_config import (  # noqa: F401 - re-exported
    a2a_card_metadata,
    a2a_card_tags,
    a2a_unsupported_protocol_version,
    agent_manifest_kind,
    has_template_markers,
    is_agent_config_path,
    parse_agent_manifest,
    structured_code_matches,
)
from shadowscan.connectors.code.semantic_config import bounded_metadata as _clip
from shadowscan.connectors.code.skill_audit import InstructionAudit, audit_skill_text
from shadowscan.connectors.code.source_identity import named_construction_spans
from shadowscan.connectors.code.source_ranges import noncode_ranges, nul_reading_ranges
from shadowscan.connectors.code.source_semantics import (
    MAX_CALL_TEXT,
    SourceBudgetExceeded,
    SourceNotParsed,
    bound_source_matches,
)
from shadowscan.connectors.code.source_text import (  # noqa: F401 - re-exported
    _COMMENT_OPENERS,
    _COMMENT_START,
    _CRAWLER_UA_MARK,
    _FRONTMATTER,
    _GLOB_KEYS,
    _IPYTHON_LINE,
    _JSON_SUFFIXES,
    _LINE_BREAK,
    _NO_STRUCTURE,
    _QUOTE_START,
    _QUOTED_VALUE,
    _YAML_SUFFIXES,
    _cell_noncode_ranges,
    _CellSpans,
    _comment_spans,
    _crawler_ua_text,
    _notebook_binder_source,
    _quote_glob_values,
    _quote_plain_values,
    _quoted_values,
    _redacted_source,
    _strip_comment,
    _structured_context,
    _within,
    _without_ipython_lines,
    _without_source_ranges,
    _without_xml_comments,
    foreign_cell,
)
from shadowscan.connectors.code.tool_attribution import ToolRegions
from shadowscan.connectors.code.walk import (
    DEFAULT_MAX_WALK_ENTRIES,
    _holds_file,
    _marks_project,
    _nearest_root,
    _project_root,
    _report_name,
    _walk_directories,
    _WalkBudget,
    _WalkCounters,
    _WalkLimitError,
)
from shadowscan.connectors.common import (
    apply_matches,
    cap_confidence,
    config_boolean,
    finalize,
    looks_like_placeholder,
    placeholder_reason,
)
from shadowscan.connectors.mcp_risk import record_server_risks
from shadowscan.connectors.posture import (
    CLIENT_SIGNATURES,
    approval_scopes,
    approval_settings,
    canonical_settings_path,
    posture_client,
    record_approval,
    record_posture,
    unreadable_settings,
)
from shadowscan.connectors.posture import assess as assess_posture
from shadowscan.connectors.posture import parseable as posture_parseable
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.signatures import Match, Signature
from shadowscan.signatures.loader import builtin_signature_dir
from shadowscan.signatures.matcher import (
    SOURCE_EXTENSIONS,
    WALL_BUDGET_FACTOR,
    LiteralScan,
    MatchTimeoutError,
    _finditer,
    language_for_path,
)
from shadowscan.utils.files import open_confined_directory, read_policy_text
from shadowscan.utils.git import (
    LFS_POINTER_MAX_BYTES,
    LFS_POINTER_PREFIX,
    MAX_GITMODULES_BYTES,
    declared_submodule_paths,
    read_gitlink_paths,
)
from shadowscan.utils.jsonc import load_json_lenient as _load_json_lenient
from shadowscan.utils.jsonc import (
    load_json_lenient_marked as _load_json_lenient_marked,  # noqa: F401 - re-exported
)
from shadowscan.utils.jsonc import strip_json_comments as _strip_json_comments  # noqa: F401 - historical name
from shadowscan.utils.redaction import SanitizationLimitError, sanitize, sanitize_text
from shadowscan.utils.safe_json import JSONIntegrityError
from shadowscan.utils.safe_yaml import (
    YAMLIntegrityError,
    YAMLResourceLimitError,
    strict_bounded_safe_load,
)
from shadowscan.utils.text import (
    line_counter,
    notebook_to_source,
    read_text,
    redact,
    truncate,
)

# Manifests that configure the code of the project containing them. A2A cards
# and M365 declarative agents declare a separately addressable agent (its own
# name, endpoint and authentication) and stay findings of their own.
_PROJECT_MANIFESTS = frozenset({"crewai", "langgraph"})

# Registered MCP tool names retained per project.
_MAX_MCP_TOOLS = 200
# Server constructions listed under metadata.mcp_server; the capability does not
# depend on the list, so the bound is disclosed on the finding, not a coverage gap.
_MAX_MCP_SERVER_CONSTRUCTIONS = 50
# The transport an MCP server code match names (metadata.mcp_server.transports).
_MCP_TRANSPORTS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("stdio", re.compile(r"\b(?:stdio_server|StdioServerTransport)\s*\(")),
    ("http", re.compile(r"\b(?:StreamableHTTP\w*|SseServerTransport|SSEServerTransport)\s*\(")),
)
# Server idioms that register tools or run a server rather than construct one.
_MCP_REGISTRATION_RE = re.compile(
    r"\A@|\.(?:tool|registerTool|list_tools|call_tool|run)\s*\(|\A\[McpServerTool"
)
# An import of an MCP SDK's server module (Python or JavaScript). A lexical
# construction pattern in a file that binds no server class is server evidence
# only next to such an import; otherwise it may name a local class.
_MCP_SERVER_IMPORT_RE = re.compile(
    r"\bmcp\.server\b|\bfastmcp\b|@modelcontextprotocol/sdk/server\b|[\"']mcp-framework[\"']"
)
# Detection-rule pack paths listed in a project finding's metadata.
_MAX_LISTED_RULE_FILES = 20

# Signal types that establish a library in a project (see _emit_project).
_LIBRARY_SIGNALS = frozenset({"import", "dependency", "code"})
# Signals that name a product without configuring it.
_MENTION_SIGNALS = frozenset({"env", "name"})
# A container image that runs a CI job is a mention of that product at this
# share of the image signal's weight; a deployed image keeps full weight.
CI_IMAGE_WEIGHT_SCALE = 0.3

# Saved outputs (plots, tables, logs) routinely push small notebooks past
# max_file_size. Their code cells are still analyzed up to this size.
DEFAULT_MAX_NOTEBOOK_SIZE = 20 * 1024 * 1024

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
# Artifact metadata bytes (inspect_model_artifacts) read per scanned root, and
# bytes read only to skip GGUF array values (vocabularies) per scanned root.
_ARTIFACT_SCAN_BYTES = 32 * 1024 * 1024
_ARTIFACT_SKIP_BYTES = 256 * 1024 * 1024

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
# Coverage profiles: ``default`` fails closed on every gap; ``ci`` declares the
# gaps a source gate accepts in advance (see ``FilesystemConnector._declared_omission``).
PROFILES: tuple[str, ...] = ("default", "ci")
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
# A name no real file can have (a path component cannot contain NUL), so only
# a wildcard glob segment such as ``**`` matches it.
_ANY_FILE_NAME = "\x00"
# The first line of a Git LFS pointer file (at most LFS_POINTER_MAX_BYTES long).
_LFS_POINTER_TEXT = LFS_POINTER_PREFIX.decode("ascii")


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


# Files that may be manifests whatever their name: IaC, compose, CI and deployment templates.
_MANIFEST_EXTENSIONS = frozenset({".tf", ".bicep", ".yml", ".yaml", ".json", ".hcl"})
# XML-based files whose comments are masked before content matching.
_XML_EXTENSIONS = frozenset({".xml", ".props", ".targets", ".csproj", ".fsproj", ".vbproj"})
# Structured files whose platform matches can describe an exported workflow.
_WORKFLOW_EXTENSIONS = frozenset({".json", ".yaml", ".yml"})
# Coding-agent sub-agent and rule definitions (Markdown with YAML front matter).
_AGENT_DEFINITION_DIRS = (".claude/agents/", ".github/agents/", ".cursor/rules/", ".windsurf/rules/")

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


def _document_declares_mcp(document: dict[str, Any], depth: int = 0) -> bool:
    """Whether a parsed JSON/TOML object configures MCP servers, wherever the table sits.

    Decided from the structure, not a text prefix: a key named ``mcpServers`` or
    ``mcp_servers`` holding a mapping, or an ``mcp`` mapping with a ``servers`` mapping,
    at the top level or nested within a client's section. Bounded in depth and breadth so
    a hostile document cannot make the walk expensive.
    """
    if depth > 6:
        return False
    # The key's presence is the signal, whatever its value: a malformed value (``mcpServers:
    # "x"``) must still route to the server parser, which records the input defect, exactly as
    # the former substring check did — only now it cannot be hidden behind leading padding.
    if "mcpServers" in document or "mcp_servers" in document:
        return True
    mcp = document.get("mcp")
    if isinstance(mcp, dict) and "servers" in mcp:
        return True
    for value in list(document.values())[:256]:
        if isinstance(value, dict) and _document_declares_mcp(value, depth + 1):
            return True
    return False


# Documentation placeholders are informational: enough to be listed, never
# enough to establish a technology or raise risk.
EXAMPLE_CREDENTIAL_WEIGHT = 0.1
MAX_EXAMPLE_CREDENTIAL_EVIDENCE = 20
# Capability implied by an MCP server's launch command; the first matching
# group wins, so a database server launched through docker keeps code-exec.
_MCP_CAPABILITY_KEYWORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("code-exec", ("shell", "bash", "terminal", "exec", "docker", "kubectl", "ssh")),
    ("data-access", ("filesystem", "sqlite", "postgres", "mysql", "mongodb")),
    ("browsing", ("puppeteer", "playwright", "browser")),
    ("saas-actions", ("github", "gitlab", "slack", "gmail", "google-drive", "aws", "gcloud", "azure")),
)


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
class _ScanState:
    """What one ``scan_tree`` walk collects for its emit phase."""

    root: Path
    label: str  # resource prefix of every finding
    # Descriptor files are read relative to, open through both the walk and ownership emission.
    root_fd: int = -1
    base: Path | None = None  # that directory (the scan root, or a single-file root's parent)
    projects: dict[str, _Project] = field(default_factory=lambda: {".": _Project(".")})
    inventory_findings: list[Finding] = field(default_factory=list)
    artifact_bytes_remaining: int = field(default_factory=lambda: _ARTIFACT_SCAN_BYTES)
    artifact_skip_bytes_remaining: int = field(default_factory=lambda: _ARTIFACT_SKIP_BYTES)
    # Selected files the exhausted artifact budget left uninspected.
    artifacts_uninspected: int = 0
    secret_hits: dict[str, list[tuple[Match, str]]] = field(default_factory=dict)  # relpath -> matches
    secret_project: dict[str, str] = field(default_factory=dict)  # relpath -> project root
    # relpath, parsed servers
    mcp_files: list[tuple[str, list[dict[str, Any]]]] = field(default_factory=list)
    # relpath, text, kind, project root
    card_files: list[tuple[str, str, str, str]] = field(default_factory=list)
    workflow_files: dict[str, list[tuple[Match, str]]] = field(default_factory=dict)
    # relpath -> model nodes in exported workflows
    workflow_providers: dict[str, list[tuple[Match, str]]] = field(default_factory=dict)
    # relpath -> (match, value, snippet)
    infra_files: dict[str, list[tuple[Match, str, str]]] = field(default_factory=dict)
    infra_names: dict[str, list[str]] = field(default_factory=dict)  # relpath -> display / resource names
    infra_project: dict[str, str] = field(default_factory=dict)  # relpath -> project root
    infra_models: dict[str, list[Match]] = field(default_factory=dict)  # relpath -> model ids declared in IaC
    # project root -> (relpath, line, excerpt)
    iam_wildcards: dict[str, list[tuple[str, int, str]]] = field(default_factory=dict)
    diff_files: frozenset[str] | None = None  # when set, only these changed files + context files are scanned
    diff_base_ref: str | None = None  # the ref that was diffed against
    reexports: PythonReexports = field(default_factory=PythonReexports)
    reexport_files: list[_MatchedSource] = field(default_factory=list)
    reexport_bytes: int = 0
    # The walk's safety margin before the connector deadline, kept by the
    # pass that analyzes the queued re-export consumers after it.
    margin: float = 0.0

    def covered_files(self) -> frozenset[str]:
        """Files whose own MCP, manifest, workflow or IaC finding reports their evidence."""
        return frozenset(
            {rel for rel, _ in self.mcp_files}
            | {rel for rel, _, _, _ in self.card_files}
            | set(self.workflow_files)
            | set(self.infra_files)
        )


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
        return self.path.name

    @property
    def ext(self) -> str:
        return self.path.suffix.lower()


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


_ROOT_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}\Z")
# The ":<line>" suffix of an evidence location.
_LOCATION_LINE = re.compile(r":\d+\Z")

# Categories whose evidence shows that a file itself talks to a model.
_LLM_CATEGORIES = frozenset({"provider", "framework", "protocol", "platform", "cloud-service"})
# Signatures that are only meaningful when the same file also invokes an LLM.
_COLOCATED_SIGNATURES = frozenset({"heuristic.llm-command-execution"})
# IAM statements granting every action (Terraform, CloudFormation, ARM/Bicep JSON).
# Whitespace runs are matched possessively: ``\s*\[?\s*`` backtracks
# quadratically over a long run of blank space after ``Action:``, and the
# stdlib engine cannot be interrupted. The bounded engine applies the
# per-input matching budget where the pattern runs (_scan_iac).
_IAM_WILDCARD_RE = regex.compile(
    r"""(?i)["']?\bActions?["']?\s*+[:=]\s*+(?:\[\s*+)?["']\*["']"""
    r"""|["'](?:bedrock|iam|sts|lambda|s3|secretsmanager|kms):\*["']"""
)
_IAC_MODEL_RE = re.compile(
    r"""(?i)\b(?:foundation_?model(?:_?(?:id|arn))?|model_?id|model_?name|model)\b"""
    r"""["']?\s*[:=]\s*["']([A-Za-z0-9][A-Za-z0-9._:/@-]{2,199})["']"""
)
_IAC_EXTENSIONS = frozenset({".tf", ".hcl", ".bicep", ".json", ".yaml", ".yml"})


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


# A signature's source names its pack file (as the validator's namespace check reads it).
_BUNDLED_PACKS = os.path.join(os.path.abspath(builtin_signature_dir()), "")


def _bundled_signature(signature: Signature) -> bool:
    """Whether ``signature`` comes from the packs that ship with the scanner, not a custom pack."""
    return signature.source is not None and signature.source.startswith(_BUNDLED_PACKS)


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


def _on_disk_project(root: Path, path: Path, proj_root: str) -> Path:
    """The project directory of ``path`` under its on-disk name; ``proj_root`` is the report-safe form."""
    return root.joinpath(*path.relative_to(root).parts[: len(PurePosixPath(proj_root).parts)])


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


def _validated_include(value: Any) -> frozenset[str]:
    """``include``: relative posix paths below a root, normalized; nothing may escape or be absolute."""
    out: set[str] = set()
    for item in _validated_names(value, "include"):
        normalized = item.replace("\\", "/").strip().strip("/")
        while normalized.startswith("./"):
            normalized = normalized[2:]
        parts = [part for part in normalized.split("/") if part not in ("", ".")]
        if not parts or ".." in parts or item.startswith(("/", "\\")) or (len(item) > 1 and item[1] == ":"):
            raise ConnectorError("code.filesystem: include entries must be relative paths below the root")
        out.add("/".join(parts))
    return frozenset(out)


def _validated_names(value: Any, key: str) -> list[str]:
    """A list-typed option: a list of non-empty strings, or unset.

    A bare string must not pass: iterated per character, ``exclude: "vendor/*"``
    would become the patterns ``/`` and ``*`` and exclude the whole tree. The
    message names the option, never its value.
    """
    if value is None:
        return []
    if not isinstance(value, (list, tuple)) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise ConnectorError(f"code.filesystem: {key} must be a list of non-empty strings")
    return list(value)


def _validated_globs(value: Any) -> list[str]:
    if not isinstance(value, (list, tuple)) or not all(isinstance(g, str) and g.strip() for g in value):
        raise ConnectorError("code.filesystem: oversize_skip_globs must be a list of file name globs")
    return [g.strip().lower() for g in value]


def _checked_scan_root(path: str | Path) -> Path:
    """Reject symlinked roots and ancestors before resolving a scan input.

    Keep ``..`` components while checking so ``link/..`` cannot conceal a
    symlink in the path supplied by the caller. The walk then opens this root
    once and reads every file relative to it without following a link in any
    component (``FilesystemConnector._walk``), so a directory concurrently
    replaced by a link fails its reads instead of redirecting them outside the
    tree. Findings still describe one consistent state only when the checkout
    does not change during the scan.
    """
    try:
        raw = Path(path).expanduser().absolute()
        if any(part.is_symlink() for part in (raw, *raw.parents)):
            raise ConnectorError("code.filesystem: scan root must not traverse a symbolic link")
        root = raw.resolve()
        if root != Path(os.path.abspath(raw)):
            raise ConnectorError("code.filesystem: scan root changed while being validated")
        return root
    except ConnectorError:
        raise
    except (OSError, RuntimeError) as exc:
        raise ConnectorError("code.filesystem: scan root could not be safely resolved") from exc


def validate_distinct_paths(paths: Any) -> list[Path]:
    """Reject aliases that resolve to the same repository under one label."""
    if not isinstance(paths, list) or not paths or not all(isinstance(p, str) and p for p in paths):
        raise ConnectorError("code.filesystem: paths must be a nonempty list of paths")
    canonical = [_checked_scan_root(path) for path in paths]
    if len(set(canonical)) != len(canonical):
        raise ConnectorError("code.filesystem: labeled paths must resolve to distinct scan roots")
    return canonical


def validate_root_ids(paths: Any, root_ids: Any) -> list[str]:
    """Validate positional, stable IDs for a labeled ``paths`` connector."""
    validate_distinct_paths(paths)
    if not isinstance(root_ids, list) or len(root_ids) != len(paths):
        raise ConnectorError("code.filesystem: root_ids must contain exactly one ID per path")
    if not all(isinstance(root_id, str) and _ROOT_ID_RE.fullmatch(root_id) for root_id in root_ids):
        raise ConnectorError(
            "code.filesystem: root_ids must be 1-80 characters of letters, digits, '.', '_' or '-'"
        )
    if len(set(root_ids)) != len(root_ids):
        raise ConnectorError("code.filesystem: root_ids must be unique within paths")
    return root_ids


def _scan_timeout(value: Any) -> float:
    """The per-file matching budget in seconds: above 0, at most 60, never a boolean."""
    message = "code.filesystem: scan_timeout must be a number of seconds above 0 and at most 60"
    if isinstance(value, bool):
        raise ConnectorError(message)
    try:
        seconds = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ConnectorError(message) from exc
    if not 0 < seconds <= 60:  # also NaN
        raise ConnectorError(message)
    return seconds


class FilesystemConnector(BaseConnector):
    @classmethod
    def cache_roots_separately(cls, roots: list[Any], root_ids: Any, *, labelled: bool) -> bool:
        # Engine hook: each repository root is an independent incremental-cache unit.
        if labelled:
            validate_distinct_paths(roots)
        if root_ids is not None:
            validate_root_ids(roots, root_ids)
        return True

    @classmethod
    def scanned_local_paths(cls, config: dict[str, Any]) -> list[str]:
        # Engine hook: the configured paths are the scan subject, unless an export is replayed.
        if config.get("input"):
            return []
        raw = config.get("paths") or [config.get("path")]
        return [path for path in raw if isinstance(path, str) and path] if isinstance(raw, list) else []

    name: ClassVar[str] = "code.filesystem"
    surface: ClassVar[Surface] = Surface.CODE
    provider: ClassVar[str | None] = "filesystem"
    description: ClassVar[str] = (
        "Scan a local directory / repository checkout for agent frameworks, MCP, coding agents, IaC "
        "and secrets."
    )
    config_keys: ClassVar[dict[str, str]] = {
        "path": "directory to scan (or `paths`: list)",
        "paths": "list of directories to scan instead of `path`; each root keeps its own identity",
        "exclude": "list of extra directory names / glob patterns to skip (a bare string is rejected)",
        "include": (
            "list of paths relative to each root that limit the walk to those files and directories; "
            "other file contents are not read; parent directory names are listed; such a scan always "
            "runs in full, without the incremental cache (endpoint scans use it; default: everything)"
        ),
        "default_excludes": (
            "skip the built-in directory names (VCS metadata, caches, virtualenvs, dependency trees, IDE "
            "state, and build-output or vendored names such as bin, build, dist, vendor) at any depth "
            "(default true); a skipped non-empty bin/build/dist/out/target/obj/coverage/vendor/"
            "third_party/thirdparty/external directory is reported as a warning. false scans all of "
            "them, including node_modules and virtualenvs unless `exclude` names them; VCS metadata "
            "(.git, .hg, .svn) is never scanned"
        ),
        "max_file_size": (
            "bytes; an analyzable larger file is skipped with incomplete coverage unless oversize_skip_globs "
            "matches it or, with scan_secrets false, it is documentation (.md/.txt outside agent instruction "
            "files) or sits under a test path while include_tests is false: those are skipped with a "
            "warning (default 1,000,000 bytes)"
        ),
        "oversize_skip_globs": (
            "case-insensitive file name globs; a file over max_file_size matching one is skipped with a "
            "warning even under strict_coverage (default: lockfiles, logs, HAR and snapshot files, "
            "minified bundles, source maps, images, fonts, archives and compiled artifacts)"
        ),
        "max_files": "stop after this many files and symbolic links (default 100000)",
        "max_entries": (
            "stop after this many filesystem entries inspected during directory enumeration, including "
            "directories, skipped entries and coverage probes (default 1000000); exhaustion is incomplete"
        ),
        "max_notebook_size": (
            "bytes; a Jupyter notebook up to this size is read with its code cells analyzed as source even "
            "when saved outputs make the file larger than max_file_size (default 20 MiB); outputs of such a "
            "notebook are not scanned for credentials"
        ),
        "max_ast_nodes": (
            "Python syntax-tree nodes analyzed per file for import-bound evidence (default 50000); a larger "
            "file keeps its lexical evidence and is reported as partially analyzed: a warning under test "
            "paths, an error elsewhere"
        ),
        "scan_timeout": (
            "matching budget in CPU seconds per file up to 256 KiB (default 2); one more budget per further "
            "256 KiB, capped at 10 seconds or scan_timeout when higher; elapsed time ends a file at four "
            "times the budget"
        ),
        "scan_secrets": "detect provider credentials (default true)",
        "inspect_model_artifacts": (
            "opt in to bounded GGUF/safetensors/ONNX header and PyInstaller footer inventory; "
            "never executes or loads tensor payloads (default false)"
        ),
        "model_metadata_bytes": (
            "maximum bytes read per selected binary/model artifact (128..1048576; default 65536)"
        ),
        "use_git": (
            "opt in to offline git author/date enrichment for trusted metadata; requires Git 2.45+ "
            "(default false)"
        ),
        "strict_coverage": (
            "report coverage gaps (unread analyzable oversize files, non-regular entries named like "
            "configuration files, symbolic links whose alias path is not covered) as errors instead of "
            "warnings; either way the scan is incomplete (default false)"
        ),
        "include_tests": (
            "let test and fixture code establish agents and credential findings at full weight "
            "(default false)"
        ),
        "profile": (
            "default | ci; ci declares as omissions, with a warning that leaves the scan complete, the "
            "coverage gaps a source gate accepts in advance: oversize files, unread symbolic links, "
            "non-regular entries, unparsed content and analysis limits under test, fixture, documentation, "
            "example and generated paths (test paths only while include_tests is false); every other gap "
            "still marks the scan incomplete, and the report counts the omissions (default: default)"
        ),
        "triage": (
            "fast subset scan: manifests, MCP and coding-agent configuration, flow exports and IaC "
            "only; source analysis, credential detection and content sweeps are skipped and the scan "
            "is always reported incomplete so a triage result is never mistaken for a full scan "
            "(default false)"
        ),
        "agent_granularity": (
            "project (default) | source; source additionally inventories unique named straight-line "
            "Python agent constructions by file and scoped binding; other source remains project evidence"
        ),
        "label": "prefix for resource ids (e.g. 'github:org/repo'); defaults to the path",
        "root_ids": "unique stable IDs aligned with paths, for resource identity across checkout moves",
        "account": "account label recorded on every finding (default none)",
        "owner": (
            "owner recorded on every finding; overrides CODEOWNERS and inventory attribution "
            "(default: CODEOWNERS, then git author when use_git, then inventory)"
        ),
        "provider": "provider label recorded on findings (default filesystem)",
        "metadata": "mapping merged into every finding's metadata",
        "diff_base": (
            "git ref to diff against (branch, tag, or SHA); only files committed between its merge-base and "
            "HEAD are scanned, plus dependency manifests and .env files for context. Uncommitted, untracked "
            "and submodule changes are not scanned. The report is not a repository inventory: `shadowscan "
            "diff` never resolves findings from it and --incremental never reuses it. Requires Git 2.45+ "
            "and a local .git directory; falls back to a full scan when the diff cannot be computed"
        ),
    }
    shared_config_keys: ClassVar[dict[str, str]] = {}  # scans a checkout, not an export file
    offline_formats: ClassVar[str] = "n/a (path is the input)"

    def __init__(self, ctx: ConnectorContext) -> None:
        super().__init__(ctx)
        # Booleans and fractions are errors, not limits: `max_file_size: true` was a
        # 1-byte limit that skipped every file and `max_files: 1.9` silently became 1.
        self.max_file_size = _positive_limit(
            ctx.get("max_file_size", 1_000_000), "code.filesystem: max_file_size"
        )
        self.max_files = _positive_limit(ctx.get("max_files", 100_000), "code.filesystem: max_files")
        self.max_entries = _positive_limit(
            ctx.get("max_entries", DEFAULT_MAX_WALK_ENTRIES), "code.filesystem: max_entries"
        )
        self.scan_timeout = _scan_timeout(ctx.get("scan_timeout", 2.0))
        # max_ast_nodes and max_notebook_size are validated below.
        self.max_ast_nodes: int | None = ctx.get("max_ast_nodes")
        self.max_notebook_size: int = ctx.get("max_notebook_size", DEFAULT_MAX_NOTEBOOK_SIZE)
        if type(self.max_notebook_size) is not int or self.max_notebook_size < 1:
            raise ConnectorError("code.filesystem: max_notebook_size must be a positive integer")
        if self.max_ast_nodes is not None and (
            type(self.max_ast_nodes) is not int or not 1_000 <= self.max_ast_nodes <= 2_000_000
        ):
            raise ConnectorError("code.filesystem: max_ast_nodes must be an integer between 1000 and 2000000")
        self.oversize_skip_globs = _validated_globs(
            ctx.get("oversize_skip_globs", list(DEFAULT_OVERSIZE_SKIP_GLOBS))
        )
        self.scan_secrets = config_boolean(ctx.get("scan_secrets", True), "scan_secrets")
        self.inspect_model_artifacts = config_boolean(
            ctx.get("inspect_model_artifacts", False), "inspect_model_artifacts"
        )
        self.model_metadata_bytes = ctx.get("model_metadata_bytes", 65536)
        if type(self.model_metadata_bytes) is not int or not 128 <= self.model_metadata_bytes <= 1048576:
            raise ConnectorError(
                "code.filesystem: model_metadata_bytes must be an integer between 128 and 1048576"
            )
        self.use_git = config_boolean(ctx.get("use_git", False), "use_git")
        self.strict_coverage = config_boolean(ctx.get("strict_coverage", False), "strict_coverage")
        self.include_tests = config_boolean(ctx.get("include_tests", False), "include_tests")
        self.profile = ctx.get("profile", "default")
        if ("profile" in ctx.config and ctx.config["profile"] is None) or self.profile not in PROFILES:
            raise ConnectorError("code.filesystem: profile must be default or ci")
        if self.profile == "ci" and self.strict_coverage:
            raise ConnectorError(
                "code.filesystem: profile ci declares omissions that strict_coverage reports as errors; "
                "set one of them"
            )
        self.triage = config_boolean(ctx.get("triage", False), "triage")
        self.agent_granularity = ctx.get("agent_granularity", "project")
        if ("agent_granularity" in ctx.config and ctx.config["agent_granularity"] is None) or (
            self.agent_granularity not in ("project", "source")
        ):
            raise ConnectorError("code.filesystem: agent_granularity must be project or source")
        extra = _validated_names(ctx.get("exclude"), "exclude")
        self.default_excludes = config_boolean(ctx.get("default_excludes", True), "default_excludes")
        self._explicit_exclude_names = frozenset(e for e in extra if "*" not in e and "/" not in e)
        self.exclude_names = (
            set(DEFAULT_EXCLUDES) if self.default_excludes else set(VCS_METADATA_EXCLUDES)
        ) | self._explicit_exclude_names
        self.exclude_globs = [e for e in extra if "*" in e or "/" in e]
        self.include_paths = _validated_include(ctx.get("include"))
        # Default-excluded directory names the current walk skipped, with counts.
        self._default_skipped: dict[str, int] = {}
        # Files that were read but not as clean text, by what was done to them (see ``_note_file``).
        self._file_notes: dict[str, list[str]] = {}
        self.label: str | None = ctx.get("label")
        # Every labeled `paths` root has its own identity, even if the list
        # shrinks to one. The engine marks a child split for incremental reuse.
        paths = ctx.get("paths")
        # Iterated per character, a bare string would name roots such as "/".
        _validated_names(paths, "paths")
        self._shared_label_roots = isinstance(paths, list) or ctx.get("_shared_label_roots") is True
        if self.label and isinstance(paths, list):
            validate_distinct_paths(paths)
        self._root_ids: dict[Path, str] = {}
        root_ids = ctx.get("root_ids")
        split_root_id = ctx.get("_root_id")
        if root_ids is not None:
            if not self.label or ctx.input_path:
                raise ConnectorError("code.filesystem: root_ids requires a label and paths, without input")
            validated = validate_root_ids(paths, root_ids)
            self._root_ids = {
                Path(path).expanduser().resolve(): root_id
                for path, root_id in zip(paths, validated, strict=True)
            }
        elif split_root_id is not None:
            path = ctx.get("path")
            if (
                not self.label
                or not isinstance(path, str)
                or not isinstance(split_root_id, str)
                or not _ROOT_ID_RE.fullmatch(split_root_id)
            ):
                raise ConnectorError("code.filesystem: invalid split root identity")
            self._root_ids[Path(path).expanduser().resolve()] = split_root_id
        self.diff_base: str | None = ctx.get("diff_base")
        if self.diff_base is not None:
            from shadowscan.utils.git import validate_diff_base

            if not isinstance(self.diff_base, str) or validate_diff_base(self.diff_base) is None:
                raise ConnectorError(
                    f"code.filesystem: diff_base must be a valid git ref, got {self.diff_base!r}"
                )
        self.account: str | None = ctx.get("account")
        self.owner: str | None = ctx.get("owner")
        self.provider_override: str | None = ctx.get("provider")
        self.extra_metadata: dict[str, Any] = dict(ctx.get("metadata", {}) or {})
        # CODEOWNERS and git-history ownership (ADR-005): reads stay on the
        # descriptor scan_tree opens, so the resolver is told the active scan.
        self.ownership = OwnershipResolver(
            ctx,
            owner=self.owner,
            use_git=self.use_git,
            max_file_size=self.max_file_size,
            included=self._included,
        )
        self._symlink_warnings: set[Path] = set()
        self._declared_link_notes: set[Path] = set()
        # Supported lockfiles of the current root's walk -> whether their own
        # manifest sits beside them (see _lockfile_gap).
        self._lockfile_governed: dict[str, bool] = {}
        # (project root, path) of settings files the walk skipped (a link gap or a non-regular entry).
        self._unread_settings: list[tuple[str, str]] = []
        # Settings files of the scanned tree that a remote API snapshot did not include (set by
        # the code.github / code.gitlab connectors that delegate to this one).
        self.unread_settings: list[str] = []
        # Whether the remote API listing of the tree was cut short or held entries it could not
        # name (set by the code.github / code.gitlab connectors that delegate to this one):
        # settings files may exist that nothing lists, so no approval gate of this tree can
        # claim every action (``record_approval(complete=False)``).
        self.tree_listing_incomplete = False
        # The same for the root being scanned, from that listing or from its own walk stopped
        # by max_files, max_entries, the deadline or a directory it could not list. Reset for
        # every root, so one root's truncation never weakens another's gates.
        self._root_listing_incomplete = False
        self._checked_submodules: set[tuple[Path, str]] = set()
        self._gitlink_roots: set[Path] = set()
        # Oversize files under test paths skipped with a warning (include_tests false).
        self.skipped_oversize_test_fixtures = 0

    # ----------------------------------------------------------------- input
    def _paths(self) -> list[Path]:
        paths = self.ctx.get("paths") or ([self.ctx.get("path")] if self.ctx.get("path") else None)
        if not paths and self.ctx.input_path:
            paths = [self.ctx.input_path]
        if not paths:
            raise ConnectorError("code.filesystem: 'path' is required")
        out = []
        for p in paths:
            pp = _checked_scan_root(p)
            if not pp.exists():
                raise ConnectorError(f"code.filesystem: path not found: {p}")
            out.append(pp)
        return out

    def collect(self) -> Iterable[dict[str, Any]]:
        for root in self._paths():
            yield {"path": str(root)}

    def load_offline(self, path: str) -> Iterator[dict[str, Any]]:
        yield {"path": path}

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        for rec in records:
            try:
                root = _checked_scan_root(rec["path"])
            except ConnectorError as exc:
                self.ctx.error(str(exc))
                continue
            if not root.exists():
                self.ctx.error(f"code.filesystem: path not found: {root}")
                continue
            yield from self.scan_tree(root)

    # ------------------------------------------------------------------ walk
    def _excluded(self, rel: str, name: str) -> bool:
        """Directory exclusion: configured names and globs."""
        return name in self.exclude_names or self._excluded_file(rel)

    def _included(self, rel: str) -> bool:
        """Whether ``rel`` is one of the configured include paths or sits below one (all, when unset)."""
        if not self.include_paths:
            return True
        return any(rel == p or rel.startswith(p + "/") for p in self.include_paths)

    def _leads_to_include(self, rel: str) -> bool:
        """Whether the walk must enter directory ``rel`` to reach a configured include path."""
        return self._included(rel) or any(p.startswith(rel + "/") for p in self.include_paths)

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
            self._model_artifact_name(name)
            or ext in SOURCE_EXTENSIONS
            or ext in TEXT_CONFIG_EXTENSIONS
            or is_manifest_name(name)
            or name in MCP_CONFIG_NAMES
            or bool(self.index.match_file(rel))
        )

    def _model_artifact_name(self, name: str) -> bool:
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

    def _note_file(self, rel: str, note: str) -> None:
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

    def _size_limit(self, name: str) -> int:
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

    def _declared_omission(self, rel: str) -> bool:
        """Whether a coverage gap at ``rel`` is one the ``ci`` profile declared in advance.

        The profile accepts gaps in the paths whose evidence is already
        discounted (``negative_context`` and the test-path policy): recorded
        cassettes, fixtures, tutorials, samples and generated files. Test paths
        count only while ``include_tests`` is false, when their evidence is
        discounted; with it set they are source like any other.
        """
        if self.profile != "ci":
            return False
        if _is_test_path(rel):
            return not self.include_tests
        return _is_docs_path(rel) or _is_example_path(rel) or _is_generated_path(rel)

    def _gap(self, rel: str, message: str, *, error: bool = False, suffix: bool = True) -> None:
        """Record a coverage gap at ``rel``.

        An error, or a warning that leaves the scan incomplete (``suffix``
        appends the usual ``; coverage incomplete``), unless the ``ci`` profile
        declared the gap: then a warning that leaves the scan complete, counted
        in the report's ``declared_omissions``, so a profile scan is never read
        as one that read everything.
        """
        if self._declared_omission(rel):
            self.ctx.warn(f"{message}; declared omission (profile ci)", incomplete=False, declared=True)
        elif error:
            self.ctx.error(message)
        else:
            self.ctx.warn(f"{message}; coverage incomplete" if suffix else message, incomplete=True)

    def _lockfile_gap(self, rel: str, reason: str) -> None:
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
            if not self._excluded_file(rel) and self._included(rel):
                return True
        return False

    def _skip_oversize(
        self, rel: str, size: int, reason: str | None = None, *, declared: bool = False
    ) -> None:
        reason = reason or "generated or binary content is never analyzed"
        self.ctx.warn(
            f"code.filesystem: {rel}: skipped {size} byte file over max_file_size ({self.max_file_size}); "
            f"{reason}",
            incomplete=False,
            declared=declared,
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
        if self._model_artifact_name(name):
            return False
        if name.lower() in LOCKFILE_NAMES:
            self._lockfile_gap(rel, "file exceeds max_file_size")
            return True
        if self._oversize_skippable(rel, name):
            self._skip_oversize(rel, size)
            return True
        if not (_analyzed_by_name(name) or self.index.match_file(rel)):
            return False
        if self.scan_secrets:
            # Documentation and fixtures are read for credentials: unread,
            # they could hide one, so the reader records the gap, unless the
            # ci profile declared such a gap in a discounted path in advance.
            if self._declared_omission(rel):
                self._skip_oversize(
                    rel, size, "unread for credentials; declared omission (profile ci)", declared=True
                )
                return True
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
        link_read = (
            bool(alias_signals) or _analyzed_by_name(link_name) or self._model_artifact_name(link_name)
        )
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
            or not self._included(target_rel)
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
            and self._model_artifact_name(link_name)
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
        if self._excluded_file(rel) or not self._included(rel):
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
            if size > self._size_limit(root.name) and self._skipped_oversize(root.name, root.name, size):
                return
            yield root.name, root, ".", size
            return

        def walk_error(exc: OSError) -> None:
            self.ctx.error(f"code.filesystem: could not enumerate a directory under {root}")
            self._root_listing_incomplete = True

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
                name for name in filenames if self._included(name if rel_dir == "." else f"{rel_dir}/{name}")
            )
            if rel_dir != "." and _marks_project(Path(dirpath), included_names):
                roots.append(rel_dir)
                proj = rel_dir
            for fn in sorted(filenames):
                walk.budget.check()
                _check_enumeration_time(walk)
                shown = _report_name(fn)
                rel = shown if rel_dir == "." else f"{rel_dir}/{shown}"
                if self._excluded_file(rel) or not self._included(rel):
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
                if info.st_size > self._size_limit(fn) and self._skipped_oversize(rel, fn, info.st_size):
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
                    if not self._included(rel) and not self._include_behind_link(path, rel):
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
        if self._declared_omission(rel):
            # Declared, counted and named in full: it does not take the gap budget below.
            self._gap(rel, f"code.filesystem: {rel}: skipped, not a regular file ({kind})")
            return
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
            self._root_listing_incomplete = True
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
            self._root_listing_incomplete = True
            return False
        # A link that resolves inside the scan root loses no coverage only if
        # the target is scanned at its real path.
        target = _resolved_link_target(link, resolved_root)
        if target is not None and self._link_target_is_scanned(rel, target, resolved_root, walk):
            return True
        if PurePosixPath(rel).name.lower() in LOCKFILE_NAMES:
            # Never followed; scoped like any other lockfile that was not inventoried.
            self._lockfile_gap(rel, "symbolic link is not followed")
            return True
        message = f"code.filesystem: skipped symbolic link {rel} whose target is unavailable or unscanned"
        if self._declared_omission(rel):
            # One representative note per root, like the gap below, and it
            # leaves that gap's own representative slot for an undeclared link.
            if root not in self._declared_link_notes:
                self._declared_link_notes.add(root)
                self._gap(rel, message)
            return True
        # A single representative diagnostic per root keeps hostile trees
        # from filling the report with thousands of link names.
        walk.link_gaps += 1
        if root not in self._symlink_warnings:
            self._symlink_warnings.add(root)
            # Stays fail-closed: the target's bytes exist and other tools may
            # read them, so an unscanned target is lost coverage a repository
            # could hide behind — not a file-attributable input defect.
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
        if self._model_artifact_name(path.name):
            return scan_timeout_for_size(self.scan_timeout, min(size, self.model_metadata_bytes))
        if size > self._size_limit(path.name):
            return 0.0
        will_read = _analyzed_by_name(path.name) or bool(self.index.match_file(rel))
        return budget if will_read or self._model_artifact_name(path.name) else 0.0

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

    # ------------------------------------------------------------------ scan
    @contextmanager
    def _isolated(
        self,
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
            self._gap(rel, f"code.filesystem: {rel}: {analysis} incomplete ({reason(exc)})", error=True)

    def scan_tree(self, root: Path) -> Iterator[Finding]:
        root = root.absolute()
        scan = _ScanState(root, self._scan_label(root))
        previous_scan = self.ownership.scan
        self.ownership.scan = scan
        # Ownership caches belong to this opened tree, not a pathname that a
        # later scan on the same connector instance may find replaced.
        self.ownership.forget_root(root)
        # Each root's gates read only its own listing (scan_tree walks and emits one root at a time).
        self._root_listing_incomplete = self.tree_listing_incomplete
        try:
            if self.triage:
                # Unconditional, per scanned root: a triage result is a subset
                # and must never read as a complete scan (fail closed, exit 3).
                self.ctx.warn(
                    f"code.filesystem: {scan.label}: triage scan: source analysis, credential detection "
                    "and content sweeps skipped; findings are a subset of a full scan",
                    incomplete=True,
                )
            if self.diff_base is not None:
                scan.diff_base_ref = self.diff_base
                scan.diff_files = self._resolve_diff(root)
            self._walk(scan)
            if scan.artifacts_uninspected:
                self.ctx.warn(
                    f"code.filesystem: {scan.label}: artifact metadata budget ({_ARTIFACT_SCAN_BYTES:,} "
                    f"bytes, or {_ARTIFACT_SKIP_BYTES:,} array bytes, per root) exhausted; "
                    f"{scan.artifacts_uninspected} selected file(s) were not inspected as artifacts "
                    "(extensionless ones were still analysed as text); artifact inventory incomplete",
                    incomplete=True,
                )
            self._resolve_reexport_sources(scan)
            for f in self._emit_findings(scan):
                if scan.diff_files is not None:
                    f.add_tag("diff-scan")
                    f.metadata["diff_scan"] = {
                        "base_ref": scan.diff_base_ref,
                        "changed_files": len(scan.diff_files),
                    }
                yield f
        finally:
            # Closed whether or not the emit completes.
            self.ownership.scan = previous_scan
            self._close_root(scan)

    @staticmethod
    def _close_root(scan: _ScanState) -> None:
        if scan.root_fd >= 0:
            os.close(scan.root_fd)
        scan.root_fd = -1

    def _resolve_diff(self, root: Path) -> frozenset[str] | None:
        from shadowscan.utils.git import DiffError, diff_changed_files

        try:
            changed = diff_changed_files(root, self.diff_base, self.ctx)  # type: ignore[arg-type]
        except DiffError as exc:
            self.ctx.warn(
                f"code.filesystem: diff-base could not be resolved ({exc}); falling back to full scan",
                incomplete=False,
            )
            return None
        # Operator intent, like --only: not a coverage gap, but the report must say
        # that unchanged files were not read, even when it holds no finding.
        self.ctx.warn(
            f"code.filesystem: diff-scoped scan against {self.diff_base!r}: only {len(changed)} changed "
            "file(s) plus dependency manifests and .env files were scanned; unchanged files were not "
            "scanned, so this report is not a repository inventory",
            incomplete=False,
        )
        return changed

    def _resolve_reexport_sources(self, scan: _ScanState) -> None:
        """Bind queued consumers after all shim snapshots have been read safely.

        The walk already matched their imports and code patterns. Each binder
        starts under the walk's own rule: only while its matching budget and
        the walk's margin fit before the connector deadline, so the findings
        already collected are still emitted in time. A consumer left unbound is
        named, keeps its lexical evidence and makes the results incomplete.
        """
        deadline = self.ctx.deadline
        for position, source in enumerate(scan.reexport_files):
            file = source.file
            size = len(file.text.encode("utf-8"))
            budget = scan_timeout_for_size(self.scan_timeout, size)
            wall_cap = budget * WALL_BUDGET_FACTOR
            if deadline is not None:
                remaining = deadline - time.monotonic()
                # As in the walk, the binder's wall cap never runs into the deadline's margin.
                wall_cap = max(budget, min(wall_cap, remaining - scan.margin))
                if remaining < budget + scan.margin:
                    if remaining > scan.margin + self.scan_timeout:
                        self.ctx.error(
                            f"code.filesystem: {file.rel}: Python re-export analysis skipped; the remaining "
                            f"connector deadline cannot cover its {budget:.0f}s matching budget; "
                            "lexical evidence retained",
                        )
                        self._retain_lexical_evidence([source], deadline - scan.margin / 2)
                        continue
                    others = len(scan.reexport_files) - position - 1
                    queued = f" and {others} other queued files" if others else ""
                    self.ctx.error(
                        "code.filesystem: connector deadline reached before Python re-export analysis of "
                        f"{file.rel}{queued}; results incomplete",
                    )
                    self._retain_lexical_evidence(scan.reexport_files[position:], deadline - scan.margin / 2)
                    break
            resolver = scan.reexports.resolver(file.proj_root, source.is_local_module)
            with (
                self._isolated(file.rel, "Python re-export analysis"),
                self.index.scan_budget(seconds=budget, chars=size, wall_seconds=wall_cap),
            ):
                try:
                    self._bind_source(source, resolve_import=resolver)
                except ReexportLimitError as exc:
                    self.ctx.error(f"code.filesystem: {file.rel}: {exc}; analysis incomplete")
                    self._bind_source(source)
        # The walk redacted every queued consumer (see _scan_file), so settling
        # only cuts the excerpts its matches asked for, reached or not.
        for source in scan.reexport_files:
            self._settle_excerpts(source.file)
        scan.reexport_files.clear()

    def _retain_lexical_evidence(self, sources: list[_MatchedSource], until: float) -> None:
        """Record the walk's lexical evidence for queued consumers the binder cannot read.

        As for a file over the binder's budget, the lexical matches stand in for
        the whole file. Recording stops at ``until``, like the walk's own final
        count, so the findings collected so far are still emitted in time.
        """
        for source in sources:
            if time.monotonic() >= until:
                return
            with self._isolated(source.file.rel, "Python re-export analysis"):
                self._record_source(source, [], [(0, len(source.text))])

    def _scan_label(self, root: Path) -> str:
        """Return the resource prefix of the findings under ``root``."""
        label = self.label or str(root)
        if self.label and self._shared_label_roots:
            # Explicit IDs survive checkout relocation; absent them, hash the
            # resolved root to avoid exposing local directory names.
            root_id = self._root_ids.get(root)
            label = (
                f"{label}/root-id-{root_id}"
                if root_id is not None
                else f"{label}/root-{hashlib.sha256(os.fsencode(root)).hexdigest()}"
            )
        return label

    def _walk(self, scan: _ScanState) -> None:
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
            self._walk_entries(scan)
        except _WalkLimitError as exc:
            self.ctx.error(f"code.filesystem: {scan.label}: {exc}; results incomplete")
            self._root_listing_incomplete = True
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

    def _walk_entries(self, scan: _ScanState) -> None:
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
            self._root_listing_incomplete = True
        entries.sort(key=lambda entry: (_scan_priority(entry[0], entry[1].name), entry[3]))
        examined = 0
        for index, (rel, path, proj_root, size) in enumerate(entries):
            if scan.diff_files is not None and not self._diff_included(rel, scan.diff_files):
                continue
            analysis_size = (
                min(size, self.model_metadata_bytes) if self._model_artifact_name(path.name) else size
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
                self._isolated(rel, "file analysis", _file_failure_reason),
                self.index.scan_budget(seconds=budget, chars=size, wall_seconds=wall_cap),
            ):
                self._scan_file(scan, rel, path, proj_root)
        # A settings file the walk skipped can only loosen the gate of a project it read.
        for rel in self.unread_settings:
            if not _below_root(rel):
                # The snapshot writer refuses such a path before this point; a path that is not
                # confined to the tree must drive no listing or manifest probe outside it, and a
                # listing that names one is not trusted to be complete.
                self.ctx.warn(
                    f"code.filesystem: {scan.label}: unread settings path outside the scanned tree "
                    "ignored; coverage incomplete",
                    incomplete=True,
                )
                self._root_listing_incomplete = True
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

    def _scan_file(self, scan: _ScanState, rel: str, path: Path, proj_root: str) -> None:
        """Run every analysis pass over one file of the walk."""
        proj = scan.projects.setdefault(proj_root, _Project(proj_root))
        scan.reexports.note_path(proj_root, rel)
        proj.files += 1
        self.ctx.examined()
        lang = language_for_path(rel)
        if lang:
            proj.languages.add(lang)

        if self._model_artifact_name(path.name):
            on_disk = (
                PurePosixPath(path.relative_to(scan.base).as_posix()) if scan.base else PurePosixPath(rel)
            )

            def charge(size: int) -> None:
                if size > scan.artifact_bytes_remaining:
                    raise ArtifactBudgetExhausted("artifact scan-wide metadata byte limit exceeded")
                scan.artifact_bytes_remaining -= size

            def skip_charge(size: int) -> None:
                if size > scan.artifact_skip_bytes_remaining:
                    raise ArtifactBudgetExhausted("artifact scan-wide array skip byte limit exceeded")
                scan.artifact_skip_bytes_remaining -= size

            try:
                result = inspect_artifact(
                    on_disk,
                    dir_fd=scan.root_fd,
                    max_bytes=self.model_metadata_bytes,
                    check=self.ctx.check_deadline,
                    charge=charge,
                    skip_charge=skip_charge,
                )
            except ArtifactBudgetExhausted:
                # The root's budget is spent: count the file once (reported
                # after the walk) and still give it the text analysis below.
                scan.artifacts_uninspected += 1
                result = None
            if result is not None:
                kind = Kind.INFRA if result.format == "pyinstaller" else Kind.LOCAL_MODEL
                finding = self._base(
                    scan.label,
                    scan.root,
                    rel,
                    kind,
                    f"{result.format} artifact inventory: {rel}",
                    "binary-artifact",
                )
                finding.metadata["artifact_inventory"] = {
                    "format": result.format,
                    **result.metadata,
                    "limitations": result.limitations,
                }
                finding.add_tag("artifact-inventory-only")
                finding.add_evidence(
                    Evidence(
                        signal=f"artifact-format:{result.format}",
                        description="Bounded file-format metadata observed; execution is unobserved",
                        location=rel,
                        weight=0.4,
                    )
                )
                finding.recompute_confidence()
                scan.inventory_findings.append(finding)
            # Extensionless text can still be a source/configuration file.
            if path.suffix.lower() in ARTIFACT_SUFFIXES or result is not None:
                return

        # 1. file-name signals (config files of agents / MCP / A2A ...)
        file_matches = self.index.match_file(rel)
        by_name = _analyzed_by_name(path.name)
        if not (by_name or file_matches):
            return
        if self.triage and not file_matches and path.suffix.lower() in SOURCE_EXTENSIONS:
            # Triage never reads plain source files; the per-root warning
            # already discloses the skipped stages.
            return
        named = by_name or self._named_by_signature(rel, file_matches)
        loaded = self._read_source(rel, path, scan.root_fd, scan.base, named=named)
        if loaded is None:
            _note_unread_settings(proj, rel)
            return
        text, raw_notebook, cells, foreign = loaded
        if path.name.lower() in LOCKFILE_NAMES:
            manifest = parse_manifest(rel, text)
            if manifest is not None:
                if manifest.lockfile_issue is not None:
                    self._lockfile_gap(rel, manifest.lockfile_issue)
                self._file_errors(rel, manifest.errors)
                if manifest.lockfile is not None:
                    self._lockfile_inventory(scan, rel, manifest.lockfile)
            if self.scan_secrets and not self.triage:
                # A lockfile is a read file: the credential pass covers it
                # like any other text. A pinned registry or source URL can
                # embed a token that the dependency inventory never retains.
                file = _SourceFile(
                    rel=rel,
                    path=path,
                    proj_root=proj_root,
                    proj=proj,
                    text=text,
                    lang=lang,
                    file_matches=file_matches,
                )
                file.structure, file.structure_strict = self._structure_for(rel, text)
                file.excerpts = _ExcerptSource(rel, path, text, file.structure)
                self._detect_secrets(scan, file)
            return
        nul_text = None
        if "\x00" in text and path.suffix.lower() != ".ipynb":
            # Bash drops NUL bytes from a script, so `api.open<NUL>ai.com` runs as api.openai.com: names
            # are matched without them. Node and PHP keep them, so a source file is also lexed as it was
            # read (``_match_source``). Lines do not move.
            nul_text, text = text, text.replace("\x00", "")
        file = _SourceFile(
            rel=rel,
            path=path,
            proj_root=proj_root,
            proj=proj,
            text=text,
            nul_text=nul_text,
            lang="python" if path.suffix.lower() == ".ipynb" else lang,
            file_matches=file_matches,
            raw_notebook=raw_notebook,
            cells=cells,
            foreign=foreign,
        )
        file.structure, file.structure_strict = self._structure_for(rel, text)
        file.excerpts = _ExcerptSource(rel, path, text, file.structure)
        try:
            if file.ext in SOURCE_EXTENSIONS:
                # One literal scan serves the credential, import and code passes of
                # a source file. Other files run the credential pass alone, whose
                # own few literals are cheaper than the union.
                file.literals = self.index.literal_scan(text, file.lang)
            self._record_file_matches(file)
            if path.name == "SKILL.md":
                audit = audit_skill_text(text)
                proj.skill_audits[rel] = audit
                if audit.incomplete:
                    self.ctx.warn(
                        f"code.filesystem: {rel}: static instruction audit incomplete", incomplete=True
                    )
            if any(rel in files for files in proj.coding_agent_files.values()):
                # Inspect the same confined snapshot as every other analysis pass.
                if len(text.encode("utf-8")) > MAX_INSTRUCTION_TEXT_BYTES:
                    self.ctx.warn(
                        f"code.filesystem: {rel}: instruction content exceeds inspection limit; "
                        "coverage incomplete",
                        incomplete=True,
                    )
                else:
                    proj.instruction_hits[rel] = inspect_instruction_text(text)
            if self.scan_secrets and not self.triage:
                self._detect_secrets(scan, file)
            if self._record_detection_rules(file):
                # A rule pack lists the names and hosts it detects. Its content
                # is data, not usage or configuration of those products.
                return
            self._detect_mcp(file)

            # 2. manifests (dependencies, images, env names, IaC types)
            self._scan_manifest(scan, file)
            if file.ext in _IAC_EXTENSIONS and not file.is_mcp:
                self._scan_iac(scan, file)

            # 3. source & config content
            self._scan_content(scan, file)

            # 4. special files
            self._record_special_files(scan, file)
        finally:
            if not file.reexport_pending:
                self._settle_excerpts(file)
            elif file.excerpts.structure is not None:
                # A queued consumer is settled after its analysis, but redacted
                # here, under the walk's deadline accounting like every other
                # file: what the re-export pass, a consumer it never reaches and
                # emit read from it afterwards is only cut from the redacted lines.
                self._redacted_lines(file)

    def _read_source(
        self, rel: str, path: Path, root_fd: int, base: Path | None = None, *, named: bool = True
    ) -> tuple[str, str | None, _CellSpans, _CellSpans] | None:
        """Read a file for analysis: its text and, for a notebook, the raw document and cell spans.

        A notebook's last element lists the cells declared another language (``_notebook_source``).

        The file is read relative to the open scan root ``root_fd``: by its on-disk
        name (``path`` below ``base``), while ``rel`` is the report-safe name used in
        diagnostics. A notebook's text is its code cells, and the spans locate each
        in it. None means nothing is analyzed; the recorded diagnostics say why.
        ``named`` is False when only a directory-wide signature glob selects the
        file, so a recognised binary artifact there (an image beside coding-agent
        rules) is skipped without a coverage gap.
        """
        read_errors: list[str] = []
        read_notes: list[str] = []
        on_disk = PurePosixPath(path.relative_to(base).as_posix()) if base is not None else PurePosixPath(rel)
        text = read_text(
            on_disk,
            self._size_limit(path.name),
            read_errors,
            dir_fd=root_fd,
            analyzable_name=named,
            notes=read_notes,
        )
        for note in read_notes:
            self._note_file(rel, note)
        for issue in read_errors:
            if issue == "file exceeds max_file_size" and not self.strict_coverage:
                self._gap(rel, f"code.filesystem: {rel}: skipped, {issue}")
            else:
                # Undecodable analyzable files stay fail-closed: editors and
                # runtimes tolerate bytes the scanner cannot decode, so a NUL
                # in a CLAUDE.md could otherwise hide content from the scan.
                self._gap(rel, f"code.filesystem: {rel}: {issue}", error=True)
        if text is None:
            return None
        if len(text) <= LFS_POINTER_MAX_BYTES and text.startswith(_LFS_POINTER_TEXT):
            # A checkout made without git-lfs holds a pointer in place of the
            # file: its content was never read, whatever the name promises.
            message = f"code.filesystem: {rel}: Git LFS pointer file, not the content it stands for"
            if self.strict_coverage:
                self.ctx.error(f"{message}; coverage incomplete")
            else:
                self._gap(rel, message)
            return None
        if path.suffix.lower() != ".ipynb":
            return text, None, (), ()
        return self._notebook_source(rel, text)

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

    def _notebook_source(
        self, rel: str, document: str
    ) -> tuple[str, str | None, _CellSpans, _CellSpans] | None:
        """Return a notebook's code cells, their spans, within max_file_size its raw document, and
        the spans of cells declared another language.

        A cell is declared another language when the notebook's kernel is not a Python one (an R
        or Julia notebook) or when a cell magic runs, renders or writes its body as something else
        (``%%bash``, ``%%writefile requirements.txt``; see ``foreign_cell``). Such a cell is still
        bound when it parses as Python; one that does not is not a coverage gap.
        """
        notebook_errors: list[str] = []
        oversized_notebook = len(document) > self.max_file_size
        raw_notebook = None if oversized_notebook else document
        sources: list[str] = []
        language: list[str] = []
        text = notebook_to_source(document, notebook_errors, cells=sources, language=language)
        self._file_errors(rel, dict.fromkeys(notebook_errors), defect=True)
        python_kernel = not language or language[0] in {"python", "python3", "ipython", "ipython3"}
        # The cells are joined by one line break each.
        spans: list[tuple[int, int]] = []
        foreign: list[tuple[int, int]] = []
        offset = 0
        for source in sources:
            spans.append((offset, offset + len(source)))
            if not python_kernel or foreign_cell(source):
                foreign.append(spans[-1])
            offset += len(source) + 1
        # Unread analyzable content leaves coverage incomplete, as
        # for any oversize file; strict_coverage only raises the
        # diagnostic from a warning to an error.
        gap: str | None = None
        if len(text) > self.max_file_size:
            gap = f"code.filesystem: {rel}: skipped, notebook code cells exceed max_file_size"
        elif oversized_notebook and self.scan_secrets:
            # Code cells are analyzed as usual. Saved outputs are
            # read only for credentials, and not at this size.
            gap = (
                f"code.filesystem: {rel}: notebook over max_file_size; code cells analyzed, "
                "saved outputs not scanned for credentials"
            )
        if gap is not None:
            self._gap(rel, gap, error=self.strict_coverage)
        if len(text) > self.max_file_size:
            return None
        return text, raw_notebook, tuple(spans), tuple(foreign)

    def _structure_for(self, rel: str, text: str) -> tuple[Any, bool]:
        """Parse the credential context of a structured file; None withholds its excerpts.

        Structured files are parsed now so a resource-limit or integrity
        failure (duplicate fields, non-finite numbers) reaches the per-file
        boundary. Redacting the text for excerpts waits until a match needs
        one, which most files never do. The flag says the document is the
        strict-JSON parse of the text, which the manifest parsers may reuse.
        """
        strict: list[bool] = []
        try:
            return _structured_context(rel, text, strict), bool(strict)
        except (
            JSONIntegrityError,
            YAMLIntegrityError,
            YAMLResourceLimitError,
            SanitizationLimitError,
        ) as exc:
            # Detection still runs, but without an established
            # structured context none of this file's excerpts can
            # safely be emitted.
            self._withhold_excerpts(rel, exc, "parsing")
            return None, False

    @staticmethod
    def _parsed_document(file: _SourceFile, suffixes: tuple[str, ...], *, strict: bool = False) -> Any:
        """Return the file's parsed document for a consumer of ``suffixes`` files, or None to parse again."""
        if file.structure is None or file.structure is _NO_STRUCTURE or not file.rel.endswith(suffixes):
            return None
        if strict and not file.structure_strict:
            return None
        return file.structure

    def _withhold_excerpts(self, rel: str, exc: Exception, stage: str = "sanitization") -> None:
        # Stays fail-closed: a resource-limit or integrity failure here means
        # the credential-redaction context could not be established, and
        # parsers diverge on such content (duplicate keys, deep nesting), so
        # treating it as a benign input defect would open an evasion channel.
        kind = type(exc).__name__
        self._gap(
            rel,
            f"code.filesystem: {rel}: structured {stage} incomplete ({kind}); excerpts withheld",
            error=True,
        )

    def _input_defect(self, rel: str, issue: str) -> None:
        """Record a defect attributable to the file's own content.

        Templates and fixtures may be intentionally malformed, but the
        scanner cannot establish their content as fully analyzed. Preserve
        valid neighboring findings and always mark coverage incomplete.
        ``strict_coverage`` promotes the diagnostic from warning to error;
        both forms fail closed.
        """
        message = f"code.filesystem: {rel}: input defect: {issue}"
        self._gap(rel, message, error=self.strict_coverage, suffix=False)

    # Syntax/shape defects get a distinct diagnostic so operators can find
    # templates and fixtures. This taxonomy never changes completeness:
    # downstream parsers or templating stages may interpret content differently.
    _SYNTAX_DEFECT_PREFIXES = (
        "invalid TOML",
        "invalid JSON",
        "invalid structured configuration syntax",
        "invalid agent manifest syntax",
        "MCP servers must be an object or array",
    )

    def _file_errors(self, rel: str, issues: Iterable[str], *, defect: bool = False) -> None:
        """Record parser or validator issues for ``rel``.

        ``defect`` routes recognized input failures through
        :meth:`_input_defect` for a distinct diagnostic. Every issue marks
        coverage incomplete, regardless of diagnostic severity.
        """
        for issue in issues:
            if defect and issue.startswith(self._SYNTAX_DEFECT_PREFIXES):
                self._input_defect(rel, issue)
            else:
                self._gap(rel, f"code.filesystem: {rel}: {issue}", error=True)

    def _redacted_lines(self, file: _SourceFile) -> list[str]:
        """Return the redacted lines excerpts are cut from, redacting on first use."""
        lines = self._redacted_lines_of(file.excerpts)
        if file.excerpts.structure is None:
            file.structure = None
        return lines

    def _redacted_lines_of(self, source: _ExcerptSource) -> list[str]:
        """Return the redacted lines of ``source``, redacting on first use."""
        if source.structure is None:
            return []
        if source.safe_lines is None:
            try:
                # Match locations count LF only. Other separators can occur
                # inside literals (Go raw imports may contain CR) and must not
                # shift excerpts. _excerpt strips a CR left by a CRLF ending.
                source.safe_lines = _redacted_source(source.text or "", source.structure).split("\n")
            except (YAMLResourceLimitError, SanitizationLimitError) as exc:
                self._withhold_excerpts(source.rel, exc)
                source.structure = None
                source.safe_lines = []
            source.text = None  # the redacted lines are all an excerpt needs
        return source.safe_lines

    def _settle_excerpts(self, file: _SourceFile) -> None:
        """Redact a file that recorded excerpted evidence, as the eager excerpts did, to surface limit errors.

        Whether a sanitization limit is exceeded is known only by redacting.
        A scan whose only such failure is in a file whose matches are all
        dropped later must still be incomplete, so every file that recorded
        a match with an excerpt is redacted when its analysis ends. Only the
        excerpts of the lines its matches asked for are kept for emit; a
        re-export consumer queued for analysis after the walk is settled when
        that analysis ends (``_resolve_reexport_sources``).
        """
        source = file.excerpts
        if source.wanted and source.safe_lines is None and source.structure is not None:
            self._redacted_lines(file)
        if source.safe_lines is not None:
            # Keep the excerpts recorded matches asked for, not every line of the file.
            source.kept = {line: _excerpt(source.safe_lines, line) for line in source.wanted}
            source.safe_lines = None
        source.text = None  # the kept excerpts are all an emit needs

    def _file_excerpt(self, file: _SourceFile, line_number: int | None, secret: str | None = None) -> str:
        return _excerpt(self._redacted_lines(file), line_number or 1, secret)

    def _lazy_excerpt(self, file: _SourceFile, line_number: int | None) -> _Snippet:
        """Return the excerpt of ``line_number`` as a callable, produced only if a report keeps the match."""
        source = file.excerpts
        if source.structure is None:
            return ""
        source.wanted.add(line_number or 1)
        return _LazyExcerpt(self._redacted_lines_of, source, line_number)

    def _record_file_matches(self, file: _SourceFile) -> None:
        """Record file-name evidence; MCP file names wait for a parsed configuration."""
        file.card_kind = agent_manifest_kind(file.rel)
        if file.card_kind:
            validation = parse_agent_manifest(file.rel, file.text, file.card_kind)
            self._file_errors(file.rel, validation.errors, defect=True)
            file.card_valid = validation.valid
            file.card_incomplete = validation.incomplete
        for m in file.file_matches:
            if m.signature_id == "protocol.mcp":
                continue
            # A suggestive filename establishes neither a valid
            # manifest nor an agent. Keep coding-agent file evidence
            # and validated product schemas; do not invent agents. An
            # incomplete card gets its own unverified finding instead.
            if file.card_kind and not file.card_valid:
                continue
            m.extra["verified_agent"] = file.card_valid
            self._record(file.proj, m, file.rel, None)
        client = posture_client(file.rel)
        canonical = canonical_settings_path(file.rel)
        if client is not None and canonical is not None and canonical != file.rel:
            # A case or trailing-dot variant of a settings file ('.CLAUDE/settings.local.json'),
            # which macOS and Windows clients read as their settings, matches no file-name
            # signature: establish the client as the documented spelling would, located here.
            sig_id = CLIENT_SIGNATURES[client]
            if not any(m.signature_id == sig_id for m in file.file_matches):
                for m in self.index.match_file(canonical):
                    if m.signature_id == sig_id:
                        self._record(file.proj, m, file.rel, None)
        issues = assess_posture(file.rel, file.text)
        if issues:
            for issue in issues:
                sig_id = CLIENT_SIGNATURES[issue.client]
                entry = {**issue.as_dict(), "file": file.rel}
                if entry not in file.proj.posture.setdefault(sig_id, []):
                    file.proj.posture[sig_id].append(entry)
        if not posture_parseable(file.rel, file.text):
            _note_unread_settings(file.proj, file.rel)
        for setting in approval_settings(file.rel, file.text) or []:
            sig_id = CLIENT_SIGNATURES[setting.client]
            approval = {**setting.as_dict(), "file": file.rel}
            if approval not in file.proj.approvals.setdefault(sig_id, []):
                file.proj.approvals[sig_id].append(approval)

    def _detect_secrets(self, scan: _ScanState, file: _SourceFile) -> None:
        """Collect provider credentials from the file text and a notebook's raw document.

        Credential detection runs first and in its own isolation so a slow or
        over-budget content pass cannot hide a real key. Notebook outputs and
        markdown cells are scanned from the raw document.
        """
        with self._isolated(file.rel, "credential detection"):
            seen_secrets: set[tuple[str, str, int | None]] = set()
            self._detect_secrets_in(scan, file, file.text, seen_secrets)
            if file.raw_notebook is not None and file.raw_notebook != file.text:
                # The raw document repeats every code cell at other line
                # numbers, so a credential found in the cells is not a second
                # observation there; only outputs and markdown cells are new.
                cell_values = {(signature, value) for signature, value, _ in seen_secrets}
                self._detect_secrets_in(scan, file, file.raw_notebook, seen_secrets, skip_values=cell_values)

    def _detect_secrets_in(
        self,
        scan: _ScanState,
        file: _SourceFile,
        raw: str,
        seen_secrets: set[tuple[str, str, int | None]],
        skip_values: AbstractSet[tuple[str, str]] = frozenset(),
    ) -> None:
        # Excerpts of a notebook's raw document come from its own sanitized
        # lines; the redacted source lines describe the code cells only.
        from_raw_notebook = raw is file.raw_notebook and file.raw_notebook != file.text
        raw_lines: list[str] | None = None
        if from_raw_notebook and file.structure is not None:
            try:
                raw_lines = sanitize_text(raw).splitlines()
            except SanitizationLimitError:
                self.ctx.error(
                    f"code.filesystem: {file.rel}: notebook excerpt sanitization incomplete; "
                    "excerpts withheld"
                )
        for m in self.index.match_secrets(raw, scan=file.literals):
            if (m.signature_id, m.value) in skip_values:
                continue
            key = (m.signature_id, m.value, m.line)
            if key in seen_secrets:
                continue
            seen_secrets.add(key)
            reason = placeholder_reason(m.value)
            if reason:
                self._record_example_credential(file.proj, m, file.rel, reason)
                continue
            if from_raw_notebook:
                snippet = _excerpt(raw_lines, m.line or 1, m.value) if raw_lines is not None else ""
            else:
                snippet = self._file_excerpt(file, m.line, m.value)
            scan.secret_hits.setdefault(file.rel, []).append((m, snippet))
            scan.secret_project.setdefault(file.rel, file.proj_root)
            self._record(file.proj, m, file.rel, None)

    def _detect_mcp(self, file: _SourceFile) -> None:
        """Parse an MCP client/server configuration.

        A server that declares itself disabled is still a configured server: the flag
        is client-specific (Cline and Roo honour it, Claude Code does not) and comes
        from the repository, so honouring it here would let a repository hide a server.
        """
        document = self._parsed_document(file, (*_JSON_SUFFIXES, ".toml"))
        file.is_mcp = self._looks_like_mcp_config(file.rel, file.name, file.text, document) or (
            file.name.lower() == "server.json" and '"mcpServers"' in file.text
        )
        if file.is_mcp:
            mcp_errors: list[str] = []
            file.mcp_servers = _parse_mcp_servers(file.rel, file.text, mcp_errors, document)
            self._file_errors(file.rel, dict.fromkeys(mcp_errors), defect=True)
            dedicated = file.name.lower() in _DEDICATED_MCP_CONFIG_NAMES
            if not file.mcp_servers and not mcp_errors and not dedicated:
                # The content heuristic (an "mcp" and a "servers" key anywhere
                # in a JSON/YAML/TOML file) selected a file whose parsed
                # structure configures no server: an exported workflow tagged
                # "mcp", a template with such a comment. It is ordinary
                # configuration, so the IaC, configuration and lexical passes
                # read it as usual instead of skipping it without a diagnostic.
                file.is_mcp = False
        file.mcp_active = bool(file.mcp_servers)
        if file.mcp_active:
            for m in file.file_matches:
                if m.signature_id == "protocol.mcp":
                    self._record(file.proj, m, file.rel, None)

    @staticmethod
    def _record_detection_rules(file: _SourceFile) -> bool:
        """Whether ``file`` is a detection-rule pack; if so, count it on its project.

        File-name and credential evidence is already recorded and agent
        manifests keep their own analysis. No rule-pack shape has an MCP
        server table, so a pack that mentions MCP keys in its patterns is not
        parsed as a client configuration.
        """
        if file.card_kind:
            return False
        parsed = None if file.structure is _NO_STRUCTURE else file.structure
        rule_format = detection_rule_format(file.rel, file.text, parsed)
        if rule_format is None:
            return False
        proj = file.proj
        proj.detection_rules[rule_format] = proj.detection_rules.get(rule_format, 0) + 1
        if len(proj.detection_rule_files) < _MAX_LISTED_RULE_FILES:
            proj.detection_rule_files.append(file.rel)
        return True

    def _record_content(self, file: _SourceFile, m: Match, snippet: _Snippet) -> None:
        # A bare key or matching filename is not evidence of a
        # configured server when the entries are all empty.
        if m.signature_id != "protocol.mcp" or not file.is_mcp or file.mcp_active:
            self._record(file.proj, m, file.rel, snippet)

    def _lockfile_inventory(self, scan: _ScanState, rel: str, inventory: LockInventory) -> None:
        """Keep locked dependencies separate from deployment and source observations."""
        packages = []
        signatures: set[str] = set()
        for package in inventory.packages:
            if package.root:
                continue
            matches = self.index.match_dependency(package.ecosystem, package.name)
            if not matches:
                continue
            signatures.update(m.signature_id for m in matches)
            packages.append(
                {
                    "ecosystem": package.ecosystem,
                    "name": package.name,
                    "version": package.version,
                    "source_type": package.source,
                    "relationship": package.relationship,
                }
            )
        if not packages:
            return
        finding = self._base(
            scan.label,
            scan.root,
            rel,
            Kind.FRAMEWORK_USAGE,
            f"AI dependency lockfile inventory: {rel}",
            "lockfile-inventory",
        )
        finding.frameworks = sorted(signatures)
        finding.metadata["lockfile_inventory"] = {
            "format": inventory.format,
            "package_count": sum(not p.root for p in inventory.packages),
            "dependency_edge_count": inventory.edge_count,
            "roots_known": inventory.roots_known,
            "matched_packages": packages,
            "limitations": inventory.limitations,
        }
        finding.add_tag("dependency-inventory-only")
        finding.add_evidence(
            Evidence(
                signal="dependency:locked-inventory",
                description="AI dependencies recorded in lockfile; installation and execution unobserved",
                location=rel,
                weight=0.4,
                attributes={"confidence_group": "locked-dependencies"},
            )
        )
        finding.recompute_confidence()
        scan.inventory_findings.append(finding)

    def _scan_manifest(self, scan: _ScanState, file: _SourceFile) -> None:
        """Match the dependencies and artifacts (images, env names, IaC types) a manifest declares."""
        rel = file.rel
        may_be_manifest = (
            is_manifest_name(file.name) or file.ext in _MANIFEST_EXTENSIONS or ".github/workflows" in rel
        )
        if not may_be_manifest:
            return
        manifest = parse_manifest(rel, file.text, self._parsed_document(file, (".json",), strict=True))
        if not manifest:
            return
        self._file_errors(rel, dict.fromkeys(manifest.errors), defect=True)
        for dep in manifest.deps:
            file.proj.deps.append(dep)
            for m in self.index.match_dependency(dep.ecosystem, dep.name):
                m.line = dep.line
                self._record(file.proj, m, rel, f"{dep.ecosystem}: {dep.name} {dep.spec or ''}".strip())
        # A pipeline's `image:` runs a job in that container; a Compose or
        # Kubernetes `image:` deploys it. Only the deployment is infrastructure.
        image_scale = CI_IMAGE_WEIGHT_SCALE if _is_pipeline_file(rel) else 1.0
        for art in manifest.artifacts:
            self._handle_artifact(
                file.proj,
                art,
                rel,
                file.text,
                scan.infra_files,
                scan.secret_hits,
                scan.infra_names,
                image_scale=image_scale,
            )

    def _scan_iac(self, scan: _ScanState, file: _SourceFile) -> None:
        """Collect wildcard IAM grants and declared model ids for the infrastructure findings."""
        rel, text = file.rel, file.text
        # Excerpts come from the redacted source, which is only
        # produced for files that actually contain a wildcard.
        if _IAM_WILDCARD_RE.search(text, timeout=_pattern_timeout(), concurrent=False):
            for number, line_text in enumerate(self._redacted_lines(file), start=1):
                if _IAM_WILDCARD_RE.search(line_text, timeout=_pattern_timeout(), concurrent=False):
                    wildcard_hits = scan.iam_wildcards.setdefault(file.proj_root, [])
                    if len(wildcard_hits) < 20:
                        wildcard_hits.append((rel, number, truncate(line_text.strip(), 160) or ""))
        if rel in scan.infra_files:
            scan.infra_project[rel] = file.proj_root
            line_at = line_counter(text)
            for model in _IAC_MODEL_RE.finditer(text):
                for mm in self.index.match_model(model.group(1)):
                    mm.line = line_at(model.start())
                    scan.infra_models.setdefault(rel, []).append(mm)

    def _scan_content(self, scan: _ScanState, file: _SourceFile) -> None:
        """Match source code and configuration content; prose is matched by file name only."""
        # Match prose documentation by its dedicated filenames only.
        # Invocations in a README, even in fenced examples, do not
        # establish executable agent code in this repository.
        is_documentation = file.ext in {".md", ".mdc", ".mdx", ".txt"} and not is_manifest_name(file.name)
        # The manifest pass's Maven XML parser extracts dependency declarations.
        # Generic regex matching over the raw POM would promote
        # examples in descriptions or CDATA to executable agents.
        is_nonexecutable = is_documentation or file.name.lower() == "pom.xml"
        # XML comments are examples/disabled declarations. Preserve
        # offsets for match line numbers and the original redacted
        # excerpts; the manifest parser handles active XML itself.
        content_text = manifest_comment_projection(file.rel, file.text)
        if file.ext in _XML_EXTENSIONS:
            content_text = _without_xml_comments(content_text)
        if file.ext in SOURCE_EXTENSIONS:
            if not self.triage:
                source = self._match_source(scan.root, file, content_text)
                if not self._defer_reexport_source(scan, source):
                    self._bind_source(source)
        elif not is_nonexecutable:
            self._scan_config(scan, file, content_text)
            if (
                not file.is_mcp
                and not self.triage
                and (file.ext in _MODEL_LITERAL_CONFIG_EXTENSIONS or file.name.lower().startswith(".env"))
            ):
                self._scan_model_literals(file, content_text, [], source=False)
        catalog_limits: list[str] = []
        if not is_nonexecutable and not file.is_mcp and not self.triage:
            variables = self.index.match_envs_in_text(content_text)
            for m in variables:
                self._record_content(file, m, self._lazy_excerpt(file, m.line))
            # Source code is never a rule list: `|| "https://api.openai.com"` continues an expression and
            # `host, err := ...` unpacks a result. Crawler user-agent values are blanked in place, so
            # domain_text keeps the original line structure the rule-list filter reads.
            skip = None if file.ext in SOURCE_EXTENSIONS else HostLineFilter(content_text)
            domain_text, ua_text = _crawler_ua_text(content_text)
            for m in self.index.match_domains_in_text(
                domain_text, skip_line=skip, source=file.ext in SOURCE_EXTENSIONS
            ):
                self._record_content(file, m, self._lazy_excerpt(file, m.line))
            if ua_text:
                ua_hosts = [str(m.value) for m in self.index.match_domains_in_text(ua_text)]
                if ua_hosts:
                    self._note_ua_mentions(file.rel, ua_hosts)
            # A deployment or CI document is configuration however many products it names.
            parsed = None if file.structure is _NO_STRUCTURE else file.structure
            variable_names = {m.value for m in variables}
            if configuration_document(
                file.rel, content_text, parsed, variable_names, file.proj_root, limits=catalog_limits
            ):
                file.proj.configuration_files.add(file.rel)
        if file.ext in LOADER_EXTENSIONS:
            # A data file that code loads by name is configuration, not a catalog.
            limits: list[str] = []
            file.proj.referenced_data_files.update(referenced_data_files(content_text, limits=limits))
            if limits:
                file.proj.reference_limits.append((file.rel, limits))
        self._file_errors(file.rel, catalog_limits)

    def _defer_reexport_source(self, scan: _ScanState, source: _MatchedSource) -> bool:
        """Keep only eligible root-level Python consumers, within a fixed memory budget."""
        file = source.file
        if file.ext != ".py" or len(project_path(file.proj_root, file.rel).parts) != 1:
            return False
        scan.reexports.add(file.proj_root, file.rel, file.text)
        local = _local_module_predicate(scan.root, file.path, file.proj_root)
        if not has_local_import(file.text, local):
            return False
        size = len(file.text.encode("utf-8"))
        if len(scan.reexport_files) >= MAX_PENDING_FILES or scan.reexport_bytes + size > MAX_PENDING_BYTES:
            self.ctx.error(f"code.filesystem: {file.rel}: Python re-export source budget exceeded")
            return False
        scan.reexport_files.append(source)
        scan.reexport_bytes += size
        file.reexport_pending = True
        return True

    def _match_source(self, root: Path, file: _SourceFile, content_text: str) -> _MatchedSource:
        """Match the imports and code patterns of a source file, recording the imports."""
        lang, ext = file.lang, file.ext
        is_local_module = _local_module_predicate(root, file.path, file.proj_root)
        # Malformed trailing literals are masked through EOF;
        # preceding valid imports/code remain inspectable. A notebook's
        # cells run one at a time, so each is lexed on its own: a literal
        # left open in one cell masks the rest of that cell only.
        if file.cells:
            ignored, ambiguous = _cell_noncode_ranges(content_text, file.cells)
        else:
            # JSX in plain .js/.mjs/.cjs (Docusaurus, CRA) is tried by
            # noncode_ranges when the plain walk is ambiguous: in a script,
            # `yield <a> 1` and `mask<<shift>limit` are comparisons that a
            # JSX walk from the start would read as elements.
            jsx = ext in {".jsx", ".tsx"}
            ignored, ambiguous = noncode_ranges(content_text, lang, ext, jsx=jsx)
            if file.nul_text is not None:
                ignored, nul_ambiguous = nul_reading_ranges(
                    manifest_comment_projection(file.rel, file.nul_text), ignored, lang, ext, jsx=jsx
                )
                ambiguous = ambiguous or nul_ambiguous
        if ambiguous:
            self.ctx.error(f"code.filesystem: {file.rel}: incomplete source lexical analysis")
        literals = file.literals
        imports = self.index.match_imports(content_text, lang, ignore_spans=ignored, scan=literals)
        for m in imports:
            if lang == "python":
                imported = re.match(r"\s*(?:from|import)\s+([A-Za-z_]\w*(?:\.\w+)*)", m.value)
                if imported and is_local_module(imported.group(1)):
                    continue
            self._record_content(file, m, self._lazy_excerpt(file, m.line))
        code_matches = self.index.match_code(content_text, lang, ignore_spans=ignored, scan=literals)
        return _MatchedSource(file, content_text, ignored, is_local_module, imports, code_matches)

    def _bind_source(self, source: _MatchedSource, *, resolve_import: ImportResolver | None = None) -> None:
        """Add the import-bound calls of a matched source file and record its code evidence."""
        bound, unbound = self._bound_matches(
            source.file, source.text, source.ignored, source.is_local_module, resolve_import=resolve_import
        )
        file, content_text = source.file, source.text
        if self.agent_granularity == "source" and file.lang == "python" and file.ext == ".py" and not unbound:
            verified = {
                tuple(m.extra["bound_call_span"])
                for m in bound
                if m.extra.get("verified_agent") and m.extra.get("bound_call_span")
            }
            regions: dict[tuple[int, int], ToolRegions] = {}
            unresolved: list[tuple[int, int]] = []
            names = named_construction_spans(
                content_text,
                max_ast_nodes=self.max_ast_nodes,
                verified_spans=verified,
                tool_regions=regions,
                unresolved_regions=unresolved,
            )
            file.source_agent_regions = [
                (start, end, names[span])
                for span, region in regions.items()
                for start, end in (*region.bodies, *region.declarations)
            ]
            if any(
                m.extra.get("registered_tool_paths")
                or (m.extra.get("verified_agent") and not m.extra.get("bound_call_span"))
                for m in bound
            ):
                # Decorator registrations and dispatch loops are not source
                # identities; whatever tools they reach stay project evidence.
                unresolved = [(0, len(content_text))]
            file.project_tool_regions = unresolved
            for m in bound:
                span = m.extra.get("bound_call_span")
                if span is not None and tuple(span) in verified and tuple(span) in names:
                    m.extra["source_agent_binding"] = names[tuple(span)]
        self._record_source(source, bound, unbound)

    def _record_source(
        self,
        source: _MatchedSource,
        bound: list[Match],
        unbound: Sequence[tuple[int, int]],
    ) -> None:
        """Record a source file's code patterns, import-bound evidence and model identifiers."""
        file, imports, code_matches = source.file, source.imports, source.code_matches
        # Execution sinks describe a model-driven capability only
        # when this same file invokes a model, framework or
        # tool-calling protocol; elsewhere they are build tooling.
        file_uses_llm = any(
            m.signature.category in _LLM_CATEGORIES for m in (*imports, *code_matches, *bound)
        )
        self._record_code_matches(
            file,
            code_matches,
            file_uses_llm,
            bound,
            unbound=unbound,
            mcp_server_imported=any(
                m.signature_id == "protocol.mcp" and _MCP_SERVER_IMPORT_RE.search(m.value) for m in imports
            ),
        )
        for m in bound:
            # A call the binder resolved to its import establishes the library;
            # the flag tells emit-time corroboration (_uncorroborated_signatures)
            # it apart from a lexical match of the same pattern.
            recorded = replace(m, extra={**m.extra, "import_bound": True}) if m.signal.type == "code" else m
            self._record_content(file, recorded, self._lazy_excerpt(file, m.line))
        if any(m.signature_id == "protocol.mcp" for m in (*imports, *code_matches, *bound)):
            self._register_mcp_tools(file, source.ignored)
            self._record_mcp_server_constructions(file, code_matches, bound)
        # Model identifiers are read in string literals, not in the comments the lexer masked.
        self._scan_model_literals(file, source.text, _comment_spans(source.text, source.ignored), source=True)

    def _scan_model_literals(
        self,
        file: _SourceFile,
        content_text: str,
        comments: Sequence[tuple[int, int]],
        *,
        source: bool,
    ) -> None:
        """Record the model identifiers a source or configuration file names (medium weight).

        Quoted literals (and, in configuration, unquoted values after a
        model-ish key) that carry a vendor stem are handed to the anchored
        ``model`` signatures, as a whole and, for a route such as
        ``bedrock/anthropic.claude-...``, by their last path segment, so the
        route's provider and the model's vendor are both attributed. Comments
        are skipped where the lexer masked them. Each match is tagged
        ``model_literal`` (weight capped at emit time) and, outside source
        files, ``data_mention``: a model id in a data file names a model as a
        domain names a host, so it anchors nothing and keeps a pricing table a
        catalog. At most ``MAX_MODEL_LITERALS_PER_FILE`` literals with a
        vendor stem are read per pass (ordinary strings are skipped in the match
        iterator and do not count) and ``MAX_MODEL_MATCHES_PER_SIGNATURE``
        matches kept per signature; unread candidates leave coverage incomplete.
        """
        lowered_text = content_text.lower()
        if not any(stem in lowered_text for stem in _MODEL_STEMS):
            return
        starts = [start for start, _ in comments]
        ends = [end for _, end in comments]

        def in_comment(offset: int) -> bool:
            previous = bisect_right(starts, offset) - 1
            return previous >= 0 and offset < ends[previous]

        literals: list[tuple[int, str]] = []
        limited = False
        quoted = _finditer(
            _MODEL_QUOTED_RE,
            content_text,
            "model identifiers",
            MAX_MODEL_LITERALS_PER_FILE + 1,
            in_comment if starts else None,
            lambda m: _has_model_stem(m.group(2)),
        )
        limited = len(quoted) > MAX_MODEL_LITERALS_PER_FILE
        literals.extend((m.start(2), m.group(2)) for m in quoted[:MAX_MODEL_LITERALS_PER_FILE])
        if not source:
            keyed = _finditer(
                _MODEL_KEY_VALUE_RE,
                content_text,
                "model identifiers",
                MAX_MODEL_LITERALS_PER_FILE + 1,
                selected=lambda m: _has_model_stem(m.group(1)),
            )
            limited = limited or len(keyed) > MAX_MODEL_LITERALS_PER_FILE
            literals.extend((m.start(1), m.group(1)) for m in keyed[:MAX_MODEL_LITERALS_PER_FILE])
        if limited:
            self._gap(
                file.rel,
                f"code.filesystem: {file.rel}: model identifiers read from the first "
                f"{MAX_MODEL_LITERALS_PER_FILE} literals only; later ones were not matched",
                suffix=False,
            )
        literals.sort()
        line_at = line_counter(content_text)
        kept: dict[str, int] = {}
        seen: set[tuple[str, str]] = set()
        for offset, value in literals:
            lowered = value.lower()
            candidates = [value]
            if "/" in value and lowered.startswith(_MODEL_ROUTE_PREFIXES):
                tail = value.rsplit("/", 1)[-1]
                if _model_lookalike(tail.lower()):
                    continue  # a route to a tool is no more a model than the tool
                if len(tail) >= 3:
                    candidates.append(tail)
            elif _model_lookalike(lowered):
                continue
            line = line_at(offset)
            for candidate in candidates:
                for m in self.index.match_model(candidate):
                    key = (m.signature_id, candidate)
                    if key in seen or kept.get(m.signature_id, 0) >= MAX_MODEL_MATCHES_PER_SIGNATURE:
                        continue
                    seen.add(key)
                    kept[m.signature_id] = kept.get(m.signature_id, 0) + 1
                    m.line = line
                    m.value = candidate  # the whole id, not the family prefix the pattern matched
                    m.extra["model_literal"] = True
                    if not source:
                        m.extra["data_mention"] = True
                    self._record_content(file, m, self._lazy_excerpt(file, line))

    def _bound_matches(
        self,
        file: _SourceFile,
        content_text: str,
        ignored: list[tuple[int, int]],
        is_local_module: Callable[[str], bool],
        *,
        resolve_import: ImportResolver | None = None,
    ) -> tuple[list[Match], list[tuple[int, int]]]:
        """Return bound evidence, including narrow Java, Go and C# proofs.

        Also returns the spans of ``content_text`` the Python or JavaScript
        binder did not read, where the lexical evidence stands in for it: the
        whole file when the binder did not run (a budget, or a source that does
        not parse), or a notebook's cells that do not parse.
        """
        lang = file.lang
        if file.ext == ".java":
            return spring_tool_registration_matches(self.index, content_text, ignored), []
        if lang == "go":
            return langchaingo_agent_matches(self.index, content_text, ignored), []
        if file.ext == ".cs":
            return microsoft_tool_loop_matches(self.index, content_text, ignored), []
        if lang not in {"python", "javascript"}:
            return [], []
        whole = [(0, len(content_text))]
        file.unparsed = ()
        truncated: list[int] = []
        unparsed: list[int] = []
        try:
            source = content_text
            if file.cells:
                # Jupyter runs the cells one at a time: one that does not parse
                # fails alone, so the binder reads the others without it. A cell
                # declared another language is bound when it parses as Python;
                # when it does not, it is lexical evidence only, without a gap.
                source, unparsed, unread = _notebook_binder_source(content_text, file.cells, file.foreign)
                file.unparsed = tuple(unread)
                if unparsed:
                    # Report before binding the other cells: a later AST
                    # budget failure must not erase this syntax coverage gap.
                    numbers = ", ".join(str(number + 1) for number in unparsed[:10])
                    cells = "cell" if len(unparsed) == 1 else "cells"
                    verb = "does" if len(unparsed) == 1 else "do"
                    self._syntax_warning(
                        file,
                        f"code.filesystem: {file.rel}: import-bound analysis skipped for notebook "
                        f"{cells} {numbers}, which {verb} not parse; lexical evidence retained",
                    )
            bound = bound_source_matches(
                self.index,
                source,
                lang,
                ignored,
                is_local_module=is_local_module if lang == "python" else None,
                max_ast_nodes=self.max_ast_nodes,
                truncated=truncated,
                resolve_import=resolve_import,
                cells=file.cells,
            )
        except SourceBudgetExceeded as exc:
            # The budget is a property of the file, not of
            # the scan: keep its lexical evidence. Test code
            # is discounted evidence, so it only warns.
            message = (
                f"code.filesystem: {file.rel}: import-bound analysis skipped ({exc}); "
                "lexical evidence retained"
            )
            if not self.include_tests and _is_test_path(file.rel):
                self.ctx.warn(message, incomplete=self.strict_coverage)
            else:
                self.ctx.error(message)
            return [], whole
        except SourceNotParsed as exc:
            # Newer syntax than the interpreter knows, or invalid source: no
            # import binding. Lexical observations stay visible, but cannot
            # replace the missing proof of agent behavior or capabilities.
            file.unparsed = tuple(whole)
            self._syntax_warning(
                file,
                f"code.filesystem: {file.rel}: import-bound analysis skipped ({exc}); "
                "lexical evidence retained",
            )
            return [], whole
        if truncated:
            # An option past the limit (tools, a stop condition) was not read: the
            # call-analysis budget is a coverage gap like the one above, but the
            # file's bound evidence, these calls' included, is kept.
            lines = ", ".join(str(line) for line in truncated[:10])
            message = (
                f"code.filesystem: {file.rel}: import-bound call at line {lines} analyzed from its first "
                f"{MAX_CALL_TEXT} characters; options after them were not read, so coverage is incomplete"
            )
            if not self.include_tests and _is_test_path(file.rel):
                self.ctx.warn(message, incomplete=self.strict_coverage)
            else:
                self.ctx.error(message)
        return bound, list(file.unparsed)

    def _syntax_warning(self, file: _SourceFile, message: str) -> None:
        """Record source that did not parse: a gap when ``_syntax_gap`` says so, else a plain warning.

        A gap goes through ``_gap``, so the ci profile declares it under a
        template, example or test path, and is counted as unparsed input.
        """
        if self._syntax_gap(file):
            self._gap(file.rel, message, suffix=False)
        else:
            self.ctx.warn(message, incomplete=False)

    def _syntax_gap(self, file: _SourceFile) -> bool:
        """Whether source that does not parse leaves coverage incomplete.

        It does, except in a test path the scan discounts (include_tests off), where a
        deliberately invalid fixture is common: there it only warns, unless strict_coverage
        is set, as for a source over the binder's budget.
        """
        return self.strict_coverage or self.include_tests or not _is_test_path(file.rel)

    def _record_code_matches(
        self,
        file: _SourceFile,
        code_matches: list[Match],
        file_uses_llm: bool,
        bound: list[Match],
        *,
        unbound: Sequence[tuple[int, int]] = (),
        mcp_server_imported: bool = False,
    ) -> None:
        # The binder's evidence for a signal on a line replaces its lexical match.
        bound_signals = {(m.signature_id, id(m.signal), m.line) for m in bound}
        # So does an import-bound MCP server construction for the server pattern of its line.
        construction_lines = {m.line for m in bound if "mcp_server_construction" in m.extra}
        configured_spans = {
            m.extra["configured_call_span"] for m in bound if "configured_call_span" in m.extra
        }
        genkit_spans = {
            m.extra["configured_call_span"]
            for m in bound
            if m.signature_id == "framework.genkit" and "configured_call_span" in m.extra
        }
        tool_regions = [span for match in bound for span in match.extra.get("registered_tool_regions", ())]
        tool_declarations = [
            span for match in bound for span in match.extra.get("registered_tool_declarations", ())
        ]
        for m in code_matches:
            if m.signature_id in _COLOCATED_SIGNATURES and not file_uses_llm:
                continue
            if _within(m.extra.get("start", -1), file.unparsed):
                # An import/dependency corroborates a library name, not the
                # semantics of code this interpreter could not parse. Keep
                # every lexical observation without promoting an agent,
                # claiming workload capabilities or constructing an MCP server.
                m.extra.update(
                    lexical_source=file.lang,
                    verified_agent=False,
                    source_capabilities=[],
                    source_unparsed=True,
                )
                if m.signature_id == "protocol.mcp":
                    m.extra["mcp_construction_unbound"] = True
                self._record_content(file, m, self._lazy_excerpt(file, m.line))
                continue
            if file.lang not in {"python", "javascript"}:
                # Lexical candidates in these languages need
                # corroborating library evidence at emit time;
                # narrow import proofs are recorded separately.
                m.extra["lexical_source"] = file.lang
                if file.ext == ".cs" and m.signature_id == "heuristic.tool-use":
                    # A local collection called tools is not registered model
                    # dispatch, and may be cleared or disabled before use.
                    # Keep the idiom for review; the C# loop proof owns the
                    # active capability rather than this declaration's name.
                    m.extra["contextual_capabilities"] = m.capabilities()
                if (file.lang == "go" and m.signature_id == "framework.langchaingo") or (
                    file.ext == ".cs"
                    and m.signature_id == "framework.microsoft-extensions-ai"
                    and not m.signal.agent_indicator
                ):
                    # These languages have narrow import/receiver proofs.
                    # A package elsewhere in the project does not bind this
                    # receiver; defining a function tool does not configure a
                    # model-directed loop. Retain the lexical candidate only.
                    # Function invocation middleware does configure that loop
                    # and stays a corroborated lexical indicator.
                    m.extra["verified_agent"] = False
                    m.extra["source_capabilities"] = []
            elif m.signature.category != "framework":
                if m.signature_id == "protocol.mcp" and "mcp-server" in m.signal.capabilities:
                    if m.line in construction_lines:
                        continue  # the bound construction is the evidence of this line
                    if (
                        not m.signal.ambiguous
                        and not mcp_server_imported
                        and not _MCP_REGISTRATION_RE.search(m.value)
                        and not any(pattern.search(m.value) for _, pattern in _MCP_TRANSPORTS)
                    ):
                        # ``FastMCP(`` or ``new McpServer(`` the binder did not
                        # resolve, in a file that imports no MCP server module:
                        # the class may be local. Evidence, but not a server.
                        m.extra["mcp_construction_unbound"] = True
                if m.signature_id in {
                    "heuristic.tool-use",
                    "heuristic.code-execution",
                    "heuristic.llm-command-execution",
                }:
                    connected = _within(m.extra.get("start", -1), (*tool_regions, *tool_declarations))
                    if not connected:
                        # A helper/decorator elsewhere in the project does not
                        # configure this agent. Keep it visible for review, but
                        # it cannot add workload capabilities or confidence.
                        m.extra["contextual_capabilities"] = m.capabilities()
                if m.signature_id == "heuristic.tool-use" and any(
                    start <= m.extra.get("start", -1) < end for start, end in genkit_spans
                ):
                    continue  # Genkit declarations/options alone do not establish model tool dispatch
                if (
                    m.signature_id in {"heuristic.tool-use", "heuristic.memory"}
                    and re.match(r"(?:tools|checkpointer)\s*[=:]", m.value)
                    and any(start <= m.extra.get("start", -1) < end for start, end in configured_spans)
                ):
                    # The parsed call owns these option values. A raw keyword
                    # match must not turn empty, disabled or unknown options
                    # into capabilities. Independent tool/memory calls remain.
                    continue
                if m.signature_id == "heuristic.tool-use" and re.fullmatch(
                    r"tools\s*=\s*(?:None|False)\s*", m.value
                ):
                    continue  # explicit disabled options do not register tools
                if m.signature_id == "heuristic.tool-use" and re.match(r"tools\s*[=:]", m.value):
                    # A declaration outside a request is still only a lexical
                    # option name. Bound configuration and registered tools
                    # establish the workload capability from its actual value.
                    m.extra["source_capabilities"] = []
                if m.signature_id in {
                    "protocol.openai-function-calling",
                    "heuristic.function-call-branch",
                    "heuristic.named-tool-lookup",
                    "heuristic.function-call-result",
                }:
                    # Field/response names also occur with empty, disabled or
                    # unknown tool settings. Bound requests and connected
                    # dispatch own the observed capability; lexical protocol
                    # syntax remains supporting, potential evidence.
                    m.extra["source_capabilities"] = []
                m.extra["verified_agent"] = False
                if m.signature_id in {
                    "heuristic.tool-use",
                    "heuristic.code-execution",
                    "heuristic.llm-command-execution",
                }:
                    bindings = {
                        binding
                        for start, end, binding in file.source_agent_regions
                        if start <= m.extra.get("start", -1) < end
                    }
                    if bindings:
                        m.extra["source_agent_bindings"] = sorted(bindings)
                        if _within(m.extra.get("start", -1), file.project_tool_regions):
                            # A construction left in the project may run this
                            # tool too: its findings keep the capability as well.
                            m.extra["source_agent_shared"] = True
            elif (m.signature_id, id(m.signal), m.line) in bound_signals or (
                _bundled_signature(m.signature) and not _within(m.extra.get("start", -1), unbound)
            ):
                continue  # import-bound calls establish the library
            else:
                # The bundled framework patterns are written for the import
                # binder. A custom pack's pattern is plain lexical evidence,
                # as in other languages, so a pack without a matching import
                # still takes effect, corroborated at emit time. So is every
                # framework pattern in source the binder could not read.
                m.extra["lexical_source"] = file.lang
            self._record_content(file, m, self._lazy_excerpt(file, m.line))

    def _register_mcp_tools(self, file: _SourceFile, ignored: list[tuple[int, int]]) -> None:
        """Remember the MCP tool names a source file registers, bounded per project."""
        if file.unparsed == ((0, len(file.text)),):
            return  # No independent tool-name pass may restore rejected source semantics.
        text = _without_ipython_lines(file.text) if file.cells else file.text
        if file.unparsed:
            text = _without_source_ranges(text, file.unparsed)
        tools = file.proj.mcp_tools
        try:
            names = mcp_tool_names(
                text,
                file.lang,
                ignored=ignored,
                max_ast_nodes=self.max_ast_nodes,
                require_mcp_binding=True,
            )
        except MCPToolLimitError as exc:
            self.ctx.error(f"code.filesystem: {file.rel}: {exc}; tool analysis incomplete")
            names = exc.names
        for tool in names:
            known = tools.get(tool)
            if known is None:
                if len(tools) < _MAX_MCP_TOOLS:
                    tools[tool] = file.rel
                elif not file.proj.mcp_tools_limited:
                    file.proj.mcp_tools_limited = True
                    self.ctx.error(
                        f"code.filesystem: {file.rel}: project MCP tool-name limit exceeded; "
                        "tool analysis incomplete"
                    )
            elif _is_test_path(known) and not _is_test_path(file.rel):
                tools[tool] = file.rel  # prefer where deployed code registers it

    def _record_mcp_server_constructions(
        self, file: _SourceFile, code_matches: list[Match], bound: list[Match]
    ) -> None:
        """Remember where a source file constructs an MCP server, bounded per project.

        Only recorded evidence counts (a lexical match the bound construction of
        its line replaced is not listed twice), and only constructions: tool
        registrations, transports and ``run`` calls carry the same capability but
        describe the server, not where it is built. The ambiguous ``Server(``
        pattern is listed only through its import binding, and a lexical
        construction in a Python or JavaScript file without the SDK's server
        import is not listed (see ``_record_code_matches``).
        """
        proj = file.proj
        constructions: dict[tuple[int, str], Match] = {}
        for m in (*bound, *code_matches):
            if (
                m.signature_id != "protocol.mcp"
                or m.signal.type != "code"
                or "mcp-server" not in m.signal.capabilities
                or m.signal.ambiguous
                or m.extra.get("mcp_construction_unbound")
                or (m.signature_id, id(m.signal), m.value, file.rel, m.line) not in proj.seen
            ):
                continue
            if "mcp_server_construction" not in m.extra and (
                _MCP_REGISTRATION_RE.search(m.value)
                or any(pattern.search(m.value) for _, pattern in _MCP_TRANSPORTS)
            ):
                continue
            # The binder and the lexical pass observe one transport call alike.
            constructions.setdefault((m.line or 0, m.value), m)
        for (line, _), m in sorted(constructions.items()):
            if len(proj.mcp_server_constructions) >= _MAX_MCP_SERVER_CONSTRUCTIONS:
                proj.mcp_server_constructions_limited = True
                return
            proj.mcp_server_constructions.append(
                {
                    "file": file.rel,
                    "line": line,
                    "construct": m.value,
                    "language": file.lang,
                    "bound": "mcp_server_construction" in m.extra,
                }
            )

    def _scan_config(self, scan: _ScanState, file: _SourceFile, content_text: str) -> None:
        """Match recognized configuration shapes and collect the model nodes of exported workflows."""
        if file.is_mcp:
            # MCP configs are structured data. A disabled server may
            # contain sample commands that look like agent code; only
            # the parsed protocol marker (see _detect_mcp) is relevant.
            return
        rel = file.rel
        config_errors: list[str] = []
        config_limits: list[str] = []
        document = (
            self._parsed_document(file, (".json", ".jsonc", ".toml", *_YAML_SUFFIXES))
            if content_text is file.text
            else None
        )
        structured = structured_code_matches(
            self.index,
            rel,
            content_text,
            errors=config_errors,
            limit_errors=config_limits,
            documents=None if document is None else [document],
        )
        # Unknown content, not a syntax error: fail closed.
        self._file_errors(rel, config_limits)
        for issue in config_errors:
            if is_agent_config_path(rel):
                self.ctx.error(f"code.filesystem: {rel}: {issue}")
            else:
                # Only the structured projection is lost; the
                # lexical env and domain passes still read this text.
                self.ctx.warn(
                    f"code.filesystem: {rel}: {issue}; structured checks skipped",
                    incomplete=self.strict_coverage,
                )
        for m in structured:
            # A recognised configuration shape declares the product by name.
            m.extra["config_projection"] = True
            self._record_content(file, m, None)
            category = m.signature.category
            agent_platform = category in {"platform", "cloud-service"} and m.agent_indicator
            if agent_platform and file.ext in _WORKFLOW_EXTENSIONS:
                scan.workflow_files.setdefault(rel, []).append((m, ""))
            elif category == "provider" and m.extra.get("structured_config"):
                scan.workflow_providers.setdefault(rel, []).append((m, ""))

    def _record_special_files(self, scan: _ScanState, file: _SourceFile) -> None:
        """Queue MCP configurations and agent manifests for their findings; keep agent definitions."""
        rel = file.rel
        if file.mcp_active:
            scan.mcp_files.append((rel, file.mcp_servers))
        if file.card_kind and (file.card_valid or file.card_incomplete):
            if len(scan.card_files) >= _MAX_CARD_FILES:
                self.ctx.error(
                    f"code.filesystem: {rel}: agent manifest limit ({_MAX_CARD_FILES}) reached; "
                    "manifest skipped"
                )
            else:
                scan.card_files.append((rel, file.text, file.card_kind, file.proj_root))
        if file.ext in {".md", ".mdc"} and any(directory in rel for directory in _AGENT_DEFINITION_DIRS):
            if len(file.proj.agent_defs) >= _MAX_AGENT_DEFINITIONS:
                self.ctx.error(
                    f"code.filesystem: {rel}: agent definition limit ({_MAX_AGENT_DEFINITIONS}) reached; "
                    "definition skipped"
                )
            else:
                file.proj.agent_defs.append(self._parse_agent_definition(rel, file.text))

    # ------------------------------------------------------------------ emit
    def _emit_findings(self, scan: _ScanState) -> Iterator[Finding]:
        """Yield the findings of one walk; a failure is isolated to its own file or project."""
        label, root = scan.label, scan.root
        yield from scan.inventory_findings
        # Project findings are held back until the manifests are read: a
        # manifest inside a reported project describes that project's agent
        # and is folded into its finding instead of counting it twice.
        project_findings: dict[str, Finding] = {}
        yield from self._emit_projects(scan, project_findings)
        for rel, servers in scan.mcp_files:
            with self._isolated(rel, "MCP analysis"), self.index.scan_budget(seconds=self.scan_timeout):
                yield self._mcp_finding(label, root, rel, servers)
        yield from self._emit_manifests(scan, project_findings)
        yield from project_findings.values()
        for rel, hits in scan.workflow_files.items():
            with self._isolated(rel, "workflow analysis"):
                yield self._workflow_finding(label, root, rel, [*hits, *scan.workflow_providers.get(rel, [])])
        for rel, infra_hits in scan.infra_files.items():
            with self._isolated(rel, "infrastructure analysis"):
                yield self._infra_finding(
                    label,
                    root,
                    rel,
                    infra_hits,
                    scan.infra_names.get(rel, []),
                    wildcards=scan.iam_wildcards.get(scan.infra_project.get(rel, ""), []),
                    models=scan.infra_models.get(rel, []),
                )
        for rel, hits in scan.secret_hits.items():
            with self._isolated(rel, "credential analysis"):
                project_root = scan.secret_project.get(rel, ".")
                f = self._secret_finding(label, root, rel, hits, project_root=project_root)
                if f:
                    yield f

    def _emit_projects(self, scan: _ScanState, project_findings: dict[str, Finding]) -> Iterator[Finding]:
        """Yield coding-agent findings and hold each project finding in ``project_findings``."""
        # MCP configs, agent manifests, exported workflows and IaC produce their
        # own findings; a project finding built only from them is a duplicate.
        covered_files = scan.covered_files()
        for proj in scan.projects.values():
            with self._isolated(proj.root, "project analysis"):
                for finding in self._emit_project(scan.label, scan.root, proj, covered_files):
                    if finding.resource_type == "project":
                        project_findings[proj.root] = finding
                    else:
                        yield finding

    def _emit_manifests(self, scan: _ScanState, project_findings: dict[str, Finding]) -> Iterator[Finding]:
        """Yield agent manifest findings; a project manifest is folded into its project's finding."""
        for rel, text, kind, proj_root in scan.card_files:
            with (
                self._isolated(rel, "agent manifest analysis"),
                self.index.scan_budget(seconds=self.scan_timeout),
            ):
                f = self._card_finding(scan.label, scan.root, rel, text, kind)
                if f is None:
                    continue
                owner = project_findings.get(proj_root) if kind in _PROJECT_MANIFESTS else None
                if owner is None:
                    yield f
                else:
                    self._fold_manifest(owner, f, scan.projects[proj_root])

    # --------------------------------------------------------------- helpers
    def _record_example_credential(self, proj: _Project, m: Match, rel: str, reason: str) -> None:
        """Remember a placeholder credential for informational project evidence."""
        key = (m.signature_id, id(m.signal), m.value, rel, m.line)
        if key in proj.seen:
            return
        proj.seen.add(key)
        proj.example_credentials.append((m, rel, reason))

    def _record(self, proj: _Project, m: Match, rel: str, snippet: _Snippet) -> None:
        if isinstance(snippet, str):
            snippet = sanitize_text(snippet)
        if m.signature.category == "identity-app":
            return  # identity-app signatures describe OAuth/SaaS apps, not code
        # A manifest artifact and the generic text pass can observe the same
        # token on the same line. Confidence combines evidence as independent
        # signals, so a duplicate observation must not count twice.
        # Distinct signals may attach different authority/capabilities to the
        # same text. Deduplicate repeated passes of the same signal only.
        key = (m.signature_id, id(m.signal), m.value, rel, m.line)
        if key in proj.seen:
            return
        proj.seen.add(key)
        if m.signature.category == "coding-agent":
            if (
                not self.include_tests
                and _is_test_path(rel)
                and m.signal.type != "file"
                and not _is_coding_agent_doc(PurePosixPath(rel).name)
            ):
                return
            proj.coding_agent_files.setdefault(m.signature_id, [])
            if rel not in proj.coding_agent_files[m.signature_id]:
                proj.coding_agent_files[m.signature_id].append(rel)
            proj.coding_agent_matches.setdefault(m.signature_id, []).append((m, rel, snippet))
            return
        proj.matches.append((m, rel, snippet))

    def _handle_artifact(
        self,
        proj: _Project,
        art: Artifact,
        rel: str,
        text: str,
        infra_files: dict[str, list[tuple[Match, str, str]]],
        secret_hits: dict[str, list[tuple[Match, str]]],
        infra_names: dict[str, list[str]] | None = None,
        *,
        image_scale: float = 1.0,
    ) -> None:
        """Record a manifest artifact: an image, variable, credential, IaC type, model, action or module.

        ``image_scale`` below 1.0 marks the file as a CI pipeline: its images
        run jobs rather than deploy services, so each image match is scaled,
        tagged ``ci_image`` (a mention that anchors no project finding) and
        produces no infrastructure finding.
        """
        infra_names = infra_names if infra_names is not None else {}
        if art.kind == "image":
            for m in self.index.match_image(art.value):
                m.line = art.line
                if image_scale < 1.0:
                    m.weight = m.weight * image_scale
                    m.extra["ci_image"] = True
                    self._record(proj, m, rel, f"image: {art.value}")
                    continue
                self._record(proj, m, rel, f"image: {art.value}")
                infra_files.setdefault(rel, []).append((m, art.value, f"image: {art.value}"))
        elif art.kind in {"env", "secret_ref"}:
            for m in self.index.match_env(art.value):
                m.line = art.line
                self._record(proj, m, rel, f"{art.kind}: {art.value}")
            val = art.extra.get("value") if art.extra else None
            if val and self.scan_secrets:
                for m in self.index.match_secrets(val):
                    m.line = art.line
                    # Judge the matched credential, not the whole assignment:
                    # a trailing comment must not hide a real key.
                    reason = placeholder_reason(m.value)
                    if reason:
                        self._record_example_credential(proj, m, rel, reason)
                        continue
                    secret_hits.setdefault(rel, []).append((m, f"{art.value}={redact(m.value)}"))
                    self._record(proj, m, rel, None)
        elif art.kind == "iac":
            for m in self.index.match_iac(art.value):
                m.line = art.line
                self._record(proj, m, rel, f"resource: {art.value}")
                label = f"resource {art.value} {art.extra.get('name', '')}".strip()
                if art.extra.get("display_name"):
                    label += f" ({art.extra['display_name']})"
                infra_files.setdefault(rel, []).append((m, art.value, label))
                names = infra_names.setdefault(rel, [])
                for n in (art.extra.get("display_name"), art.extra.get("name")):
                    if n and n not in names:
                        names.append(n)
        elif art.kind == "model":
            for m in self.index.match_model(art.value):
                m.line = art.line
                m.extra["manifest_artifact"] = True  # a model the manifest selects, not a literal
                self._record(proj, m, rel, f"model: {art.value}")
        elif art.kind == "action":
            for m in self.index.match_code(f"uses: {art.value}"):
                m.line = art.line
                m.extra["manifest_artifact"] = True
                self._record(proj, m, rel, f"uses: {art.value}")
        elif art.kind == "module":
            for m in self.index.match_domains_in_text(art.value):
                m.line = art.line
                self._record(proj, m, rel, f"module: {art.value}")

    @staticmethod
    def _looks_like_mcp_config(rel: str, name: str, text: str, document: Any = None) -> bool:
        """Whether a file is an MCP client or registry configuration; ``document`` is its parse if held."""
        lower = name.lower()
        # Cookiecutter template paths and compiled agentic-workflow lock files are
        # not client configuration. Other GitHub Actions workflows are parsed for
        # MCP servers embedded in step inputs (see _embedded_workflow_mcp).
        if "{{" in rel or lower.endswith((".lock.yml", ".lock.yaml")):
            return False
        if lower == "server.json":
            # A generic service can use this filename. The MCP registry format
            # has a name and structured package or remote transport records.
            if document is not None:
                data = document
            else:
                try:
                    data = _load_json_lenient(text)
                except (ValueError, RecursionError):
                    return False
            if not isinstance(data, dict):
                return False
            explicit = data.get("mcpServers", data.get("mcp_servers"))
            if isinstance(explicit, dict) and bool(explicit):
                return True
            if not isinstance(data.get("name"), str) or not data["name"].strip():
                return False
            packages = data.get("packages")
            remotes = data.get("remotes")
            return (
                isinstance(packages, list)
                and any(
                    isinstance(p, dict)
                    and isinstance(p.get("registryType"), str)
                    and isinstance(p.get("identifier"), str)
                    and p["identifier"].strip()
                    for p in packages
                )
                or isinstance(remotes, list)
                and any(
                    isinstance(r, dict)
                    and isinstance(r.get("url"), str)
                    and r["url"].startswith(("https://", "http://"))
                    and r.get("type") in {"streamable-http", "sse"}
                    for r in remotes
                )
            )
        if lower in _DEDICATED_MCP_CONFIG_NAMES:
            return True
        if lower in MCP_CONFIG_NAMES or rel.endswith((".json", ".toml", ".yaml", ".yml")):
            # Decide from the parsed structure when it is held (JSON/TOML): leading
            # padding before the keys then cannot hide a server table. A JSON object
            # must be decided structurally; the text fallback below never sees past
            # its truncation, so a string search of a prefix could miss the keys.
            if isinstance(document, dict):
                return _document_declares_mcp(document)
            # No parse is held for YAML here. Substring and anchored searches are linear,
            # so read the whole (size-bounded) text rather than a prefix a server can be pushed past.
            return (
                '"mcpServers"' in text
                or '"mcp_servers"' in text
                or "mcpServers:" in text
                or "mcp_servers:" in text
                or "[mcp_servers." in text
                or re.search(r"(?m)^[ \t]*\[mcp_servers\][ \t]*(?:#.*)?$", text) is not None
                or re.search(r"(?m)^[ \t]*mcp_servers\.[A-Za-z0-9_-]+[ \t]*=", text) is not None
                or ('"mcp"' in text and '"servers"' in text)
                or ("mcp:" in text and "servers:" in text)
            )
        return False

    # ----------------------------------------------------------------- emits
    def _base(
        self,
        label: str,
        root: Path,
        rel: str,
        kind: Kind,
        title: str,
        resource_type: str,
        *,
        identity_discriminator: str = "",
    ) -> Finding:
        f = Finding(
            surface=Surface.CODE,
            connector=self.name,
            kind=kind,
            title=title,
            resource=f"{label}/{rel}" if rel != "." else label,
            resource_type=resource_type,
            identity_discriminator=identity_discriminator,
            provider=self.provider_override or self.provider,
            account=self.account,
            owner=self.owner,
        )
        f.metadata.update(self.extra_metadata)
        f.metadata["path"] = rel
        f.metadata["scan_root"] = str(root)
        return f

    def _emit_project(
        self,
        label: str,
        root: Path,
        proj: _Project,
        covered_files: frozenset[str] = frozenset(),
    ) -> Iterator[Finding]:
        catalogs = project_catalog_files(proj, proj.configuration_files, proj.referenced_data_files)
        if proj.reference_limits and references_could_change(catalogs):
            # An unread reference could have named a data file discounted here.
            for rel, issues in proj.reference_limits:
                self._file_errors(rel, issues)
        observations = self._project_observations(proj, catalogs)
        # Evidence held back only because it sits in a catalog is listed in the
        # project finding (catalog_mentions) or, without one, in a scan note.
        reported = self._anchored(observations, covered_files)
        if reported:
            if self.agent_granularity == "source":
                groups: dict[tuple[str, str], list[_Observation]] = {}
                remaining: list[_Observation] = []
                for observation in observations:
                    match, rel, _ = observation
                    bindings = match.extra.get("source_agent_bindings") or (
                        [match.extra["source_agent_binding"]]
                        if match.extra.get("source_agent_binding")
                        else []
                    )
                    if bindings and rel not in covered_files:
                        for binding in bindings:
                            groups.setdefault((rel, binding), []).append(observation)
                        if match.extra.get("source_agent_shared"):
                            remaining.append(observation)
                    else:
                        remaining.append(observation)
                for (rel, binding), source_observations in sorted(groups.items()):
                    yield self._source_agent_finding(label, root, proj, rel, binding, source_observations)
                observations = remaining
            yield self._project_finding(label, root, proj, observations)
        discounted = (
            bool(catalogs)
            and not reported
            and self._anchored(self._project_observations(proj, frozenset()), covered_files)
        )
        unanchored = not reported and not discounted
        for sig_id, files in proj.coding_agent_files.items():
            # Env-name and display-name mentions (GOOSE_PROVIDER in a detector
            # matrix, "GitHub Copilot" in an SDK adapter) are not configuration.
            # Config files, instruction docs, dependencies and code such as a
            # workflow step or a YOLO-mode flag still establish the agent. A
            # catalog (an allowlist of vendor hosts) establishes none.
            establishing = [
                rel
                for m, rel, _ in proj.coding_agent_matches.get(sig_id, [])
                if m.signal.type not in _MENTION_SIGNALS or _is_coding_agent_doc(PurePosixPath(rel).name)
            ]
            if all(rel in catalogs for rel in establishing):
                discounted = discounted or (bool(establishing) and not reported)
                continue
            yield self._coding_agent_finding(label, root, proj, sig_id, files)
        if discounted:
            self._note_discounted_catalogs(label, proj, catalogs)
        elif unanchored:
            self._note_unanchored(label, proj, observations, covered_files)

    def _anchored(self, observations: list[_Observation], covered_files: frozenset[str]) -> bool:
        """Whether ``observations`` establish a project finding.

        Anchors establish LLM / agent technology on their own. A credential
        alone is already a SECRET finding, evidence that an MCP, manifest,
        workflow or IaC finding already reports is not a project anchor, and
        a vendor-neutral heuristic alone (a retry loop, subprocess.run)
        describes ordinary automation. Nor does evidence that establishes no
        technology (``_ProjectEvidence.established``): a code pattern without
        the library's import or dependency anywhere in the project, or a
        signature known only from mentions below ``WEAK_MENTION_WEIGHT``. A
        mention (a host, a variable, a display name, a model id in a data
        file, a CI job image) anchors only outside test paths, unless test
        code is included: ``huggingface.co`` inside ``test/data/*.json``
        describes a fixture, not a deployment.
        """
        discount = not self.include_tests

        def in_tests(rel: str) -> bool:
            return discount and _is_test_path(rel)

        uncorroborated = _uncorroborated_signatures(observations, in_tests)
        weak = _weak_mention_signatures(observations, in_tests)
        return any(
            m.signature.category != "heuristic"
            and rel not in covered_files
            and m.signal.type != "secret"
            and m.signature_id not in uncorroborated
            and m.signature_id not in weak
            and not m.extra.get("data_mention")
            and not m.extra.get("ci_image")
            and not (discount and _is_test_path(rel) and (_mention(m) or m.extra.get("model_literal")))
            for m, rel, _ in observations
        )

    def _note_unanchored(
        self,
        label: str,
        proj: _Project,
        observations: list[_Observation],
        covered_files: frozenset[str],
    ) -> None:
        """Name the files whose evidence establishes no technology on its own; never drop it silently.

        A note, not a coverage gap: every file was read and matched. Nothing is
        said for a project whose evidence is heuristics or credentials alone,
        which have their own handling.
        """
        files = sorted(
            {
                rel
                for m, rel, _ in observations
                if m.signature.category != "heuristic"
                and m.signal.type != "secret"
                and rel not in covered_files
            }
        )
        if not files:
            return
        names = ", ".join(files[:5]) + (f" and {len(files) - 5} more" if len(files) > 5 else "")
        where = "repository root" if proj.root == "." else proj.root
        self.ctx.warn(
            f"code.filesystem: {self._root_prefix(label)}{where}: evidence not reported because nothing in "
            "the project establishes a technology on its own (a code pattern without the library's import or "
            "dependency, a host, variable or model id mentioned in test data or a data file, a CI job image, "
            f"or a mention below weight {WEAK_MENTION_WEIGHT}): {names}; review them if the project uses "
            "these products",
            incomplete=False,
        )

    def _note_ua_mentions(self, rel: str, hosts: list[str]) -> None:
        """Name the provider hosts a user-agent string mentioned; never drop them silently.

        A note, not a coverage gap: the file was read and matched, and the
        mention identifies a crawler's operator rather than provider use.
        """
        listed = sorted(set(hosts))
        names = ", ".join(listed[:5]) + (f" and {len(listed) - 5} more" if len(listed) > 5 else "")
        self.ctx.warn(
            f"code.filesystem: {rel}: provider domains inside crawler user-agent strings were not "
            f"counted as usage: {names}; review them if this file configures a client",
            incomplete=False,
        )

    def _note_discounted_catalogs(self, label: str, proj: _Project, catalogs: frozenset[str]) -> None:
        """Name the catalogs that held evidence a project finding would have listed; never drop it silently.

        A shape cannot tell every configuration from a list, so the files are named
        for review. A note, not a coverage gap: every file was read and matched.
        """
        listed = sorted(catalogs)
        names = ", ".join(listed[:5]) + (f" and {len(listed) - 5} more" if len(listed) > 5 else "")
        where = "repository root" if proj.root == "." else proj.root
        reason = f"name {CATALOG_MIN_SIGNATURES} or more products"
        if any(deny_list_file(rel) for rel in listed):
            reason += " or are named as block or deny lists"
        self.ctx.warn(
            f"code.filesystem: {self._root_prefix(label)}{where}: evidence not reported because it is only "
            f"in catalog-like data files that {reason}, which nothing else in the project uses: {names}; "
            "review them if they configure a deployment",
            incomplete=False,
        )

    def _root_prefix(self, label: str) -> str:
        """Name the scan root in a diagnostic only when this connector scans several roots."""
        paths = self.ctx.get("paths")
        several = (isinstance(paths, list) and len(paths) > 1) or self.ctx.get("_shared_label_roots") is True
        return f"{label}: " if several else ""

    @staticmethod
    def _project_observations(proj: _Project, catalogs: frozenset[str]) -> list[_Observation]:
        """Return a project's technology evidence without policy, catalog or ambiguous-only matches."""
        observations = [
            (m, rel, snip) for (m, rel, snip) in proj.matches if m.signature.category not in {"policy"}
        ]
        # An ambiguous pattern is a common identifier outside the product
        # (aiohttp's ClientSession, a UI component named AgentCard). It counts
        # only when the same signature has library evidence in this project:
        # an import, a dependency or one of its specific code patterns.
        independent = {
            m.signature_id
            for m, _, _ in observations
            if m.signal.type in _LIBRARY_SIGNALS and not m.signal.ambiguous
        }
        if "provider.openai" in independent:
            # The OpenAI request shape (`.chat.completions.create(`) in a
            # project that installs or imports the OpenAI SDK describes that
            # SDK: it must not add an OpenAI-compatible endpoint as a second
            # provider. The shape still counts for a project whose only
            # library is a compatible server's base URL override.
            observations = [
                t
                for t in observations
                if not (
                    t[0].signature_id == "provider.openai-compatible"
                    and t[0].signal.type == "code"
                    and t[0].signal.ambiguous
                )
            ]
        # A catalog (a blocklist, a vendor policy, a copy of the signature
        # packs) names many products and uses none, so its mentions are held
        # to the same rule (see shadowscan.connectors.code.catalogs).
        return [
            t
            for t in observations
            if (not t[0].signal.ambiguous or t[0].signature_id in independent)
            and (t[1] not in catalogs or t[0].signature_id in independent)
        ]

    def _project_finding(
        self,
        label: str,
        root: Path,
        proj: _Project,
        observations: list[_Observation],
    ) -> Finding:
        """Build the finding that summarizes a project's frameworks, providers and capabilities."""
        evidence = _ProjectEvidence(
            observations,
            discount_tests=not self.include_tests,
            mcp_tools=proj.mcp_tools,
            project_root=proj.root,
        )
        f = self._base(label, root, proj.root, Kind.FRAMEWORK_USAGE, "", "project")
        if self.agent_granularity == "source":
            unresolved = {
                (rel, tuple(m.extra.get("bound_call_span", (m.line,))))
                for m, rel, _ in observations
                if evidence.verified_indicator(m) and m.signal.type in {"code", "file"}
            }
            f.metadata["source_identity"] = {
                "mode": "source",
                "scope": "unique named straight-line Python constructions",
                "unresolved_constructions": len(unresolved),
                "runtime_instances": "not-enumerated",
            }
        self._apply_project_evidence(f, evidence)
        if evidence.env_only:
            f.add_tag("env-names-only")
        elif evidence.model_ids_only:
            f.add_tag("model-ids-only")
        self._attach_example_credentials(f, proj)
        self._attach_project_metadata(f, root, proj, evidence)
        catalogs = project_catalog_files(proj, proj.configuration_files, proj.referenced_data_files)
        if catalogs:
            f.metadata["catalog_mentions"] = catalog_metadata(catalogs)
        if evidence.test_only:
            f.add_tag("test-code-only")
        if evidence.docs_only:
            f.add_tag("docs-only")
        if evidence.example_only:
            f.add_tag("example-code-only")
        if evidence.generated_only:
            f.add_tag("generated-code-only")
        if evidence.negative_contexts:
            reasons = sorted({ctx.reason for ctx in evidence.negative_contexts.values()})
            f.metadata["negative_contexts"] = reasons
        # 4a: Cross-signal corroboration — when independent signal types
        # (library + code, or 3+ types) corroborate each other, add a
        # small synthetic evidence item so the noisy-OR rewards diversity.
        if evidence.has_library_and_code or evidence.has_multi_signal:
            boost = 0.15 if evidence.has_multi_signal else 0.1
            # Every code observation has a source location. The synthetic item
            # points at one it summarizes: the code evidence that the library
            # evidence corroborates, else the first deployed observation.
            located = [
                item
                for item in f.evidence
                if item.location
                and item.attributes.get("category") != "heuristic"
                and not evidence.in_tests(_LOCATION_LINE.sub("", item.location))
            ]
            anchor = next((item for item in located if item.signal.startswith("code:")), None)
            if anchor is None and located:
                anchor = located[0]
            f.add_evidence(
                Evidence(
                    signal="corroboration:cross-signal",
                    description="Multiple independent signal types corroborate this finding",
                    location=anchor.location if anchor is not None else None,
                    weight=boost,
                    attributes={"confidence_group": "cross-signal-corroboration", "synthetic": True},
                )
            )
            f.metadata["cross_signal_corroboration"] = {
                "library_and_code": evidence.has_library_and_code,
                "multi_signal": evidence.has_multi_signal,
                "boost": boost,
            }
        finalize(f, self.index)
        if evidence.env_only:
            cap_confidence(f, ENV_ONLY_MAX_CONFIDENCE)
            f.metadata["confidence_cap"] = {"reason": "env-names-only", "maximum": ENV_ONLY_MAX_CONFIDENCE}
        elif evidence.model_ids_only:
            cap_confidence(f, MODEL_IDS_ONLY_MAX_CONFIDENCE)
            f.metadata["confidence_cap"] = {
                "reason": "model-ids-only",
                "maximum": MODEL_IDS_ONLY_MAX_CONFIDENCE,
            }
        lowest_cap: float | None = None
        cap_reason: str | None = None
        if evidence.docs_only:
            lowest_cap = DOCS_MAX_CONFIDENCE
            cap_reason = "docs-only"
        if evidence.example_only:
            c = EXAMPLE_PATH_MAX_CONFIDENCE
            if lowest_cap is None or c < lowest_cap:
                lowest_cap = c
                cap_reason = "example-code-only"
        if evidence.generated_only:
            c = GENERATED_MAX_CONFIDENCE
            if lowest_cap is None or c < lowest_cap:
                lowest_cap = c
                cap_reason = "generated-code-only"
        if lowest_cap is not None and cap_reason is not None:
            cap_confidence(f, lowest_cap)
            f.metadata.setdefault("confidence_cap", {})
            f.metadata["confidence_cap"] = {"reason": cap_reason, "maximum": lowest_cap}
        f.title = self._project_title(f, proj)
        return f

    def _source_agent_finding(
        self,
        label: str,
        root: Path,
        proj: _Project,
        rel: str,
        binding: str,
        observations: list[_Observation],
    ) -> Finding:
        """Inventory one static source binding without inheriting project capabilities."""
        evidence = _ProjectEvidence(
            observations, discount_tests=not self.include_tests, mcp_tools={}, project_root=proj.root
        )
        f = self._base(label, root, f"{rel}#agent:{binding}", Kind.FRAMEWORK_USAGE, "", "source-agent")
        self._apply_project_evidence(f, evidence)
        source_project = _Project(proj.root, files=1, languages={"python"})
        self._attach_project_metadata(f, root, source_project, evidence)
        f.metadata["path"] = rel
        f.metadata["project_resource"] = f"{label}/{proj.root}" if proj.root != "." else label
        f.metadata["source_identity"] = {
            "schema": "python-named-construction-v1",
            "binding": binding,
            "runtime_instances": "not-enumerated",
        }
        if evidence.test_only:
            f.add_tag("test-code-only")
        finalize(f, self.index)
        f.title = f"{'Agent' if f.kind == Kind.AGENT else 'Agent test construction'} in {rel}: {binding}"
        return f

    def _apply_project_evidence(self, f: Finding, evidence: _ProjectEvidence) -> None:
        # Decisive evidence must survive the per-signature report quota.
        decisive_first = sorted(evidence.matches, key=lambda item: not evidence.verified_indicator(item[0]))
        for m, rel, snip in decisive_first:
            if m.signature_id in evidence.uncorroborated:
                m.weight = min(m.weight, 0.6)
            if m.extra.get("model_literal"):
                m.weight = min(m.weight, MODEL_LITERAL_MAX_WEIGHT)
            observed = m.extra.get("source_capabilities")
            applied = (
                replace(m, signal=replace(m.signal, capabilities=observed)) if observed is not None else m
            )
            if "mcp-server" in applied.signal.capabilities and not evidence.server_implemented:
                # The capability follows the implemented server (see
                # mcp_server_evidence). A server idiom in a project without the
                # SDK anywhere (a Rust or Go source whose crate or module is not
                # declared), the ambiguous ``Server(`` class next to an MCP client
                # import, or an unbound ``McpServer(`` of a local class stays
                # evidence but does not establish one.
                applied = replace(
                    applied,
                    signal=replace(
                        applied.signal,
                        capabilities=[c for c in applied.signal.capabilities if c != "mcp-server"],
                    ),
                )
            contextual = bool(m.extra.get("contextual_capabilities"))
            if contextual:
                applied = replace(applied, weight=0.0)
            before = len(f.evidence)
            apply_matches(
                f,
                [applied],
                location=rel,
                snippet=snip,
                weight_scale=evidence.weight_scale(rel),
                capabilities=evidence.implies_capabilities(m, rel),
                signature_capabilities=observed is None
                and (evidence.verified_indicator(m) or m.signature.category != "framework"),
                establish=evidence.established(m.signature_id),
            )
            if contextual:
                for item in f.evidence[before:]:
                    item.attributes["capability_basis"] = "contextual-unlinked-source"
            if m.extra.get("source_unparsed"):
                for item in f.evidence[before:]:
                    item.attributes["source_analysis"] = "unparsed"
            neg_ctx = evidence.negative_contexts.get(rel)
            if neg_ctx is not None:
                for item in f.evidence[before:]:
                    item.attributes["negative_context"] = neg_ctx.reason
        if "protocol.mcp" in f.frameworks and evidence.server_tools:
            self._apply_mcp_tools(f, evidence.server_tools)
        contextual_capabilities = {
            cap
            for m, rel, _ in evidence.matches
            if m.extra.get("contextual_capabilities") and not evidence.in_tests(rel)
            for cap in m.extra["contextual_capabilities"]
        }
        if contextual_capabilities:
            f.metadata["contextual_capabilities"] = sorted(contextual_capabilities)
        potential = {cap for m, _, _ in evidence.matches for cap in m.capabilities()} - set(f.capabilities)
        if potential:
            f.metadata["potential_capabilities"] = sorted(potential)
        # Repeated observations of one technology are correlated evidence.
        # Generic idioms share a single supporting group; loops in several
        # worker files must never accumulate into a strong AI agent.
        for item in f.evidence:
            category = item.attributes.get("category")
            item.attributes["confidence_group"] = (
                "heuristic-support"
                if category == "heuristic"
                else "uncorroborated-lexical"
                if item.signature in evidence.uncorroborated
                else item.signature or item.signal
            )

    def _attach_project_metadata(
        self,
        f: Finding,
        root: Path,
        proj: _Project,
        evidence: _ProjectEvidence,
    ) -> None:
        """Record a project's owner, history, inventory and agent indicators."""
        matches = evidence.matches
        git = self.ownership.git_info(root, proj.root)
        f.metadata.update(git)
        if git.get("last_commit"):
            f.last_seen = git["last_commit"]
        f.owner, by_file = self.ownership.owners_for_files(root, (rel for _, rel, _ in matches))
        f.owner = f.owner or (git.get("last_author_email") if not by_file else None) or self.owner
        if by_file:
            f.metadata["codeowners_by_file"] = by_file
        f.metadata["files_scanned"] = proj.files
        f.metadata["languages"] = sorted(proj.languages)
        f.metadata["dependencies_matched"] = sorted(
            {
                f"{m.signal.ecosystem or 'any'}:{m.value}"
                for m, _, _ in matches
                if m.signal.type == "dependency"
            }
        )
        f.metadata["models"] = sorted({m.value for m, _, _ in matches if m.signal.type == "model"})
        f.models = f.metadata["models"]
        if proj.detection_rules:
            # Rule packs read as data, not as evidence (see rule_packs).
            f.metadata["detection_rule_files"] = {
                "count": sum(proj.detection_rules.values()),
                "formats": dict(sorted(proj.detection_rules.items())),
                "files": list(proj.detection_rule_files),
            }
        if proj.agent_defs:
            f.metadata["agent_definitions"] = proj.agent_defs
        if evidence.server_implemented:
            f.metadata["mcp_server"] = self._mcp_server_metadata(proj, evidence)
        # Installed SDKs, imports and endpoint strings establish framework
        # use. MCP code/config alone establishes a tool server/client, not
        # an agent capable of choosing actions or planning.
        f.metadata["agent_indicators"] = sum(
            evidence.verified_indicator(m)
            and m.signal.type in {"code", "file"}
            and not evidence.in_tests(rel)
            for m, rel, _ in matches
        )
        if any(
            m.extra.get("agent_classification") == "openai-responses-tool-dispatch"
            and evidence.verified_indicator(m)
            and not evidence.in_tests(rel)
            for m, rel, _ in matches
        ):
            f.metadata["agent_classification"] = "openai-responses-tool-dispatch"

    @staticmethod
    def _mcp_server_metadata(proj: _Project, evidence: _ProjectEvidence) -> dict[str, Any]:
        """Describe the MCP server a project implements: where it is built, in what, over which transports.

        Constructions in tests are left out unless the project is only tests
        (as for the tools it registers); the bound on the list is disclosed.
        """
        counted = [(m, rel) for m, rel, _ in evidence.matches if evidence.mcp_server_evidence(m, rel)]
        constructions = [
            c for c in proj.mcp_server_constructions if evidence.test_only or not evidence.in_tests(c["file"])
        ]
        languages = {c["language"] for c in constructions if c["language"]}
        languages.update(lang for _, rel in counted if (lang := language_for_path(rel)))
        transports = {
            transport for m, _ in counted for transport, pattern in _MCP_TRANSPORTS if pattern.search(m.value)
        }
        metadata: dict[str, Any] = {
            "constructions": constructions,
            "languages": sorted(languages),
            "transports": sorted(transports),
        }
        if proj.mcp_server_constructions_limited:
            metadata["constructions_limited"] = True
        return metadata

    def _coding_agent_finding(
        self,
        label: str,
        root: Path,
        proj: _Project,
        sig_id: str,
        files: list[str],
    ) -> Finding:
        """Build the finding for one coding-agent product configured in a project."""
        sig = self.index.get(sig_id)
        where = proj.root if proj.root != "." else "repository root"
        f = self._base(
            label,
            root,
            proj.root,
            Kind.AGENT_CONFIG,
            f"{sig.name if sig else sig_id} configured in {where}",
            "coding-agent-config",
            identity_discriminator=f"coding-agent-config:{sig_id}",
        )
        for m, rel, snip in proj.coding_agent_matches.get(sig_id, []):
            apply_matches(f, [m], location=rel, snippet=snip)
        f.metadata["files"] = sorted(files)
        self._inspect_instruction_files(f, proj, sig_id, files)
        if sig_id == "coding-agent.agent-skills":
            audits = []
            for rel in sorted(files):
                if (audit := proj.skill_audits.get(rel)) is None:
                    continue
                audits.append({"path": rel, **audit.to_metadata()})
                for indicator in audit.indicators:
                    f.add_tag("suspicious-instruction")
                    f.add_evidence(
                        Evidence(
                            signal=f"static-instruction:{indicator.rule}",
                            description=indicator.description,
                            location=f"{rel}:{indicator.line}",
                            weight=0.0,
                            attributes={"category": "static-instruction-audit", "rule": indicator.rule},
                        )
                    )
            if audits:
                f.metadata["static_instruction_audit"] = {"files": audits}
        posture = proj.posture.get(sig_id, [])
        if posture:
            record_posture(f, posture)
        # A tree whose listing was cut short may hold a settings file nothing names: no gate of
        # it can claim every action.
        record_approval(f, proj.approvals.get(sig_id, []), complete=not self._root_listing_incomplete)
        defs = [d for d in proj.agent_defs if any(d["file"] == x for x in files)]
        if defs:
            f.metadata["agent_definitions"] = defs
            f.add_capability("multi-agent")
        f.kind = Kind.AGENT_CONFIG
        f.owner, by_file = self.ownership.owners_for_files(root, files)
        f.owner = f.owner or self.owner
        if by_file:
            f.metadata["codeowners_by_file"] = by_file
        finalize(f, self.index)
        f.kind = Kind.AGENT_CONFIG
        return f

    @staticmethod
    def _inspect_instruction_files(f: Finding, proj: _Project, sig_id: str, files: list[str]) -> None:
        """Attach bounded content checks captured from the original confined file read."""
        rules: dict[str, int] = {}
        flagged: list[str] = []
        for rel in sorted(files):
            hits = proj.instruction_hits.get(rel, [])
            if hits:
                flagged.append(rel)
            for hit in hits:
                rules[hit.rule] = rules.get(hit.rule, 0) + 1
                f.add_tag(hit.tag)
                f.add_evidence(
                    Evidence(
                        signal=f"content:{hit.rule}",
                        description=f"{hit.detail} in {rel}",
                        location=f"{rel}:{hit.line}",
                        weight=hit.weight,
                        signature=sig_id,
                        attributes={"category": "content", "rule": hit.rule, "tag": hit.tag},
                    )
                )
        if flagged:
            f.metadata["instruction_content"] = {"rules": dict(sorted(rules.items())), "files": flagged}

    @staticmethod
    def _apply_mcp_tools(f: Finding, server_tools: dict[str, str]) -> None:
        """Derive MCP server capabilities from the tool names it registers."""
        tools = sorted(server_tools)
        f.metadata["mcp_tools"] = tools[:50]
        implied: dict[str, list[str]] = {}
        for tool in tools:
            for capability in mcp_tool_capabilities(tool):
                implied.setdefault(capability, []).append(tool)
        for capability, names in sorted(implied.items()):
            f.add_capability(capability)
            f.add_evidence(
                Evidence(
                    signal=f"mcp-tool:{capability}",
                    description=(
                        f"registers MCP tools implying {capability}: "
                        f"{', '.join(names[:5])}{' …' if len(names) > 5 else ''}"
                    ),
                    location=server_tools[names[0]],
                    weight=0.5,
                    signature="protocol.mcp",
                    attributes={"category": "protocol", "value": names[0]},
                )
            )

    def _fold_manifest(self, project: Finding, manifest: Finding, proj: _Project) -> None:
        """Merge a project manifest into the finding of the project that contains it.

        A CrewAI ``agents.yaml`` or a ``langgraph.json`` configures the agent
        implemented by that project's code, so the project is an agent and the
        manifest's evidence, technologies and details move onto it instead of
        counting the same agent twice. The manifest stays visible under
        ``metadata.manifests``.
        """
        for evidence in manifest.evidence:
            project.add_evidence(evidence)
        for sid in manifest.frameworks:
            project.add_framework(sid)
        for pid in manifest.model_providers:
            project.add_model_provider(pid)
        for capability in manifest.capabilities:
            project.add_capability(capability)
        for tag in manifest.tags:
            project.add_tag(tag)
        for model in manifest.models:
            if model not in project.models:
                project.models.append(model)
        details = {
            k: v
            for k, v in manifest.metadata.items()
            if k not in {"path", "scan_root", "technologies", "evidence_counts"}
        }
        project.metadata.setdefault("manifests", []).append(
            {
                "path": manifest.metadata.get("path"),
                "title": manifest.title,
                "resource": manifest.resource,
                **details,
            }
        )
        project.metadata["agent_indicators"] = max(1, int(project.metadata.get("agent_indicators") or 0))
        project.kind = Kind.AGENT
        finalize(project, self.index)
        project.title = self._project_title(project, proj)

    @staticmethod
    def _attach_example_credentials(f: Finding, proj: _Project) -> None:
        """Attach placeholder credentials as informational evidence (see module docstring)."""
        if not proj.example_credentials:
            return
        f.add_tag("example-credential")
        files: list[str] = []
        for i, (m, rel, reason) in enumerate(proj.example_credentials):
            if rel not in files:
                files.append(rel)
            if i >= MAX_EXAMPLE_CREDENTIAL_EVIDENCE:
                continue
            what = m.signal.description or m.signature.name
            f.add_evidence(
                Evidence(
                    signal=f"example-credential:{m.signature_id}",
                    description=f"placeholder {what} ({reason}) in {rel}: {redact(m.value)}",
                    location=f"{rel}:{m.line}" if m.line else rel,
                    weight=EXAMPLE_CREDENTIAL_WEIGHT,
                    signature=m.signature_id,
                    attributes={
                        "category": m.signature.category,
                        "value": redact(m.value),
                        "placeholder": reason,
                    },
                )
            )
        # The key name must not read as a credential field, or the report
        # sanitizer withholds the file list itself.
        f.metadata["placeholder_samples"] = {
            "count": len(proj.example_credentials),
            "files": sorted(files)[:MAX_EXAMPLE_CREDENTIAL_EVIDENCE],
        }

    def _project_title(self, f: Finding, proj: _Project) -> str:
        order = {"framework": 0, "cloud-service": 1, "platform": 2, "protocol": 3}
        ranked = sorted(
            (sig for sid in f.frameworks if (sig := self.index.get(sid)) and sig.category in order),
            key=lambda s: order[s.category],
        )
        names = [s.name for s in ranked[:4]]
        provs = [sig.name for sid in f.model_providers[:3] if (sig := self.index.get(sid))]
        where = "repository root" if proj.root == "." else proj.root
        what = "Agent" if f.kind == Kind.AGENT else "LLM usage"
        if f.kind != Kind.AGENT and "mcp_server" in f.metadata:
            # The project exposes tools over MCP rather than calling a model
            # (metadata.mcp_server). The title is prose: finding identity
            # (resource and discriminator) is unchanged.
            what = "MCP server"
        detail = ", ".join(names) or ", ".join(provs)
        if not detail:
            # Only supporting technology (a search tool, a vector store,
            # tracing): name it rather than claim an LLM SDK.
            support = [s.name.split(" (", 1)[0] for sid in f.frameworks if (s := self.index.get(sid))]
            detail = ", ".join(support[:3]) or "LLM SDK"
            if support and f.kind not in {Kind.AGENT, Kind.MCP_SERVER}:
                what = "AI tooling"
        return f"{what} in {where}: {detail}"

    def _mcp_finding(self, label: str, root: Path, rel: str, servers: list[dict[str, Any]]) -> Finding:
        # Every configured server is evidence, including one that declares itself
        # disabled (see _detect_mcp); each record carries its own ``disabled`` flag.
        enabled = [server for server in servers if not server["disabled"]]
        f = self._base(label, root, rel, Kind.MCP_SERVER, f"MCP configuration: {rel}", "mcp-config")
        sig = self.index.get("protocol.mcp")
        f.add_framework("protocol.mcp")
        f.add_capability("tool-use")
        f.add_evidence(
            Evidence(
                signal="file:protocol.mcp",
                description=f"MCP client/server configuration file {rel}",
                location=rel,
                weight=0.95,
                signature="protocol.mcp",
            )
        )
        remote_hosts: list[str] = []
        for s in servers:
            urls = s.get("urls")
            if not isinstance(urls, list):
                urls = [s["url"]] if s.get("url") else []
            for url in urls:
                if not isinstance(url, str):
                    continue
                for m in self.index.match_domains_in_text(url):
                    if m.signature.category != "identity-app":
                        apply_matches(f, [m], location=rel)
                if url not in remote_hosts:
                    remote_hosts.append(url)
            for env_name in s.get("env_names", []):
                for m in self.index.match_env(env_name):
                    apply_matches(f, [m], location=rel, weight_scale=0.5)
            if s.get("secrets_inline"):
                f.add_tag("inline-secrets")
                f.add_evidence(
                    Evidence(
                        signal="secret:inline",
                        description=(
                            f"MCP server '{s['name']}' has credential-looking values inline "
                            f"({', '.join(s.get('secret_locations') or ['configuration'])})"
                        ),
                        location=rel,
                        weight=0.3,
                    )
                )
            record_server_risks(f, s, rel)
            cmd = " ".join([str(s.get("command") or "")] + [str(a) for a in s.get("args", [])]).lower()
            for capability, keywords in _MCP_CAPABILITY_KEYWORDS:
                if any(k in cmd for k in keywords):
                    f.add_capability(capability)
                    break
        f.metadata["servers"] = servers
        # Servers that are not declared disabled; the others are counted apart.
        f.metadata["server_count"] = len(enabled)
        f.metadata["disabled_server_count"] = len(servers) - len(enabled)
        if len(enabled) < len(servers):
            f.add_tag("declared-disabled")
            if not enabled:
                f.metadata["disabled"] = True
        f.metadata["remote_urls"] = remote_hosts
        f.metadata["client"] = _mcp_client_for(rel)
        f.owner = self.ownership.owner_for(root, rel) or f.owner
        finalize(f, self.index)
        f.kind = Kind.MCP_SERVER
        if sig:
            f.metadata["risk_notes"] = sig.risk_notes
        return f

    # Shared agent-manifest card scaffold per manifest kind: framework id,
    # title prefix, whether the manifest name joins the title, evidence
    # description and weight, and the capability declared by the format itself.
    _CARD_KINDS: dict[str, tuple[str, str, bool, str, float, str | None]] = {
        "a2a": ("protocol.a2a", "A2A agent card", True, "A2A Agent Card", 0.95, "multi-agent"),
        "m365": (
            "platform.m365-declarative-agent",
            "M365 Copilot declarative agent",
            True,
            "Microsoft 365 declarative agent manifest",
            0.95,
            None,
        ),
        "langgraph": (
            "framework.langgraph",
            "LangGraph deployment manifest",
            False,
            "langgraph.json deployment manifest",
            0.95,
            None,
        ),
        "crewai": (
            "framework.crewai",
            "CrewAI agent definitions",
            False,
            "CrewAI agents.yaml",
            0.9,
            "multi-agent",
        ),
    }

    def _card_finding(self, label: str, root: Path, rel: str, text: str, kind: str) -> Finding | None:
        validation = parse_agent_manifest(rel, text, kind)
        if not validation.valid and not validation.incomplete:
            self._file_errors(rel, validation.errors)
            return None
        # Retain sibling credential context before projecting descriptive fields.
        # An opaque secret may also appear in a description, URL or dependency.
        data = sanitize(validation.data)
        f = self._base(label, root, rel, Kind.AGENT, "", "agent-manifest")
        spec = self._CARD_KINDS.get(kind)
        if spec:
            fw, prefix, named, description, weight, capability = spec
            if validation.incomplete:
                prefix = f"Incomplete {prefix}"
            f.title = f"{prefix}: {(data.get('name') or rel) if named else rel}"
            f.add_framework(fw)
            if capability and validation.valid:
                f.add_capability(capability)
            f.add_evidence(
                Evidence(
                    signal=f"file:{fw}", description=description, location=rel, weight=weight, signature=fw
                )
            )
        if kind == "a2a":
            self._describe_a2a_card(f, rel, validation.data or {}, data)
        elif kind == "m365":
            self._describe_m365_agent(f, rel, data)
        elif kind == "langgraph":
            self._describe_langgraph_manifest(f, rel, data)
        elif kind == "crewai":
            self._describe_crewai_agents(f, rel, data)
        f.owner = self.ownership.owner_for(root, rel) or f.owner
        finalize(f, self.index)
        if validation.incomplete:
            # Evidence of the protocol, never of an agent. Its validation
            # errors were recorded when the file was read.
            f.kind = Kind.FRAMEWORK_USAGE
            f.add_tag("incomplete-agent-card")
            f.metadata["card_errors"] = list(validation.errors)
        else:
            f.kind = Kind.AGENT
        return f

    def _describe_a2a_card(self, f: Finding, rel: str, card: dict[str, Any], shown: dict[str, Any]) -> None:
        """Project the card as every A2A source does; ``shown`` is its whole-document sanitized copy."""
        if a2a_unsupported_protocol_version(card):
            self.ctx.warn(
                f"code.filesystem: {rel}: A2A card declares a protocol version other than 0.x or 1.x; "
                "its fields were read as A2A 0.3 and 1.0 fields"
            )
        f.metadata["agent_card"] = agent_card = a2a_card_metadata(card, shown)
        for interface in agent_card["interfaces"]:
            apply_matches(f, self.index.match_domains_in_text(interface["url"]), location=rel)
        for tag in a2a_card_tags(card, agent_card["signature"]):
            f.add_tag(tag)

    @staticmethod
    def _describe_m365_agent(f: Finding, rel: str, data: dict[str, Any]) -> None:
        f.metadata["declarative_agent"] = {
            "name": data.get("name"),
            "description": truncate(sanitize_text(str(data.get("description", ""))), 300),
            "instructions": truncate(sanitize_text(str(data.get("instructions", ""))), 300),
            "capabilities": [
                c.get("name") for c in data.get("capabilities", []) or [] if isinstance(c, dict)
            ],
            "actions": [
                a.get("id") or a.get("file") for a in data.get("actions", []) or [] if isinstance(a, dict)
            ],
            "conversation_starters": len(data.get("conversation_starters", []) or []),
        }
        if data.get("actions"):
            f.add_capability("tool-use")

    @staticmethod
    def _describe_langgraph_manifest(f: Finding, rel: str, data: dict[str, Any]) -> None:
        graphs = data.get("graphs", {}) or {}
        f.metadata["graphs"] = _clip(list(graphs.keys()) if isinstance(graphs, dict) else graphs)
        f.metadata["dependencies"] = _clip(data.get("dependencies"))
        env = data.get("env")
        f.metadata["env_names"] = sorted(env) if isinstance(env, dict) else []
        if isinstance(env, str):
            f.metadata["env_file"] = sanitize_text(env)
        f.add_capability("tool-use")

    def _describe_crewai_agents(self, f: Finding, rel: str, data: dict[str, Any]) -> None:
        f.metadata["agents"] = [
            {
                "name": k,
                "role": truncate(sanitize_text(str((v or {}).get("role", ""))), 120),
                "llm": (v or {}).get("llm"),
            }
            for k, v in data.items()
            if isinstance(v, dict)
        ]
        for v in data.values():
            if isinstance(v, dict) and v.get("llm"):
                apply_matches(
                    f,
                    self.index.match_model(str(v["llm"]).split("/")[-1]),
                    location=rel,
                    weight_scale=0.6,
                )

    def _workflow_finding(self, label: str, root: Path, rel: str, hits: list[tuple[Match, str]]) -> Finding:
        f = self._base(label, root, rel, Kind.WORKFLOW, "", "workflow-export")
        # A workflow export kept as a test or fixture input exercises the
        # importer; it is not a deployed workflow. Apply the project policy:
        # half weight and an explicit tag, unless test code is included.
        test_only = not self.include_tests and _is_test_path(rel)
        for m, snip in hits:
            apply_matches(f, [m], location=rel, snippet=snip, weight_scale=0.5 if test_only else 1.0)
        if test_only:
            f.add_tag("test-code-only")
        names = {
            self.index.get(m.signature_id).name  # type: ignore[union-attr]
            for m, _ in hits
            if m.signature.category != "provider" and self.index.get(m.signature_id)
        }
        # An export whose nodes include a verified agent node (n8n .agent,
        # agentTool, openAiAssistant — semantic_config sets verified_agent)
        # is an agent, matching the lowcode.n8n connector's classification;
        # an LLM chain without one stays a workflow. The resource_type stays
        # "workflow-export" either way, so finding identity is unchanged.
        agent_flow = any(m.extra.get("verified_agent") for m, _ in hits)
        noun = "agent workflow" if agent_flow else "AI workflow"
        f.title = f"Exported {noun} ({', '.join(sorted(names))}): {rel}"
        f.owner = self.ownership.owner_for(root, rel) or f.owner
        finalize(f, self.index)
        f.kind = Kind.AGENT if agent_flow else Kind.WORKFLOW
        f.metadata["agent_flow"] = agent_flow
        graphs = []
        for match, _ in hits:
            for graph in match.extra.get("workflow_graphs", [match.extra.get("workflow_graph")]):
                if isinstance(graph, dict) and graph not in graphs:
                    graphs.append(graph)
        if len(graphs) == 1:
            f.metadata["workflow_graph"] = graphs[0]
        elif graphs:
            f.metadata["workflow_graphs"] = graphs
        return f

    def _infra_finding(
        self,
        label: str,
        root: Path,
        rel: str,
        hits: list[tuple[Match, str, str]],
        names_found: list[str] | None = None,
        *,
        wildcards: list[tuple[str, int, str]] | None = None,
        models: list[Match] | None = None,
    ) -> Finding:
        f = self._base(label, root, rel, Kind.INFRA, "", "iac")
        for m, _value, snip in hits:
            apply_matches(f, [m], location=rel, snippet=snip)
        for m in models or []:
            apply_matches(f, [m], location=rel)
            if m.value not in f.models:
                f.models.append(m.value)
        for source, line, snip in (wildcards or [])[:5]:
            f.add_tag("wildcard-permissions")
            f.add_evidence(
                Evidence(
                    signal="iac:iam-wildcard",
                    description="IAM statement in the same project grants wildcard actions",
                    location=f"{source}:{line}",
                    snippet=snip,
                    weight=0.5,
                )
            )
        names = {
            self.index.get(m.signature_id).name  # type: ignore[union-attr]
            for m, _, _ in hits
            if self.index.get(m.signature_id)
        }
        resources = sorted({v for _, v, _ in hits})
        f.title = f"Infrastructure provisions {', '.join(sorted(names))}: {rel}"
        f.metadata["resources"] = resources
        if names_found:
            f.metadata["names"] = names_found
        f.owner = self.ownership.owner_for(root, rel) or f.owner
        finalize(f, self.index)
        f.kind = Kind.INFRA
        return f

    def _secret_finding(
        self,
        label: str,
        root: Path,
        rel: str,
        hits: list[tuple[Match, str]],
        project_root: str = ".",
    ) -> Finding | None:
        # A structured value (e.g. a .env assignment) and the raw text pass can
        # both observe the same credential on the same line; count it once.
        # Placeholders are filtered again here so every caller shares the rule.
        unique: dict[tuple[str, str, int | None], tuple[Match, str]] = {}
        for m, snip in hits:
            if not looks_like_placeholder(m.value):
                unique.setdefault((m.signature_id, m.value, m.line), (m, snip))
        hits = list(unique.values())
        if not hits:
            return None
        f = self._base(label, root, rel, Kind.SECRET, f"LLM provider credential in {rel}", "file")
        # Test, fixture and recorded-cassette paths follow the project test-code
        # policy: half weight and an explicit tag unless test code is included.
        # The credential is still reported: cassettes record real traffic, and a
        # key committed under tests/ is as exposed as one anywhere else.
        test_only = not self.include_tests and _is_test_path(rel)
        # Documentation, example and generated paths are discounted the same way
        # project evidence is (``negative_context``): a credential-shaped value
        # in a tutorial is more often a sample than a live key, but it is still
        # reported, with the context named, because samples are sometimes real.
        context = None if self.include_tests or test_only else negative_context(rel, project_root)
        weight_scale = 1.0
        if test_only:
            weight_scale = 0.5
        elif context is not None:
            weight_scale = context.weight_scale
        for m, snip in hits:
            apply_matches(f, [m], location=rel, snippet=snip, weight_scale=weight_scale)
        f.add_tag("hardcoded-credential")
        if not f.model_providers:
            # Only the generic rules matched (an assigned PASSWORD, ACCESS_TOKEN or *_API_KEY): the value
            # is a hard-coded credential, but nothing ties it to an LLM provider, so the title must not
            # say so. The identity of the finding does not include its title.
            f.title = f"Hard-coded credential in {rel}"
            f.add_tag("unattributed-credential")
        if test_only:
            f.add_tag("test-code-only")
        elif context is not None:
            f.add_tag(NEGATIVE_CONTEXT_TAGS[context.reason])
            f.metadata["negative_contexts"] = [context.reason]
        f.metadata["providers"] = sorted({m.signature_id for m, _ in hits})
        f.metadata["count"] = len(hits)
        f.owner = self.ownership.owner_for(root, rel) or f.owner
        finalize(f, self.index)
        if context is not None and context.confidence_cap is not None:
            cap_confidence(f, context.confidence_cap)
            f.metadata["confidence_cap"] = {
                "reason": NEGATIVE_CONTEXT_TAGS[context.reason],
                "maximum": context.confidence_cap,
            }
        f.kind = Kind.SECRET
        return f

    def _parse_agent_definition(self, rel: str, text: str) -> dict[str, Any]:
        info: dict[str, Any] = {"file": rel, "name": PurePosixPath(rel).stem}
        m = _FRONTMATTER.match(text, timeout=_pattern_timeout(), concurrent=False)
        if m:
            quoted = _quote_glob_values(m.group(1))
            try:
                fm = strict_bounded_safe_load(quoted) or {}
            except (ValueError, RecursionError, yaml.YAMLError):
                # Includes resource limits, duplicate fields, non-finite
                # numbers, and SafeLoader's plain ValueError for an
                # impossible date or an over-long integer.
                try:
                    # Coding agents read a description such as "Use this agent when: ..." although
                    # YAML does not allow ": " in a plain scalar, by quoting it and parsing again.
                    # So do we, through the same strict loader: a document that is still invalid,
                    # has repeated fields or carries explicit tags stays an error.
                    fm = strict_bounded_safe_load(_quote_plain_values(quoted)) or {}
                    self._note_file(
                        rel, "agent definition front matter quoted to parse (a plain value contained ': ')"
                    )
                except (ValueError, RecursionError, yaml.YAMLError):
                    self.ctx.error(f"code.filesystem: {rel}: invalid agent definition YAML")
                    fm = {}
            if isinstance(fm, dict):
                fm = sanitize(fm)
                for k in (
                    "name",
                    "description",
                    "tools",
                    "model",
                    "permissionMode",
                    "mode",
                    "globs",
                    "alwaysApply",
                ):
                    if k in fm:
                        v = fm[k]
                        info[k] = (
                            truncate(sanitize_text(v), 200) if isinstance(v, str) else _clip(sanitize(v))
                        )
        return info


_MAX_CARD_FILES = 200
_MAX_AGENT_DEFINITIONS = 50
