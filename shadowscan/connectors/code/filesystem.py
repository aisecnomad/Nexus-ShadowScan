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
# path_context, project_evidence, model_identifiers, source_text and excerpts,
# and before its ownership, walk, file scan and finding code moved into
# collaborator classes (ADR-005), stays importable: the imports marked
# `noqa: F401 - re-exported` and the redundant `name as name` imports carry
# names this module does not use itself. Patch such a name in its defining
# module; rebinding it here does not change what the helpers use.
import ast  # noqa: F401 - re-exported
import errno as errno
import fnmatch as fnmatch
import hashlib
import os
import re
import stat as stat
import subprocess as subprocess
import time as time
import tomllib  # noqa: F401 - re-exported
from bisect import bisect_right as bisect_right
from collections.abc import Callable as Callable
from collections.abc import Iterable, Iterator
from collections.abc import Sequence as Sequence
from contextlib import contextmanager as contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath
from typing import Any, ClassVar

import regex as regex
import yaml as yaml

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
from shadowscan.connectors.code.dotnet_semantics import (
    microsoft_tool_loop_matches as microsoft_tool_loop_matches,
)
from shadowscan.connectors.code.excerpts import _excerpt as _excerpt
from shadowscan.connectors.code.excerpts import _ExcerptSource as _ExcerptSource
from shadowscan.connectors.code.excerpts import _LazyExcerpt as _LazyExcerpt
from shadowscan.connectors.code.excerpts import _Snippet as _Snippet
from shadowscan.connectors.code.file_scan import _ANY_FILE_NAME as _ANY_FILE_NAME
from shadowscan.connectors.code.file_scan import _BUNDLED_PACKS as _BUNDLED_PACKS
from shadowscan.connectors.code.file_scan import _COLOCATED_SIGNATURES as _COLOCATED_SIGNATURES
from shadowscan.connectors.code.file_scan import _DEDICATED_MCP_CONFIG_NAMES as _DEDICATED_MCP_CONFIG_NAMES
from shadowscan.connectors.code.file_scan import _IAC_EXTENSIONS as _IAC_EXTENSIONS
from shadowscan.connectors.code.file_scan import _IAC_MODEL_RE as _IAC_MODEL_RE
from shadowscan.connectors.code.file_scan import _IAM_WILDCARD_RE as _IAM_WILDCARD_RE
from shadowscan.connectors.code.file_scan import _LFS_POINTER_TEXT as _LFS_POINTER_TEXT
from shadowscan.connectors.code.file_scan import _LLM_CATEGORIES as _LLM_CATEGORIES
from shadowscan.connectors.code.file_scan import _MANIFEST_EXTENSIONS as _MANIFEST_EXTENSIONS
from shadowscan.connectors.code.file_scan import _MAX_AGENT_DEFINITIONS as _MAX_AGENT_DEFINITIONS
from shadowscan.connectors.code.file_scan import _MAX_CARD_FILES as _MAX_CARD_FILES
from shadowscan.connectors.code.file_scan import _MAX_LISTED_RULE_FILES as _MAX_LISTED_RULE_FILES
from shadowscan.connectors.code.file_scan import (
    _MAX_MCP_SERVER_CONSTRUCTIONS as _MAX_MCP_SERVER_CONSTRUCTIONS,
)
from shadowscan.connectors.code.file_scan import _MAX_MCP_TOOLS as _MAX_MCP_TOOLS
from shadowscan.connectors.code.file_scan import _MCP_REGISTRATION_RE as _MCP_REGISTRATION_RE
from shadowscan.connectors.code.file_scan import _MCP_SERVER_IMPORT_RE as _MCP_SERVER_IMPORT_RE
from shadowscan.connectors.code.file_scan import _MCP_TRANSPORTS, FileScanner, _MatchedSource, _Project
from shadowscan.connectors.code.file_scan import _WORKFLOW_EXTENSIONS as _WORKFLOW_EXTENSIONS
from shadowscan.connectors.code.file_scan import _XML_EXTENSIONS as _XML_EXTENSIONS
from shadowscan.connectors.code.file_scan import CI_IMAGE_WEIGHT_SCALE as CI_IMAGE_WEIGHT_SCALE
from shadowscan.connectors.code.file_scan import MAX_INSTRUCTION_TEXT_BYTES as MAX_INSTRUCTION_TEXT_BYTES
from shadowscan.connectors.code.file_scan import AbstractSet as AbstractSet
from shadowscan.connectors.code.file_scan import _bundled_signature as _bundled_signature
from shadowscan.connectors.code.file_scan import _document_declares_mcp as _document_declares_mcp
from shadowscan.connectors.code.file_scan import _load_json_lenient as _load_json_lenient
from shadowscan.connectors.code.file_scan import _local_module_predicate as _local_module_predicate
from shadowscan.connectors.code.file_scan import _on_disk_project as _on_disk_project
from shadowscan.connectors.code.file_scan import _SourceFile as _SourceFile
from shadowscan.connectors.code.file_scan import assess_posture as assess_posture
from shadowscan.connectors.code.file_scan import posture_parseable as posture_parseable
from shadowscan.connectors.code.go_semantics import langchaingo_agent_matches as langchaingo_agent_matches
from shadowscan.connectors.code.import_provenance import local_module_conflict as local_module_conflict
from shadowscan.connectors.code.instruction_content import ContentHit as ContentHit
from shadowscan.connectors.code.instruction_content import (
    inspect_instruction_text as inspect_instruction_text,
)
from shadowscan.connectors.code.java_semantics import (
    spring_tool_registration_matches as spring_tool_registration_matches,
)
from shadowscan.connectors.code.lockfiles import LOCKFILE_NAMES as LOCKFILE_NAMES
from shadowscan.connectors.code.lockfiles import LockInventory as LockInventory
from shadowscan.connectors.code.manifests import Artifact as Artifact
from shadowscan.connectors.code.manifests import Dep as Dep
from shadowscan.connectors.code.manifests import _pattern_timeout as _pattern_timeout
from shadowscan.connectors.code.manifests import is_manifest_name as is_manifest_name
from shadowscan.connectors.code.manifests import manifest_comment_projection as manifest_comment_projection
from shadowscan.connectors.code.manifests import parse_manifest as parse_manifest
from shadowscan.connectors.code.mcp_config import _mcp_client_for
from shadowscan.connectors.code.mcp_config import _parse_mcp_servers as _parse_mcp_servers
from shadowscan.connectors.code.mcp_tools import MCPToolLimitError as MCPToolLimitError
from shadowscan.connectors.code.mcp_tools import mcp_tool_capabilities
from shadowscan.connectors.code.mcp_tools import mcp_tool_names as mcp_tool_names
from shadowscan.connectors.code.model_artifacts import ARTIFACT_SUFFIXES as ARTIFACT_SUFFIXES
from shadowscan.connectors.code.model_artifacts import ArtifactBudgetExhausted as ArtifactBudgetExhausted
from shadowscan.connectors.code.model_artifacts import inspect_artifact as inspect_artifact
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
from shadowscan.connectors.code.ownership import _MAX_GIT_AUTHOR_CHARS as _MAX_GIT_AUTHOR_CHARS
from shadowscan.connectors.code.ownership import _MAX_GIT_EMAIL_CHARS as _MAX_GIT_EMAIL_CHARS
from shadowscan.connectors.code.ownership import _MAX_GIT_TIMESTAMP_CHARS as _MAX_GIT_TIMESTAMP_CHARS
from shadowscan.connectors.code.ownership import MAX_OWNERSHIP_STEPS as MAX_OWNERSHIP_STEPS
from shadowscan.connectors.code.ownership import MAX_PATTERN_LENGTH as MAX_PATTERN_LENGTH
from shadowscan.connectors.code.ownership import MAX_ROOT_OWNERSHIP_STEPS as MAX_ROOT_OWNERSHIP_STEPS
from shadowscan.connectors.code.ownership import MAX_RULES as MAX_RULES
from shadowscan.connectors.code.ownership import CodeOwnership, codeowners_match
from shadowscan.connectors.code.ownership import OwnershipBudget as OwnershipBudget
from shadowscan.connectors.code.ownership import OwnershipLimitError as OwnershipLimitError
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
from shadowscan.connectors.code.python_reexports import MAX_PENDING_BYTES as MAX_PENDING_BYTES
from shadowscan.connectors.code.python_reexports import MAX_PENDING_FILES as MAX_PENDING_FILES
from shadowscan.connectors.code.python_reexports import ImportResolver as ImportResolver
from shadowscan.connectors.code.python_reexports import PythonReexports
from shadowscan.connectors.code.python_reexports import ReexportLimitError as ReexportLimitError
from shadowscan.connectors.code.python_reexports import has_local_import as has_local_import
from shadowscan.connectors.code.python_reexports import project_path as project_path
from shadowscan.connectors.code.rule_packs import detection_rule_format as detection_rule_format
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
from shadowscan.connectors.code.skill_audit import InstructionAudit as InstructionAudit
from shadowscan.connectors.code.skill_audit import audit_skill_text as audit_skill_text
from shadowscan.connectors.code.source_identity import named_construction_spans as named_construction_spans
from shadowscan.connectors.code.source_ranges import noncode_ranges as noncode_ranges
from shadowscan.connectors.code.source_ranges import nul_reading_ranges as nul_reading_ranges
from shadowscan.connectors.code.source_semantics import MAX_CALL_TEXT as MAX_CALL_TEXT
from shadowscan.connectors.code.source_semantics import SourceBudgetExceeded as SourceBudgetExceeded
from shadowscan.connectors.code.source_semantics import SourceNotParsed as SourceNotParsed
from shadowscan.connectors.code.source_semantics import bound_source_matches as bound_source_matches
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
from shadowscan.connectors.code.tool_attribution import ToolRegions as ToolRegions
from shadowscan.connectors.code.walk import _AGENT_DEFINITION_DIRS as _AGENT_DEFINITION_DIRS
from shadowscan.connectors.code.walk import _CODING_AGENT_DOC_NAMES as _CODING_AGENT_DOC_NAMES
from shadowscan.connectors.code.walk import _DOCUMENTATION_EXTENSIONS as _DOCUMENTATION_EXTENSIONS
from shadowscan.connectors.code.walk import _IGNORED_STAT_ERRNOS as _IGNORED_STAT_ERRNOS
from shadowscan.connectors.code.walk import _LOCKFILE_MANIFESTS as _LOCKFILE_MANIFESTS
from shadowscan.connectors.code.walk import _MAX_NON_REGULAR_NOTES as _MAX_NON_REGULAR_NOTES
from shadowscan.connectors.code.walk import _NEVER_READ_SUFFIXES as _NEVER_READ_SUFFIXES
from shadowscan.connectors.code.walk import _ROOT_OPEN_REASONS as _ROOT_OPEN_REASONS
from shadowscan.connectors.code.walk import DEADLINE_MARGIN_FRACTION as DEADLINE_MARGIN_FRACTION
from shadowscan.connectors.code.walk import DEADLINE_MARGIN_MIN_SECONDS as DEADLINE_MARGIN_MIN_SECONDS
from shadowscan.connectors.code.walk import (
    DEFAULT_EXCLUDES,
    DEFAULT_MAX_WALK_ENTRIES,
    DEFAULT_OVERSIZE_SKIP_GLOBS,
    VCS_METADATA_EXCLUDES,
    TreeWalker,
    _is_coding_agent_doc,
    isolated,
)
from shadowscan.connectors.code.walk import DISCLOSED_DEFAULT_EXCLUDES as DISCLOSED_DEFAULT_EXCLUDES
from shadowscan.connectors.code.walk import ENUMERATION_DEADLINE_SHARE as ENUMERATION_DEADLINE_SHARE
from shadowscan.connectors.code.walk import LOCK_FILES as LOCK_FILES
from shadowscan.connectors.code.walk import MCP_CONFIG_NAMES as MCP_CONFIG_NAMES
from shadowscan.connectors.code.walk import (
    SCAN_TIMEOUT_BAND_HEADROOM_BYTES as SCAN_TIMEOUT_BAND_HEADROOM_BYTES,
)
from shadowscan.connectors.code.walk import SCAN_TIMEOUT_CAP_SECONDS as SCAN_TIMEOUT_CAP_SECONDS
from shadowscan.connectors.code.walk import SCAN_TIMEOUT_STEP_BYTES as SCAN_TIMEOUT_STEP_BYTES
from shadowscan.connectors.code.walk import TEXT_CONFIG_EXTENSIONS as TEXT_CONFIG_EXTENSIONS
from shadowscan.connectors.code.walk import _analyzed_by_name as _analyzed_by_name
from shadowscan.connectors.code.walk import _below_root as _below_root
from shadowscan.connectors.code.walk import _check_enumeration_time as _check_enumeration_time
from shadowscan.connectors.code.walk import _exception_name as _exception_name
from shadowscan.connectors.code.walk import _file_failure_reason as _file_failure_reason
from shadowscan.connectors.code.walk import _holds_file as _holds_file
from shadowscan.connectors.code.walk import _marks_project as _marks_project
from shadowscan.connectors.code.walk import _nearest_root as _nearest_root
from shadowscan.connectors.code.walk import _never_read_by_name as _never_read_by_name
from shadowscan.connectors.code.walk import _note_unread_settings as _note_unread_settings
from shadowscan.connectors.code.walk import _project_root as _project_root
from shadowscan.connectors.code.walk import _report_name as _report_name
from shadowscan.connectors.code.walk import _resolved_link_target as _resolved_link_target
from shadowscan.connectors.code.walk import _root_open_failure as _root_open_failure
from shadowscan.connectors.code.walk import _scan_priority as _scan_priority
from shadowscan.connectors.code.walk import _special_file_kind as _special_file_kind
from shadowscan.connectors.code.walk import _walk_directories as _walk_directories
from shadowscan.connectors.code.walk import _WalkBudget as _WalkBudget
from shadowscan.connectors.code.walk import _WalkCounters as _WalkCounters
from shadowscan.connectors.code.walk import _WalkLimitError as _WalkLimitError
from shadowscan.connectors.code.walk import deadline_margin as deadline_margin
from shadowscan.connectors.code.walk import enumeration_deadline as enumeration_deadline
from shadowscan.connectors.code.walk import scan_timeout_for_size as scan_timeout_for_size
from shadowscan.connectors.common import (
    apply_matches,
    cap_confidence,
    config_boolean,
    finalize,
    looks_like_placeholder,
)
from shadowscan.connectors.common import placeholder_reason as placeholder_reason
from shadowscan.connectors.mcp_risk import record_server_risks
from shadowscan.connectors.posture import CLIENT_SIGNATURES as CLIENT_SIGNATURES
from shadowscan.connectors.posture import approval_scopes as approval_scopes
from shadowscan.connectors.posture import approval_settings as approval_settings
from shadowscan.connectors.posture import canonical_settings_path as canonical_settings_path
from shadowscan.connectors.posture import posture_client as posture_client
from shadowscan.connectors.posture import record_approval, record_posture
from shadowscan.connectors.posture import unreadable_settings as unreadable_settings
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.signatures import Match
from shadowscan.signatures import Signature as Signature
from shadowscan.signatures.loader import builtin_signature_dir as builtin_signature_dir
from shadowscan.signatures.matcher import SOURCE_EXTENSIONS as SOURCE_EXTENSIONS
from shadowscan.signatures.matcher import WALL_BUDGET_FACTOR as WALL_BUDGET_FACTOR
from shadowscan.signatures.matcher import LiteralScan as LiteralScan
from shadowscan.signatures.matcher import MatchTimeoutError as MatchTimeoutError
from shadowscan.signatures.matcher import _finditer as _finditer
from shadowscan.signatures.matcher import language_for_path
from shadowscan.utils.files import link_in_path as link_in_path
from shadowscan.utils.files import open_confined_directory as open_confined_directory
from shadowscan.utils.files import open_confined_file as open_confined_file
from shadowscan.utils.files import read_policy_text as read_policy_text
from shadowscan.utils.git import LFS_POINTER_MAX_BYTES as LFS_POINTER_MAX_BYTES
from shadowscan.utils.git import LFS_POINTER_PREFIX as LFS_POINTER_PREFIX
from shadowscan.utils.git import MAX_GITMODULES_BYTES as MAX_GITMODULES_BYTES
from shadowscan.utils.git import MetadataOutputLimitError as MetadataOutputLimitError
from shadowscan.utils.git import MetadataTimeoutError as MetadataTimeoutError
from shadowscan.utils.git import declared_submodule_paths as declared_submodule_paths
from shadowscan.utils.git import metadata_git_argv_prefix as metadata_git_argv_prefix
from shadowscan.utils.git import metadata_git_env as metadata_git_env
from shadowscan.utils.git import read_gitlink_paths as read_gitlink_paths
from shadowscan.utils.git import require_local_git_metadata as require_local_git_metadata
from shadowscan.utils.git import run_bounded_metadata as run_bounded_metadata
from shadowscan.utils.jsonc import (
    load_json_lenient_marked as _load_json_lenient_marked,  # noqa: F401 - re-exported
)
from shadowscan.utils.jsonc import strip_json_comments as _strip_json_comments  # noqa: F401 - historical name
from shadowscan.utils.redaction import SanitizationLimitError as SanitizationLimitError
from shadowscan.utils.redaction import sanitize, sanitize_text
from shadowscan.utils.safe_json import JSONIntegrityError as JSONIntegrityError
from shadowscan.utils.safe_yaml import YAMLIntegrityError as YAMLIntegrityError
from shadowscan.utils.safe_yaml import YAMLResourceLimitError as YAMLResourceLimitError
from shadowscan.utils.safe_yaml import strict_bounded_safe_load as strict_bounded_safe_load
from shadowscan.utils.text import line_counter as line_counter
from shadowscan.utils.text import notebook_to_source as notebook_to_source
from shadowscan.utils.text import parse_timestamp as parse_timestamp
from shadowscan.utils.text import read_text as read_text
from shadowscan.utils.text import redact, truncate

# The name this module bound CODEOWNERS matching to before its caller moved (ADR-005).
_codeowners_match = codeowners_match

# Manifests that configure the code of the project containing them. A2A cards
# and M365 declarative agents declare a separately addressable agent (its own
# name, endpoint and authentication) and stay findings of their own.
_PROJECT_MANIFESTS = frozenset({"crewai", "langgraph"})

# Signal types that establish a library in a project (see _emit_project).
_LIBRARY_SIGNALS = frozenset({"import", "dependency", "code"})
# Signals that name a product without configuring it.
_MENTION_SIGNALS = frozenset({"env", "name"})

# Saved outputs (plots, tables, logs) routinely push small notebooks past
# max_file_size. Their code cells are still analyzed up to this size.
DEFAULT_MAX_NOTEBOOK_SIZE = 20 * 1024 * 1024

# Artifact metadata bytes (inspect_model_artifacts) read per scanned root, and
# bytes read only to skip GGUF array values (vocabularies) per scanned root.
_ARTIFACT_SCAN_BYTES = 32 * 1024 * 1024
_ARTIFACT_SKIP_BYTES = 256 * 1024 * 1024

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


_ROOT_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}\Z")
# The ":<line>" suffix of an evidence location.
_LOCATION_LINE = re.compile(r":\d+\Z")


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
    component (``TreeWalker.walk``), so a directory concurrently
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
        self.walker = TreeWalker(
            ctx,
            max_file_size=self.max_file_size,
            max_files=self.max_files,
            max_entries=self.max_entries,
            max_notebook_size=self.max_notebook_size,
            scan_timeout=self.scan_timeout,
            oversize_skip_globs=self.oversize_skip_globs,
            scan_secrets=self.scan_secrets,
            inspect_model_artifacts=self.inspect_model_artifacts,
            model_metadata_bytes=self.model_metadata_bytes,
            use_git=self.use_git,
            strict_coverage=self.strict_coverage,
            include_tests=self.include_tests,
            default_excludes=self.default_excludes,
            exclude_names=self.exclude_names,
            explicit_exclude_names=self._explicit_exclude_names,
            exclude_globs=self.exclude_globs,
            include_paths=self.include_paths,
            root_prefix=self._root_prefix,
        )
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
        self.ownership = CodeOwnership(
            ctx,
            use_git=self.use_git,
            owner=self.owner,
            max_file_size=self.max_file_size,
            included=self.walker.included,
        )
        self.file_scanner = FileScanner(
            ctx,
            walker=self.walker,
            base=self._base,
            max_file_size=self.max_file_size,
            max_ast_nodes=self.max_ast_nodes,
            scan_timeout=self.scan_timeout,
            scan_secrets=self.scan_secrets,
            strict_coverage=self.strict_coverage,
            include_tests=self.include_tests,
            triage=self.triage,
            agent_granularity=self.agent_granularity,
            model_metadata_bytes=self.model_metadata_bytes,
        )
        # Settings files of the scanned tree that a remote API snapshot did not include (set by
        # the code.github / code.gitlab connectors that delegate to this one).
        self.unread_settings: list[str] = []
        # Whether the remote API listing of the tree was cut short or held entries it could not
        # name (set by the code.github / code.gitlab connectors that delegate to this one):
        # settings files may exist that nothing lists, so no approval gate of this tree can
        # claim every action (``record_approval(complete=False)``).
        self.tree_listing_incomplete = False

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

    # ------------------------------------------------------------------ scan
    def scan_tree(self, root: Path) -> Iterator[Finding]:
        root = root.absolute()
        scan = _ScanState(root, self._scan_label(root))
        previous_scan = self.ownership.begin_scan(scan)
        # Each root's gates read only its own listing (scan_tree walks and emits one root at a time).
        self.walker.root_listing_incomplete = self.tree_listing_incomplete
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
            self.walker.walk(scan, self.file_scanner.scan_file, self.unread_settings)
            if scan.artifacts_uninspected:
                self.ctx.warn(
                    f"code.filesystem: {scan.label}: artifact metadata budget ({_ARTIFACT_SCAN_BYTES:,} "
                    f"bytes, or {_ARTIFACT_SKIP_BYTES:,} array bytes, per root) exhausted; "
                    f"{scan.artifacts_uninspected} selected file(s) were not inspected as artifacts "
                    "(extensionless ones were still analysed as text); artifact inventory incomplete",
                    incomplete=True,
                )
            self.file_scanner.resolve_reexport_sources(scan)
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
            self.ownership.end_scan(previous_scan)
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
            with isolated(self.ctx, rel, "MCP analysis"), self.index.scan_budget(seconds=self.scan_timeout):
                yield self._mcp_finding(label, root, rel, servers)
        yield from self._emit_manifests(scan, project_findings)
        yield from project_findings.values()
        for rel, hits in scan.workflow_files.items():
            with isolated(self.ctx, rel, "workflow analysis"):
                yield self._workflow_finding(label, root, rel, [*hits, *scan.workflow_providers.get(rel, [])])
        for rel, infra_hits in scan.infra_files.items():
            with isolated(self.ctx, rel, "infrastructure analysis"):
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
            with isolated(self.ctx, rel, "credential analysis"):
                f = self._secret_finding(label, root, rel, hits)
                if f:
                    yield f

    def _emit_projects(self, scan: _ScanState, project_findings: dict[str, Finding]) -> Iterator[Finding]:
        """Yield coding-agent findings and hold each project finding in ``project_findings``."""
        # MCP configs, agent manifests, exported workflows and IaC produce their
        # own findings; a project finding built only from them is a duplicate.
        covered_files = scan.covered_files()
        for proj in scan.projects.values():
            with isolated(self.ctx, proj.root, "project analysis"):
                for finding in self._emit_project(scan.label, scan.root, proj, covered_files):
                    if finding.resource_type == "project":
                        project_findings[proj.root] = finding
                    else:
                        yield finding

    def _emit_manifests(self, scan: _ScanState, project_findings: dict[str, Finding]) -> Iterator[Finding]:
        """Yield agent manifest findings; a project manifest is folded into its project's finding."""
        for rel, text, kind, proj_root in scan.card_files:
            with (
                isolated(self.ctx, rel, "agent manifest analysis"),
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
                self.file_scanner.file_errors(rel, issues)
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
        record_approval(f, proj.approvals.get(sig_id, []), complete=not self.walker.root_listing_incomplete)
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
            self.file_scanner.file_errors(rel, validation.errors)
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
        for m, snip in hits:
            apply_matches(f, [m], location=rel, snippet=snip, weight_scale=0.5 if test_only else 1.0)
        f.add_tag("hardcoded-credential")
        if not f.model_providers:
            # Only the generic rules matched (an assigned PASSWORD, ACCESS_TOKEN or *_API_KEY): the value
            # is a hard-coded credential, but nothing ties it to an LLM provider, so the title must not
            # say so. The identity of the finding does not include its title.
            f.title = f"Hard-coded credential in {rel}"
            f.add_tag("unattributed-credential")
        if test_only:
            f.add_tag("test-code-only")
        f.metadata["providers"] = sorted({m.signature_id for m, _ in hits})
        f.metadata["count"] = len(hits)
        f.owner = self.ownership.owner_for(root, rel) or f.owner
        finalize(f, self.index)
        f.kind = Kind.SECRET
        return f
