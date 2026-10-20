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
from dataclasses import dataclass, field
from dataclasses import replace as replace
from pathlib import Path
from pathlib import PurePosixPath as PurePosixPath
from typing import Any, ClassVar

import regex as regex
import yaml as yaml

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError, _positive_limit
from shadowscan.connectors.base import incomplete_reason as incomplete_reason
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
from shadowscan.connectors.code.file_scan import _COLOCATED_SIGNATURES as _COLOCATED_SIGNATURES
from shadowscan.connectors.code.file_scan import _ENV_TEMPLATE_WORDS as _ENV_TEMPLATE_WORDS
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
from shadowscan.connectors.code.file_scan import _WORKFLOW_EXTENSIONS as _WORKFLOW_EXTENSIONS
from shadowscan.connectors.code.file_scan import _WORKFLOW_FILE as _WORKFLOW_FILE
from shadowscan.connectors.code.file_scan import _XML_EXTENSIONS as _XML_EXTENSIONS
from shadowscan.connectors.code.file_scan import CI_IMAGE_WEIGHT_SCALE as CI_IMAGE_WEIGHT_SCALE
from shadowscan.connectors.code.file_scan import MAX_INSTRUCTION_TEXT_BYTES as MAX_INSTRUCTION_TEXT_BYTES
from shadowscan.connectors.code.file_scan import AbstractSet as AbstractSet
from shadowscan.connectors.code.file_scan import FileScanner
from shadowscan.connectors.code.file_scan import _clip as _clip
from shadowscan.connectors.code.file_scan import _env_values_file as _env_values_file
from shadowscan.connectors.code.file_scan import _load_json_lenient as _load_json_lenient
from shadowscan.connectors.code.file_scan import _mentions_mcp_keys as _mentions_mcp_keys
from shadowscan.connectors.code.file_scan import _UndecodableFile as _UndecodableFile
from shadowscan.connectors.code.file_scan import _yaml_declares_mcp as _yaml_declares_mcp
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
from shadowscan.connectors.code.javascript_imports import JavascriptToolImports
from shadowscan.connectors.code.lockfiles import LOCKFILE_NAMES as LOCKFILE_NAMES
from shadowscan.connectors.code.lockfiles import LockInventory as LockInventory
from shadowscan.connectors.code.manifests import Artifact as Artifact
from shadowscan.connectors.code.manifests import Dep as Dep
from shadowscan.connectors.code.manifests import _pattern_timeout as _pattern_timeout
from shadowscan.connectors.code.manifests import is_manifest_name as is_manifest_name
from shadowscan.connectors.code.manifests import manifest_comment_projection as manifest_comment_projection
from shadowscan.connectors.code.manifests import parse_manifest as parse_manifest
from shadowscan.connectors.code.mcp_config import _mcp_client_for as _mcp_client_for
from shadowscan.connectors.code.mcp_config import _parse_mcp_servers as _parse_mcp_servers
from shadowscan.connectors.code.mcp_tools import MCPToolLimitError as MCPToolLimitError
from shadowscan.connectors.code.mcp_tools import mcp_tool_capabilities as mcp_tool_capabilities
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
from shadowscan.connectors.code.ownership import OwnershipBudget as OwnershipBudget
from shadowscan.connectors.code.ownership import OwnershipLimitError as OwnershipLimitError
from shadowscan.connectors.code.ownership import OwnershipResolver, codeowners_match
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
from shadowscan.connectors.code.path_context import NEGATIVE_CONTEXT_TAGS as NEGATIVE_CONTEXT_TAGS
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
from shadowscan.connectors.code.project_findings import _LIBRARY_SIGNALS as _LIBRARY_SIGNALS
from shadowscan.connectors.code.project_findings import _LOCATION_LINE as _LOCATION_LINE
from shadowscan.connectors.code.project_findings import _MCP_CAPABILITY_KEYWORDS as _MCP_CAPABILITY_KEYWORDS
from shadowscan.connectors.code.project_findings import _MENTION_SIGNALS as _MENTION_SIGNALS
from shadowscan.connectors.code.project_findings import _PROJECT_MANIFESTS as _PROJECT_MANIFESTS
from shadowscan.connectors.code.project_findings import EXAMPLE_CREDENTIAL_WEIGHT as EXAMPLE_CREDENTIAL_WEIGHT
from shadowscan.connectors.code.project_findings import (
    MAX_EXAMPLE_CREDENTIAL_EVIDENCE as MAX_EXAMPLE_CREDENTIAL_EVIDENCE,
)
from shadowscan.connectors.code.project_findings import ProjectFindings
from shadowscan.connectors.code.python_dispatch import PythonDispatches
from shadowscan.connectors.code.python_reexports import MAX_PENDING_BYTES as MAX_PENDING_BYTES
from shadowscan.connectors.code.python_reexports import MAX_PENDING_FILES as MAX_PENDING_FILES
from shadowscan.connectors.code.python_reexports import ImportResolver as ImportResolver
from shadowscan.connectors.code.python_reexports import PythonReexports
from shadowscan.connectors.code.python_reexports import ReexportLimitError as ReexportLimitError
from shadowscan.connectors.code.python_reexports import has_local_import as has_local_import
from shadowscan.connectors.code.python_reexports import project_path as project_path
from shadowscan.connectors.code.rule_packs import detection_rule_format as detection_rule_format
from shadowscan.connectors.code.scan_records import _BUNDLED_PACKS as _BUNDLED_PACKS
from shadowscan.connectors.code.scan_records import _DEDICATED_MCP_CONFIG_NAMES as _DEDICATED_MCP_CONFIG_NAMES
from shadowscan.connectors.code.scan_records import _MCP_TRANSPORTS as _MCP_TRANSPORTS
from shadowscan.connectors.code.scan_records import _READ_ISSUE_REASONS as _READ_ISSUE_REASONS
from shadowscan.connectors.code.scan_records import CREDENTIAL_FILE_NAMES as CREDENTIAL_FILE_NAMES
from shadowscan.connectors.code.scan_records import _bundled_signature as _bundled_signature
from shadowscan.connectors.code.scan_records import _document_declares_mcp as _document_declares_mcp
from shadowscan.connectors.code.scan_records import _local_module_predicate as _local_module_predicate
from shadowscan.connectors.code.scan_records import _MatchedSource, _Project
from shadowscan.connectors.code.scan_records import _on_disk_project as _on_disk_project
from shadowscan.connectors.code.scan_records import _read_issue_reason as _read_issue_reason
from shadowscan.connectors.code.scan_records import _SourceFile as _SourceFile
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
from shadowscan.connectors.code.walk import _ANY_FILE_NAME as _ANY_FILE_NAME
from shadowscan.connectors.code.walk import _CODING_AGENT_DOC_NAMES as _CODING_AGENT_DOC_NAMES
from shadowscan.connectors.code.walk import _DOCUMENTATION_EXTENSIONS as _DOCUMENTATION_EXTENSIONS
from shadowscan.connectors.code.walk import _IGNORED_STAT_ERRNOS as _IGNORED_STAT_ERRNOS
from shadowscan.connectors.code.walk import _LOCKFILE_MANIFESTS as _LOCKFILE_MANIFESTS
from shadowscan.connectors.code.walk import _MAX_NON_REGULAR_NOTES as _MAX_NON_REGULAR_NOTES
from shadowscan.connectors.code.walk import _MCP_STRUCTURE_SUFFIXES as _MCP_STRUCTURE_SUFFIXES
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
)
from shadowscan.connectors.code.walk import DISCLOSED_DEFAULT_EXCLUDES as DISCLOSED_DEFAULT_EXCLUDES
from shadowscan.connectors.code.walk import ENUMERATION_DEADLINE_SHARE as ENUMERATION_DEADLINE_SHARE
from shadowscan.connectors.code.walk import LOCK_FILES as LOCK_FILES
from shadowscan.connectors.code.walk import MCP_CONFIG_NAMES as MCP_CONFIG_NAMES
from shadowscan.connectors.code.walk import PROJECT_ROOT_MARKERS as PROJECT_ROOT_MARKERS
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
from shadowscan.connectors.code.walk import _is_coding_agent_doc as _is_coding_agent_doc
from shadowscan.connectors.code.walk import _link_names_one_file as _link_names_one_file
from shadowscan.connectors.code.walk import _marks_deployable_project as _marks_deployable_project
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
from shadowscan.connectors.common import apply_matches as apply_matches
from shadowscan.connectors.common import cap_confidence as cap_confidence
from shadowscan.connectors.common import config_boolean
from shadowscan.connectors.common import finalize as finalize
from shadowscan.connectors.common import looks_like_placeholder as looks_like_placeholder
from shadowscan.connectors.common import placeholder_reason as placeholder_reason
from shadowscan.connectors.mcp_risk import record_server_risks as record_server_risks
from shadowscan.connectors.posture import CLIENT_SIGNATURES as CLIENT_SIGNATURES
from shadowscan.connectors.posture import approval_scopes as approval_scopes
from shadowscan.connectors.posture import approval_settings as approval_settings
from shadowscan.connectors.posture import canonical_settings_path as canonical_settings_path
from shadowscan.connectors.posture import posture_client as posture_client
from shadowscan.connectors.posture import record_approval as record_approval
from shadowscan.connectors.posture import record_posture as record_posture
from shadowscan.connectors.posture import unreadable_settings as unreadable_settings
from shadowscan.coverage import is_vendored_path as is_vendored_path
from shadowscan.coverage import validate_max_coverage_gap
from shadowscan.models import Evidence as Evidence
from shadowscan.models import Finding, Kind, Surface
from shadowscan.signatures import Match
from shadowscan.signatures import Signature as Signature
from shadowscan.signatures.loader import builtin_signature_dir as builtin_signature_dir
from shadowscan.signatures.matcher import MAX_SECRETS_PER_SIGNAL as MAX_SECRETS_PER_SIGNAL
from shadowscan.signatures.matcher import SOURCE_EXTENSIONS as SOURCE_EXTENSIONS
from shadowscan.signatures.matcher import WALL_BUDGET_FACTOR as WALL_BUDGET_FACTOR
from shadowscan.signatures.matcher import LiteralScan as LiteralScan
from shadowscan.signatures.matcher import MatchTimeoutError as MatchTimeoutError
from shadowscan.signatures.matcher import _finditer as _finditer
from shadowscan.signatures.matcher import language_for_path as language_for_path
from shadowscan.signatures.matcher import reported_credential as reported_credential
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
from shadowscan.utils.redaction import sanitize as sanitize
from shadowscan.utils.redaction import sanitize_text as sanitize_text
from shadowscan.utils.safe_json import JSONIntegrityError as JSONIntegrityError
from shadowscan.utils.safe_yaml import YAMLIntegrityError as YAMLIntegrityError
from shadowscan.utils.safe_yaml import YAMLResourceLimitError as YAMLResourceLimitError
from shadowscan.utils.safe_yaml import strict_bounded_safe_load as strict_bounded_safe_load

# Names the filesystem module held before the ADR-005 split and the review fixes carried
# onto it; kept importable from here (see the note above). Patch such a name in its
# defining module; rebinding it here does not change what the collaborators use.
from shadowscan.utils.text import BINARY_CONTENT_ERROR as BINARY_CONTENT_ERROR
from shadowscan.utils.text import line_counter as line_counter
from shadowscan.utils.text import notebook_to_source as notebook_to_source
from shadowscan.utils.text import parse_timestamp as parse_timestamp
from shadowscan.utils.text import read_credential_text as read_credential_text
from shadowscan.utils.text import read_text as read_text
from shadowscan.utils.text import redact as redact
from shadowscan.utils.text import truncate as truncate

# The name this module bound CODEOWNERS matching to before its caller moved (ADR-005).
_codeowners_match = codeowners_match

# Saved outputs (plots, tables, logs) routinely push small notebooks past
# max_file_size. Their code cells are still analyzed up to this size.
DEFAULT_MAX_NOTEBOOK_SIZE = 20 * 1024 * 1024

# Artifact metadata bytes (inspect_model_artifacts) read per scanned root, and
# bytes read only to skip GGUF array values (vocabularies) per scanned root.
_ARTIFACT_SCAN_BYTES = 32 * 1024 * 1024
_ARTIFACT_SKIP_BYTES = 256 * 1024 * 1024


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
    # relpath -> signature ids whose per-signal credential quota the file exceeded
    secrets_limited: dict[str, set[str]] = field(default_factory=dict)
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
    javascript_imports: JavascriptToolImports = field(default_factory=JavascriptToolImports)
    python_dispatches: PythonDispatches = field(default_factory=PythonDispatches)
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
    #: Entries (directories and files) a probe counts before it stops, and the
    #: seconds it may spend counting them. Bounded so the estimate costs a
    #: fraction of a second even on a huge tree or a slow filesystem.
    _PROBE_LIMIT = 20_000
    _PROBE_SECONDS = 1.0
    #: Entries the default deadline comfortably covers. Above this the budget
    #: grows in proportion, because the walk's cost is roughly linear in
    #: entries once signature matching dominates.
    _ENTRIES_PER_DEFAULT_BUDGET = 12_000

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
        "staged": (
            "scan only changed Git index blobs, never unstaged working-tree edits; at most 100 changed "
            "files, 1 MiB each and 8 MiB combined Git output; links, submodules, conflicts and unread "
            "objects fail closed; requires a local repository root and Git 2.45+; the report cannot "
            "establish a repository inventory or resolve baseline findings (default false)"
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
        "max_coverage_gap": (
            "share of examined entries that may be left unread before this scan reports itself "
            "incomplete (default: the scan-wide options.max_coverage_gap, 0.02); 0 is strict "
            "accounting, as strict_coverage is: any gap fails and none is discounted or declared. A gap "
            "the scanner cannot bound always fails closed, whatever this allows"
        ),
        "strict_coverage": (
            "strict accounting: report every coverage gap (unread analyzable oversize files, non-regular "
            "entries named like configuration files, symbolic links whose alias path is not covered, "
            "unreadable test fixtures) as an error that marks the scan incomplete, with no gap budget, "
            "test-code discount or ci declaration (default false)"
        ),
        "include_tests": (
            "let test and fixture code establish agents and credential findings at full weight "
            "(default false)"
        ),
        "profile": (
            "default | ci; ci declares as omissions, with a warning that leaves the scan complete, the "
            "coverage gaps a source gate accepts in advance: unread symbolic links, non-regular entries, "
            "unparsed content, analysis limits and, while scan_secrets is off, oversize files under test, "
            "fixture, documentation, example and generated paths (documentation and example directories "
            "below the file's project root, test paths only while include_tests is false); every other gap "
            "is judged by the coverage budget as usual, an MCP configuration, coding-agent file, agent card "
            "or credential limit is never declared, and the report counts the omissions; refused with "
            "strict_coverage or a max_coverage_gap of 0 (default: default)"
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
        # A gap budget of 0 is strict accounting, as strict_coverage is (see _strict_accounting).
        self._zero_budget = coverage_profile(ctx.config, strict_coverage=self.strict_coverage)
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
            profile=self.profile,
            zero_budget=self._zero_budget,
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
        self.staged = config_boolean(ctx.get("staged", False), "staged")
        if self.staged and (
            self.diff_base is not None or self.triage or self.include_paths or ctx.input_path
        ):
            raise ConnectorError(
                "code.filesystem: staged conflicts with diff_base, triage, include and input"
            )
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
        self.findings = ProjectFindings(
            ctx,
            ownership=self.ownership,
            walker=self.walker,
            file_scanner=self.file_scanner,
            base=self._base,
            root_prefix=self._root_prefix,
            include_tests=self.include_tests,
            agent_granularity=self.agent_granularity,
            owner=self.owner,
            scan_timeout=self.scan_timeout,
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
            if self.staged:
                yield from self._scan_staged(root)
            else:
                yield from self.scan_tree(root)

    def _scan_staged(self, root: Path) -> Iterator[Finding]:
        from shadowscan.utils.staged import StagedScanError, staged_snapshot

        try:
            with staged_snapshot(root, self.ctx) as snapshot:
                self.ctx.warn(
                    f"code.filesystem: staged scope: {snapshot.files} changed file(s), "
                    f"{snapshot.deleted} deletion(s); exact index blobs only. Unchanged files, "
                    "unstaged edits and cross-file context were not scanned; "
                    "this is not a repository inventory",
                    incomplete=False,
                )
                for finding in self.scan_tree(snapshot.root, label=self._scan_label(root)):
                    finding.add_tag("staged-scan")
                    finding.metadata["scan_root"] = str(root)
                    finding.metadata["staged_scan"] = {
                        "files": snapshot.files,
                        "deleted": snapshot.deleted,
                        "selection_sha256": snapshot.selection_sha256,
                    }
                    yield finding
        except StagedScanError as exc:
            self.ctx.error(f"code.filesystem: {exc}", reason="unscanned-input")

    # ------------------------------------------------------------------ scan
    def scan_tree(self, root: Path, *, label: str | None = None) -> Iterator[Finding]:
        root = root.absolute()
        scan = _ScanState(root, label or self._scan_label(root))
        previous_scan = self.ownership.scan
        self.ownership.scan = scan
        # Ownership caches belong to this opened tree, not a pathname that a
        # later scan on the same connector instance may find replaced.
        self.ownership.forget_root(root)
        # Each root's gates read only its own listing (scan_tree walks and emits one root at a time).
        self.walker.root_listing_incomplete = self.tree_listing_incomplete
        # Each root's gaps are judged against its own entries, as if it were
        # scanned alone; a code.github or code.gitlab checkout shares its
        # parent's ledger, so each repository is its own part there too.
        self.ctx.begin_coverage_part(scan.label)
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
            for f in self.findings.emit_findings(scan):
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

    def _root_prefix(self, label: str) -> str:
        """Name the scan root in a diagnostic only when this connector scans several roots."""
        paths = self.ctx.get("paths")
        several = (isinstance(paths, list) and len(paths) > 1) or self.ctx.get("_shared_label_roots") is True
        return f"{label}: " if several else ""

    def coverage_is_strict(self) -> bool:
        # This connector's own option, parsed in __init__.
        return self.strict_coverage

    def coverage_gap_override(self) -> float | None:
        """This connector's documented ``max_coverage_gap``, if the scan set one."""
        raw = self.ctx.get("max_coverage_gap")
        return None if raw is None else validate_max_coverage_gap(raw)

    @classmethod
    def estimate_timeout_seconds(cls, config: dict[str, Any], default: float) -> float | None:
        """Scale the deadline to the size of the tree about to be walked.

        A fixed deadline silently truncated large repositories: the walk hit
        it mid-tree and the connector reported nothing, which reads as a clean
        result everywhere except the exit code. The probe counts entries up to
        ``_PROBE_LIMIT`` and stops; reaching the limit means "at least this
        many", so the proposal saturates at ``default * _PROBE_LIMIT /
        _ENTRIES_PER_DEFAULT_BUDGET`` (200 s at the 120 s default), below the
        engine's own ceiling. A larger tree needs an explicit deadline; one
        that overruns this one is still incomplete.
        """
        if config.get("staged"):
            # A bounded index snapshot does not enumerate the working tree.
            return None
        try:
            roots = [Path(p) for p in cls.scanned_local_paths(config)]
            extra = _validated_names(config.get("exclude"), "exclude")
            default_excludes = config_boolean(config.get("default_excludes", True), "default_excludes")
        except Exception:  # noqa: BLE001 - an unusable path or option is the scan's problem, not the estimate's
            return None
        if not roots:
            return None
        # The directory names the walk prunes. An exclude glob only narrows the
        # walk further, so leaving it out can lengthen the estimate, never cut it.
        pruned = set(DEFAULT_EXCLUDES) if default_excludes else set(VCS_METADATA_EXCLUDES)
        pruned |= {e for e in extra if "*" not in e and "/" not in e}
        entries = cls._probe_entry_count(roots, frozenset(pruned))
        if entries < cls._ENTRIES_PER_DEFAULT_BUDGET:
            return None
        return default * (entries / cls._ENTRIES_PER_DEFAULT_BUDGET)

    @classmethod
    def _probe_entry_count(
        cls, roots: list[Path], pruned: AbstractSet[str] = frozenset(DEFAULT_EXCLUDES)
    ) -> int:
        """Count directories and files under *roots*, stopping at ``_PROBE_LIMIT`` or ``_PROBE_SECONDS``.

        Directory names the walk prunes (``pruned``) are pruned here too, so
        the estimate reflects the tree that will actually be read. Every
        directory counts, so a tree of empty directories reaches the limit
        instead of being walked in full. A probe that runs out of time reports
        the limit too: a tree or filesystem that slow to list needs the
        largest deadline the estimate can propose.
        """
        seen = 0
        stop = time.monotonic() + cls._PROBE_SECONDS
        for root in roots:
            if not root.is_dir():
                seen += 1
                continue
            for _dirpath, dirnames, filenames in os.walk(root, onerror=lambda _exc: None):
                dirnames[:] = [d for d in dirnames if d not in pruned]
                seen += 1 + len(filenames)
                if seen >= cls._PROBE_LIMIT or time.monotonic() >= stop:
                    return cls._PROBE_LIMIT
        return seen


# A file over max_file_size that the scanner would read leaves coverage
# incomplete: unread content could hide agent configuration. Names matching
# these globs hold generated, locked or binary content that is explicitly
# outside the scan scope, so skipping them is a warning and the scan stays
# complete. The connector's `oversize_skip_globs` replaces the list.
# Coverage profiles: ``default`` charges every gap to the coverage budget or, for a
# gap it cannot bound, fails closed; ``ci`` declares the gaps a source gate accepts
# in advance (see ``FilesystemConnector._declared_omission``) and is refused under
# strict accounting (``coverage_profile``).
PROFILES: tuple[str, ...] = ("default", "ci")


def coverage_profile(
    config: dict[str, Any], *, strict_coverage: bool, connector: str = "code.filesystem"
) -> bool:
    """Check the coverage ``profile`` of ``config`` and return whether its gap budget is 0.

    ``config`` holds the filesystem options: ``profile``, the connector's own
    ``max_coverage_gap`` and the scan-wide ``_max_coverage_gap`` the engine
    injects. A budget of 0, like ``strict_coverage``, is strict accounting
    (docs/scanning.md#coverage-budget-and-strict-accounting): every gap counts, none is
    discounted or declared. The ``ci`` profile exists to declare gaps, so it is
    refused with either spelling of strict accounting, as a ConnectorError
    before anything is read.
    """
    profile = config.get("profile", "default")
    if ("profile" in config and profile is None) or profile not in PROFILES:
        raise ConnectorError(f"{connector}: profile must be default or ci")
    raw = config.get("max_coverage_gap")
    if raw is None:
        raw = config.get("_max_coverage_gap")
    try:
        zero_budget = raw is not None and validate_max_coverage_gap(raw) == 0.0
    except ValueError as exc:
        raise ConnectorError(f"{connector}: {exc}") from exc
    if profile == "ci" and (strict_coverage or zero_budget):
        setting = "strict_coverage" if strict_coverage else "a max_coverage_gap of 0"
        raise ConnectorError(
            f"{connector}: profile ci declares omissions that strict accounting ({setting}) reports as "
            "gaps; set one of them (strict_coverage and max_coverage_gap 0 are both strict accounting)"
        )
    return zero_budget
