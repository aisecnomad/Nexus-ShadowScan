"""Reading, redaction and analysis of one file of the code scan.

``FileScanner`` is the file-scan collaborator of ``FilesystemConnector``
(ADR-005). The walk hands it one file at a time (``scan_file``): it reads the
file relative to the opened scan root without following a link, prepares the
credential context its excerpts are redacted with, and dispatches it to the
credential, MCP, manifest, IaC, configuration and source passes, which record
what they observe on the file's project and the scan state. Queued cross-file
consumers are bound after the walk (``resolve_reexport_sources``).
"""

from __future__ import annotations

import re
from bisect import bisect_right
from collections.abc import Callable, Iterable, Sequence
from collections.abc import Set as AbstractSet
from dataclasses import replace
from functools import partial
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

import regex
import yaml

from shadowscan.connectors.base import ConnectorContext, incomplete_reason
from shadowscan.connectors.code import javascript_imports
from shadowscan.connectors.code.catalogs import (
    LOADER_EXTENSIONS,
    HostLineFilter,
    configuration_document,
    referenced_data_files,
)
from shadowscan.connectors.code.cross_file_sources import CrossFileSources
from shadowscan.connectors.code.dotnet_semantics import microsoft_tool_loop_matches
from shadowscan.connectors.code.excerpts import _excerpt, _ExcerptSource, _LazyExcerpt, _Snippet
from shadowscan.connectors.code.go_semantics import langchaingo_agent_matches
from shadowscan.connectors.code.instruction_content import MAX_TEXT_BYTES as MAX_INSTRUCTION_TEXT_BYTES
from shadowscan.connectors.code.instruction_content import inspect_instruction_text
from shadowscan.connectors.code.java_semantics import spring_tool_registration_matches
from shadowscan.connectors.code.javascript_imports import (
    JavascriptImportLimit,
    JavascriptToolResolver,
    has_javascript_tool_import,
)
from shadowscan.connectors.code.lockfiles import LOCKFILE_NAMES, LockInventory
from shadowscan.connectors.code.manifests import (
    Artifact,
    _pattern_timeout,
    is_manifest_name,
    manifest_comment_projection,
    parse_manifest,
)
from shadowscan.connectors.code.mcp_config import _parse_mcp_servers
from shadowscan.connectors.code.mcp_tools import MCPToolLimitError, mcp_tool_names
from shadowscan.connectors.code.model_artifacts import (
    ARTIFACT_SUFFIXES,
    ArtifactBudgetExhausted,
    inspect_artifact,
)
from shadowscan.connectors.code.model_identifiers import (
    _MODEL_KEY_VALUE_RE,
    _MODEL_LITERAL_CONFIG_EXTENSIONS,
    _MODEL_QUOTED_RE,
    _MODEL_ROUTE_PREFIXES,
    _MODEL_STEMS,
    MAX_MODEL_LITERAL_OCCURRENCES,
    MAX_MODEL_LITERALS_PER_FILE,
    MAX_MODEL_MATCHES_PER_SIGNATURE,
    _has_model_stem,
    _model_lookalike,
)
from shadowscan.connectors.code.path_context import _is_pipeline_file, _is_test_path
from shadowscan.connectors.code.python_reexports import (
    MAX_PENDING_BYTES,
    MAX_PENDING_FILES,
    ImportResolver,
)
from shadowscan.connectors.code.rule_packs import detection_rule_format
from shadowscan.connectors.code.scan_records import (
    _DEDICATED_MCP_CONFIG_NAMES,
    _MCP_TRANSPORTS,
    CREDENTIAL_FILE_NAMES,
    FindingBase,
    _bundled_signature,
    _document_declares_mcp,
    _env_values_file,
    _local_module_predicate,
    _MatchedSource,
    _names_mcp_key,
    _Project,
    _read_issue_reason,
    _SourceFile,
    _UndecodableFile,
)
from shadowscan.connectors.code.scan_records import _ENV_TEMPLATE_WORDS as _ENV_TEMPLATE_WORDS
from shadowscan.connectors.code.semantic_config import (
    agent_manifest_kind,
    is_agent_config_path,
    parse_agent_manifest,
    structured_code_matches,
)
from shadowscan.connectors.code.semantic_config import bounded_metadata as _clip
from shadowscan.connectors.code.skill_audit import audit_skill_text
from shadowscan.connectors.code.source_identity import named_construction_spans
from shadowscan.connectors.code.source_ranges import noncode_ranges, nul_reading_ranges
from shadowscan.connectors.code.source_semantics import (
    MAX_CALL_TEXT,
    SourceBudgetExceeded,
    SourceNotParsed,
    bound_source_matches,
    javascript_tool_exports,
)
from shadowscan.connectors.code.source_text import (
    _FRONTMATTER,
    _JSON_SUFFIXES,
    _NO_STRUCTURE,
    _YAML_SUFFIXES,
    _cell_noncode_ranges,
    _CellSpans,
    _comment_spans,
    _crawler_ua_text,
    _notebook_binder_source,
    _quote_glob_values,
    _quote_plain_values,
    _redacted_source,
    _structured_context,
    _within,
    _without_ipython_lines,
    _without_source_ranges,
    _without_xml_comments,
    foreign_cell,
)
from shadowscan.connectors.code.tool_attribution import ToolRegions
from shadowscan.connectors.code.walk import (
    _AGENT_DEFINITION_DIRS,
    _MCP_STRUCTURE_SUFFIXES,
    MCP_CONFIG_NAMES,
    TreeWalker,
    _analyzed_by_name,
    _guessed_mcp_name,
    _is_coding_agent_doc,
    _may_declare_mcp,
    _note_unread_settings,
    isolated,
)
from shadowscan.connectors.common import placeholder_reason
from shadowscan.connectors.posture import (
    CLIENT_SIGNATURES,
    approval_settings,
    canonical_settings_path,
    posture_client,
)
from shadowscan.connectors.posture import assess as assess_posture
from shadowscan.connectors.posture import parseable as posture_parseable
from shadowscan.models import Evidence, Kind
from shadowscan.signatures import Match
from shadowscan.signatures.matcher import (
    MAX_SECRETS_PER_SIGNAL,
    SOURCE_EXTENSIONS,
    _finditer,
    language_for_path,
    reported_credential,
)
from shadowscan.utils.git import LFS_POINTER_MAX_BYTES, LFS_POINTER_PREFIX
from shadowscan.utils.jsonc import load_json_lenient as _load_json_lenient
from shadowscan.utils.redaction import SanitizationLimitError, sanitize, sanitize_text
from shadowscan.utils.safe_json import JSONIntegrityError
from shadowscan.utils.safe_yaml import YAMLIntegrityError, YAMLResourceLimitError, strict_bounded_safe_load
from shadowscan.utils.text import (
    BINARY_CONTENT_ERROR,
    line_counter,
    notebook_to_source,
    notebook_without_binary_data,
    read_credential_text,
    read_text,
    redact,
    truncate,
)

if TYPE_CHECKING:  # filesystem imports this module
    from shadowscan.connectors.code.filesystem import _ScanState

# Registered MCP tool names retained per project.
_MAX_MCP_TOOLS = 200
# A notebook's binary output values are read for credentials in windows this long,
# overlapping by more than any credential's length.
_CREDENTIAL_WINDOW = 4096
_CREDENTIAL_OVERLAP = 256
# Server constructions listed under metadata.mcp_server; the capability does not
# depend on the list, so the bound is disclosed on the finding, not a coverage gap.
_MAX_MCP_SERVER_CONSTRUCTIONS = 50
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
# A container image that runs a CI job is a mention of that product at this
# share of the image signal's weight; a deployed image keeps full weight.
CI_IMAGE_WEIGHT_SCALE = 0.3

# The first line of a Git LFS pointer file (at most LFS_POINTER_MAX_BYTES long).
_LFS_POINTER_TEXT = LFS_POINTER_PREFIX.decode("ascii")


# Files that may be manifests whatever their name: IaC, compose, CI and deployment templates.
_MANIFEST_EXTENSIONS = frozenset({".tf", ".bicep", ".yml", ".yaml", ".json", ".hcl"})
# XML-based files whose comments are masked before content matching.
_XML_EXTENSIONS = frozenset({".xml", ".props", ".targets", ".csproj", ".fsproj", ".vbproj"})
# Structured files whose platform matches can describe an exported workflow.
_WORKFLOW_EXTENSIONS = frozenset({".json", ".yaml", ".yml"})


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


_MAX_CARD_FILES = 200
_MAX_AGENT_DEFINITIONS = 50


class FileScanner:
    """Reads, redacts and analyzes the files of the walk, one at a time (ADR-005).

    ``scan_file`` runs every analysis pass over one file and records what they
    observe; ``resolve_reexport_sources`` binds the queued cross-file
    consumers after the walk; ``file_errors`` records parser and validator
    issues, each a coverage gap.
    """

    def __init__(
        self,
        ctx: ConnectorContext,
        *,
        walker: TreeWalker,
        base: FindingBase,
        max_file_size: int,
        max_ast_nodes: int | None,
        scan_timeout: float,
        scan_secrets: bool,
        strict_coverage: bool,
        include_tests: bool,
        triage: bool,
        agent_granularity: str,
        model_metadata_bytes: int,
    ) -> None:
        self.ctx = ctx
        self.index = ctx.index
        # Size limits, artifact selection, read notes and lockfile gaps belong to the walk.
        self.walker = walker
        # Inventory findings (artifacts, lockfiles) carry the connector's identity.
        self._base = base
        self.max_file_size = max_file_size
        self.max_ast_nodes = max_ast_nodes
        self.scan_timeout = scan_timeout
        self.scan_secrets = scan_secrets
        self.strict_coverage = strict_coverage
        self.include_tests = include_tests
        self.triage = triage
        self.agent_granularity = agent_granularity
        self.model_metadata_bytes = model_metadata_bytes
        self.cross_file = CrossFileSources(self)

    def scan_file(self, scan: _ScanState, rel: str, path: Path, proj_root: str) -> None:
        """Run every analysis pass over one file of the walk."""
        proj = scan.projects.setdefault(proj_root, _Project(proj_root))
        scan.reexports.note_path(proj_root, rel)
        scan.python_dispatches.note_path(proj_root, rel)
        proj.files += 1
        self.ctx.examined()
        lang = language_for_path(rel)
        if lang:
            proj.languages.add(lang)

        if self.walker.model_artifact_name(path.name):
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
        credential_file = path.name.lower() in CREDENTIAL_FILE_NAMES
        if credential_file:
            # Only the credential pass reads a tool credential file, but its name is evidence
            # in every mode: '.codex/.netrc' configures Codex as '.codex/config.toml' does.
            self._record_name_matches(proj, rel, file_matches)
            if not self.scan_secrets or self.triage:
                return
        named = by_name or self.walker._named_by_signature(rel, file_matches)
        loaded = self._read_source(rel, path, scan.root_fd, scan.base, named=named)
        if isinstance(loaded, _UndecodableFile):
            _note_unread_settings(proj, rel)
            self._scan_undecodable_file(scan, proj, proj_root, rel, path, loaded, file_matches)
            return
        if loaded is None:
            _note_unread_settings(proj, rel)
            return
        text, raw_notebook, cells, foreign = loaded
        if credential_file or path.name.lower() in LOCKFILE_NAMES:
            read = _SourceFile(
                rel=rel,
                path=path,
                proj_root=proj_root,
                proj=proj,
                text=text,
                lang=lang,
                file_matches=file_matches,
            )
            if credential_file:
                self._scan_credential_file(scan, read)
            else:
                self._scan_lockfile(scan, read)
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
                        f"code.filesystem: {rel}: static instruction audit incomplete",
                        incomplete=True,
                        reason="analysis-limit",
                    )
            if any(rel in files for files in proj.coding_agent_files.values()):
                # Inspect the same confined snapshot as every other analysis pass.
                if len(text.encode("utf-8")) > MAX_INSTRUCTION_TEXT_BYTES:
                    self.ctx.warn(
                        f"code.filesystem: {rel}: instruction content exceeds inspection limit; "
                        "coverage incomplete",
                        incomplete=True,
                        reason="analysis-limit",
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
    ) -> tuple[str, str | None, _CellSpans, _CellSpans] | _UndecodableFile | None:
        """Read a file for analysis: its text and, for a notebook, the raw document and cell spans.

        A notebook's last element lists the cells declared another language (``_notebook_source``).

        The file is read relative to the open scan root ``root_fd``: by its on-disk
        name (``path`` below ``base``), while ``rel`` is the report-safe name used in
        diagnostics. A notebook's text is its code cells, and the spans locate each
        in it. None means nothing is analyzed; the recorded diagnostics say why.
        ``named`` is False when only a directory-wide signature glob selects the
        file, so a recognised binary artifact there (an image beside coding-agent
        rules) is skipped without a coverage gap. An ``_UndecodableFile`` means
        the file is binary or undecodable and its gap is discounted test code or a
        ``ci`` declaration (``_credential_only_read``): the caller reads it for
        credentials only (``_scan_undecodable_file``), and records the gap after.
        """
        read_errors: list[str] = []
        read_notes: list[str] = []
        on_disk = PurePosixPath(path.relative_to(base).as_posix()) if base is not None else PurePosixPath(rel)
        text = read_text(
            on_disk,
            self.walker.size_limit(path.name),
            read_errors,
            dir_fd=root_fd,
            analyzable_name=named,
            notes=read_notes,
        )
        for note in read_notes:
            self.walker.note_file(rel, note)
        undecodable = False
        for issue in read_errors:
            if issue == BINARY_CONTENT_ERROR and self.walker._credential_only_read(rel):
                # Read for credentials first, under every accounting; the gap is
                # recorded after that read: discounted, declared, or an error
                # under strict accounting (_scan_undecodable_file).
                undecodable = True
            elif self.strict_coverage:
                self.ctx.error(f"code.filesystem: {rel}: {issue}", reason=_read_issue_reason(issue))
            elif issue == "file exceeds max_file_size":
                self.walker._oversize_gap(rel, path.name, on_disk, root_fd)
            else:
                self.walker._unreadable_gap(rel, issue)
        if text is None:
            return _UndecodableFile(on_disk) if undecodable else None
        if len(text) <= LFS_POINTER_MAX_BYTES and text.startswith(_LFS_POINTER_TEXT):
            # A checkout made without git-lfs holds a pointer in place of the
            # file: its content was never read, whatever the name promises.
            message = f"code.filesystem: {rel}: Git LFS pointer file, not the content it stands for"
            if self.strict_coverage:
                self.ctx.error(f"{message}; coverage incomplete", reason="unscanned-input")
            else:
                self.walker._gap(rel, message, reason="unscanned-input")
            return None
        if path.suffix.lower() != ".ipynb":
            return text, None, (), ()
        return self._notebook_source(rel, text)

    def _holds_credential(self, value: str) -> bool:
        """Whether the credential pass matches anything in ``value``, read in overlapping windows."""
        return any(
            self.index.match_secrets(value[max(0, start - _CREDENTIAL_OVERLAP) : start + _CREDENTIAL_WINDOW])
            for start in range(0, len(value), _CREDENTIAL_WINDOW)
        )

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
        binary: list[str] = []
        text = notebook_to_source(document, notebook_errors, cells=sources, language=language, binary=binary)
        self.file_errors(rel, dict.fromkeys(notebook_errors), defect=True)
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
            # Code cells are analyzed as usual. Saved outputs are read only for
            # credentials: their text, once the base64 images, audio, video and
            # PDFs that make a notebook large are emptied, when that fits. A
            # notebook that did not parse whole is not rebuilt.
            outputs, removed = document, 0
            if not notebook_errors:
                # A credential spelled in the base64 alphabet can sit in a valid image's
                # value: a value the credential pass matches is kept and read with the text.
                binary = [part for part in binary if not self._holds_credential(part)]
                outputs, removed = notebook_without_binary_data(document, binary)
            if len(outputs) <= self.max_file_size:
                raw_notebook = outputs
                self.walker.note_file(
                    rel,
                    f"notebook over max_file_size; {removed:,} characters of base64 image, audio, video "
                    "and PDF output data not read, every text output scanned for credentials",
                )
            elif self.strict_coverage:
                gap = (
                    f"code.filesystem: {rel}: notebook over max_file_size; code cells analyzed, "
                    "saved outputs not scanned for credentials"
                )
            else:
                # Its code is analyzed, and its text outputs are data like any other
                # oversize file's: one whole entry of the budget (``_oversize_gap``).
                self.walker._budgeted_gap(
                    rel,
                    f"code.filesystem: {rel}: notebook over max_file_size; code cells analyzed, "
                    "text outputs over max_file_size not scanned for credentials; coverage gap",
                    full_weight=True,
                    reason="oversize-file",
                    unread_credentials=True,
                )
        if gap is not None:
            self.walker._gap(
                rel, gap, error=self.strict_coverage, reason="oversize-file", unread_credentials=True
            )
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
        # Only discounted test code is exempt (see _discounted_test_gap): its
        # credentials are still detected and its excerpts are still withheld.
        failure = type(exc).__name__
        # Content that would not parse is unparsed input; a resource or
        # sanitizer limit is the redaction context's own limit.
        integrity = isinstance(exc, (JSONIntegrityError, YAMLIntegrityError))
        self.walker._discounted_gap(
            rel,
            f"code.filesystem: {rel}: structured {stage} incomplete ({failure}); excerpts withheld",
            reason="unparsed-input" if integrity else "sanitization-limit",
        )

    def _input_defect(self, rel: str, issue: str, *, full_weight: bool = False) -> None:
        """Record a defect attributable to the file's own content.

        Templates and fixtures may be intentionally malformed, but the
        scanner cannot establish their content as fully analyzed. Preserve
        valid neighboring findings and mark coverage incomplete, except in
        discounted test code (see ``_discounted_test_gap``, which also takes
        ``full_weight``). ``strict_coverage`` promotes the diagnostic from
        warning to error; both forms fail closed.
        """
        message = f"code.filesystem: {rel}: input defect: {issue}"
        self.walker._discounted_gap(
            rel,
            message,
            error=self.strict_coverage,
            suffix=False,
            full_weight=full_weight,
            reason="unparsed-input",
        )

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

    def file_errors(
        self, rel: str, issues: Iterable[str], *, defect: bool = False, full_weight: bool = False
    ) -> None:
        """Record parser or validator issues for ``rel``.

        ``defect`` routes recognized input failures through
        :meth:`_input_defect` for a distinct diagnostic. Every issue marks
        coverage incomplete, regardless of diagnostic severity, except in
        discounted test code (see ``_discounted_test_gap``); ``full_weight``
        says the file is an MCP configuration by its structure, which is not
        discounted there either.

        These stay errors rather than budgeted coverage gaps. A parser or
        validator issue means a file the scanner *selected* -- a manifest, an
        agent card, a tool catalog -- could not be read, and that is the one
        place a definition would be hidden from it. The budget is for content
        whose loss is incidental; this is not. Incidental unreadable content
        is charged to the budget in :meth:`_unreadable_gap` instead.
        """
        for issue in issues:
            if defect and issue.startswith(self._SYNTAX_DEFECT_PREFIXES):
                self._input_defect(rel, issue, full_weight=full_weight)
            else:
                # The parser's own text, without the path, names the category; a
                # defect it does not name is still content that did not parse.
                category = incomplete_reason(issue)
                self.walker._discounted_gap(
                    rel,
                    f"code.filesystem: {rel}: {issue}",
                    full_weight=full_weight,
                    reason="unparsed-input" if category == "other" else category,
                )

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
        that analysis ends (``resolve_reexport_sources``).
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
            self.file_errors(file.rel, validation.errors, defect=True)
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
        with isolated(
            self.walker,
            file.rel,
            "credential detection",
            by_content=partial(self.walker._mcp_by_content, scan, file.rel, file.path),
        ):
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
        # In source code an unquoted value is an expression, so a generic match on
        # 'api_key = api_key' names a variable. A notebook's raw document is JSON
        # with outputs and markdown, where an unquoted value is printed text.
        code = file.lang is not None and not from_raw_notebook
        limited: set[str] = set()
        # Placeholders take no place in the quota and never count past it, so a
        # .env.example of sample keys reads as complete rather than exit 3.
        matches = self.index.match_secrets(
            raw,
            scan=file.literals,
            code=code,
            limited=limited,
            placeholder=placeholder_reason,
            env_file=not code and _env_values_file(file.path.name),
        )
        for m in matches:
            if (m.signature_id, m.value) in skip_values:
                continue
            key = (m.signature_id, m.value, m.line)
            if key in seen_secrets:
                continue
            seen_secrets.add(key)
            reason = placeholder_reason(reported_credential(m))
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
        self._record_secret_limit(scan.secrets_limited, file.rel, limited)

    def _detect_mcp(self, file: _SourceFile) -> None:
        """Parse an MCP client/server configuration.

        A server that declares itself disabled is still a configured server: the flag
        is client-specific (Cline and Roo honour it, Claude Code does not) and comes
        from the repository, so honouring it here would let a repository hide a server.
        """
        # The YAML parse decides whether a guessed file declares servers, so it is not parsed
        # twice; the server parser itself reloads YAML with string keys required.
        document = self._parsed_document(file, (*_JSON_SUFFIXES, ".toml", *_YAML_SUFFIXES))
        file.is_mcp = self._looks_like_mcp_config(file.rel, file.name, file.text, document) or (
            file.name.lower() == "server.json" and '"mcpServers"' in file.text
        )
        # Decided before the server parser runs, so a limit it reaches is the gap of
        # an MCP configuration (isolated, in walk.py).
        self.walker._content_mcp = file.is_mcp
        if file.is_mcp:
            mcp_errors: list[str] = []
            file.mcp_servers = _parse_mcp_servers(file.rel, file.text, mcp_errors, document)
            # An MCP configuration is reported at full weight in test code, so its defects are gaps there.
            self.file_errors(file.rel, dict.fromkeys(mcp_errors), defect=True, full_weight=True)
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
        self.file_errors(rel, dict.fromkeys(manifest.errors), defect=True)
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
                secrets_limited=scan.secrets_limited,
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
        self._javascript_path_config(scan, file)
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
        self.cross_file.index(scan, file, content_text)
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
        self.file_errors(file.rel, catalog_limits)

    def _defer_reexport_source(self, scan: _ScanState, source: _MatchedSource) -> bool:
        return self.cross_file.defer(scan, source, max_files=MAX_PENDING_FILES, max_bytes=MAX_PENDING_BYTES)

    def _javascript_path_config(self, scan: _ScanState, file: _SourceFile) -> None:
        if file.name == "package.json":
            scan.javascript_imports.note_package(file.rel)
        if file.name not in {"tsconfig.json", "jsconfig.json"}:
            return
        try:
            scan.javascript_imports.add_config(file.proj_root, file.rel, file.text)
        except (ValueError, RecursionError, JavascriptImportLimit):
            self.ctx.error(
                f"code.filesystem: {file.rel}: JavaScript path configuration analysis incomplete",
                reason="unparsed-input",
            )

    def _javascript_tool_candidate(self, scan: _ScanState, source: _MatchedSource) -> bool:
        """Snapshot a JavaScript module's eligible tool exports; whether it consumes imported tools."""
        file = source.file
        scan.javascript_imports.note_source(file.rel)
        if not self.include_tests and _is_test_path(file.rel):
            return False
        limited = len(file.text.encode("utf-8")) > javascript_imports.MAX_MODULE_BYTES
        try:
            exports = {} if limited else javascript_tool_exports(source.text, source.ignored)
        except SourceBudgetExceeded:
            exports, limited = {}, True
        scan.javascript_imports.add(file.proj_root, file.rel, exports, limited=limited)
        return has_javascript_tool_import(source.text)

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
            self.walker._discounted_gap(
                file.rel,
                f"code.filesystem: {file.rel}: incomplete source lexical analysis",
                reason="unparsed-input",
            )
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

    def _bind_source(
        self,
        source: _MatchedSource,
        *,
        resolve_import: ImportResolver | None = None,
        resolve_javascript_tool: JavascriptToolResolver | None = None,
        resolve_dispatch: Callable[[str, str], bool | None] | None = None,
        extra_bound: Sequence[Match] = (),
    ) -> None:
        """Add the import-bound calls of a matched source file and record its code evidence."""
        bound, unbound = self._bound_matches(
            source.file,
            source.text,
            source.ignored,
            source.is_local_module,
            resolve_import=resolve_import,
            resolve_javascript_tool=resolve_javascript_tool,
            resolve_dispatch=resolve_dispatch,
        )
        if not unbound:
            bound.extend(extra_bound)
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
        catalog. At most ``MAX_MODEL_LITERAL_OCCURRENCES`` literals with a
        vendor stem are read per pass, and ``MAX_MODEL_LITERALS_PER_FILE`` distinct
        ones matched (ordinary strings are skipped in the match
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
            MAX_MODEL_LITERAL_OCCURRENCES + 1,
            in_comment if starts else None,
            lambda m: _has_model_stem(m.group(2)),
        )
        limited = len(quoted) > MAX_MODEL_LITERAL_OCCURRENCES
        literals.extend((m.start(2), m.group(2)) for m in quoted[:MAX_MODEL_LITERAL_OCCURRENCES])
        if not source:
            keyed = _finditer(
                _MODEL_KEY_VALUE_RE,
                content_text,
                "model identifiers",
                MAX_MODEL_LITERAL_OCCURRENCES + 1,
                selected=lambda m: _has_model_stem(m.group(1)),
            )
            limited = limited or len(keyed) > MAX_MODEL_LITERAL_OCCURRENCES
            literals.extend((m.start(1), m.group(1)) for m in keyed[:MAX_MODEL_LITERAL_OCCURRENCES])
        # A literal's matches depend on its value alone, and a repeat was never
        # recorded twice (``seen`` below): each distinct value is matched once, at
        # its first offset, and the bound counts distinct values. A package's own
        # dotted module names ("llama_index.core", carrying the "llama" stem)
        # repeat throughout its mapping files.
        first: dict[str, int] = {}
        for offset, value in sorted(literals):
            first.setdefault(value, offset)
        limited = limited or len(first) > MAX_MODEL_LITERALS_PER_FILE
        literals = sorted((offset, value) for value, offset in first.items())[:MAX_MODEL_LITERALS_PER_FILE]
        if limited:
            self.walker._gap(
                file.rel,
                f"code.filesystem: {file.rel}: model identifiers read from the first "
                f"{MAX_MODEL_LITERALS_PER_FILE} distinct literals only; later ones were not matched",
                suffix=False,
                reason="analysis-limit",
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
        resolve_javascript_tool: JavascriptToolResolver | None = None,
        resolve_dispatch: Callable[[str, str], bool | None] | None = None,
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
                analyzed: list[int] = []
                source, unparsed, unread = _notebook_binder_source(
                    content_text, file.cells, file.foreign, analyzed
                )
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
                        notebook_cells=bool(analyzed),
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
                resolve_javascript_tool=resolve_javascript_tool,
                resolve_dispatch=resolve_dispatch,
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
            # A time budget is a timeout; an AST, call, nesting or recursion limit is not.
            reason = incomplete_reason(str(exc))
            if not self.include_tests and _is_test_path(file.rel):
                self.walker._strict_gap_warning(message, reason=reason)
            else:
                self.ctx.error(message, reason=reason)
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
                self.ctx.warn(message, incomplete=self.walker._strict_accounting(), reason="analysis-limit")
            else:
                self.ctx.error(message, reason="analysis-limit")
        return bound, list(file.unparsed)

    def _syntax_gap(self, file: _SourceFile) -> bool:
        """Whether source that does not parse leaves coverage incomplete.

        It does, except in a test path the scan discounts (include_tests off), where a
        deliberately invalid fixture is common: there it only warns, unless the accounting is
        strict (``_strict_accounting``), as for a source over the binder's budget.
        """
        return self.walker._strict_accounting() or self.include_tests or not _is_test_path(file.rel)

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
        text = _without_ipython_lines(file.text, file.cells) if file.cells else file.text
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
            self.ctx.error(
                f"code.filesystem: {file.rel}: {exc}; tool analysis incomplete", reason="analysis-limit"
            )
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
                        "tool analysis incomplete",
                        reason="analysis-limit",
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
        self.file_errors(rel, config_limits)
        for issue in config_errors:
            if is_agent_config_path(rel):
                self.ctx.error(f"code.filesystem: {rel}: {issue}", reason="unparsed-input")
            else:
                # Only the structured projection is lost; the
                # lexical env and domain passes still read this text.
                self.walker._strict_gap_warning(
                    f"code.filesystem: {rel}: {issue}; structured checks skipped", reason="unparsed-input"
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
                    "manifest skipped",
                    reason="analysis-limit",
                )
            else:
                scan.card_files.append((rel, file.text, file.card_kind, file.proj_root))
        if file.ext in {".md", ".mdc"} and any(directory in rel for directory in _AGENT_DEFINITION_DIRS):
            if len(file.proj.agent_defs) >= _MAX_AGENT_DEFINITIONS:
                self.ctx.error(
                    f"code.filesystem: {rel}: agent definition limit ({_MAX_AGENT_DEFINITIONS}) reached; "
                    "definition skipped",
                    reason="analysis-limit",
                )
            else:
                file.proj.agent_defs.append(self._parse_agent_definition(rel, file.text))

    def resolve_reexport_sources(self, scan: _ScanState) -> None:
        """Bind queued consumers after the walk has collected project snapshots."""
        self.cross_file.resolve(scan)

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
        secrets_limited: dict[str, set[str]],
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
            for m in self._image_matches(art):
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
                limited: set[str] = set()
                for m in self.index.match_secrets(val, limited=limited, placeholder=placeholder_reason):
                    m.line = art.line
                    # Judge the matched credential, not the whole assignment:
                    # a trailing comment must not hide a real key.
                    reason = placeholder_reason(reported_credential(m))
                    if reason:
                        self._record_example_credential(proj, m, rel, reason)
                        continue
                    secret_hits.setdefault(rel, []).append((m, f"{art.value}={redact(m.value)}"))
                    self._record(proj, m, rel, None)
                self._record_secret_limit(secrets_limited, rel, limited)
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

    def _image_matches(self, art: Artifact) -> list[Match]:
        """An image identifies Kubernetes only inside a parsed workload PodSpec."""
        return [
            match
            for match in self.index.match_image(art.value)
            if match.signature_id != "cloud.kubernetes-agent-workloads"
            or art.extra.get("kubernetes_workload") is True
        ]

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
        if lower in MCP_CONFIG_NAMES or rel.endswith(_MCP_STRUCTURE_SUFFIXES):
            return _content_declares_mcp(rel, text, document)
        return False

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
                    self.walker.note_file(
                        rel, "agent definition front matter quoted to parse (a plain value contained ': ')"
                    )
                except (ValueError, RecursionError, yaml.YAMLError):
                    self.ctx.error(
                        f"code.filesystem: {rel}: invalid agent definition YAML", reason="unparsed-input"
                    )
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

    def _scan_lockfile(self, scan: _ScanState, file: _SourceFile) -> None:
        """Inventory a lockfile's locked dependencies, then run the credential pass over it."""
        manifest = parse_manifest(file.rel, file.text)
        if manifest is not None:
            if manifest.lockfile_issue is not None:
                self.walker.lockfile_gap(file.rel, manifest.lockfile_issue)
            self.file_errors(file.rel, manifest.errors)
            if manifest.lockfile is not None:
                self._lockfile_inventory(scan, file.rel, manifest.lockfile)
        if self.scan_secrets and not self.triage:
            # A lockfile is a read file: the credential pass covers it
            # like any other text. A pinned registry or source URL can
            # embed a token that the dependency inventory never retains.
            file.structure, file.structure_strict = self._structure_for(file.rel, file.text)
            file.excerpts = _ExcerptSource(file.rel, file.path, file.text, file.structure)
            self._detect_secrets(scan, file)

    def _scan_credential_file(self, scan: _ScanState, file: _SourceFile) -> None:
        """Run the credential pass alone over a tool credential file (``CREDENTIAL_FILE_NAMES``).

        Such a file exists to hold a password or token, in a syntax the
        sanitizer may not know: netrc writes 'machine h login u password v',
        so an excerpt of any of its lines could show one. No other analysis
        reads it (a provider host in a netrc entry is where a credential
        goes, not usage of that provider), and no excerpt is cut from it: a
        credential finding names the file and line, and its count and
        providers, without the line.
        """
        # Matched as the other passes match a file (see _scan_file), without stray NUL bytes.
        file.text = file.text.replace("\x00", "")
        file.excerpts = _ExcerptSource(file.rel, file.path, file.text, None)
        self._detect_secrets(scan, file)

    def _record_name_matches(self, proj: _Project, rel: str, file_matches: list[Match]) -> None:
        """Record the file-name evidence of a file whose content no other pass reads.

        The evidence names the file and carries no content or snippet. MCP
        file names wait for a parsed configuration, as in ``_record_file_matches``.
        """
        for m in file_matches:
            if m.signature_id == "protocol.mcp":
                continue
            m.extra["verified_agent"] = False
            self._record(proj, m, rel, None)

    def _record_secret_limit(self, secrets_limited: dict[str, set[str]], rel: str, limited: set[str]) -> None:
        """Disclose that ``rel`` holds more credentials of a format than the matcher reports.

        The per-signal quota (:data:`MAX_SECRETS_PER_SIGNAL`) bounds the
        evidence one file can contribute, but a match past it is never read,
        so the scanner cannot tell a real key there from a placeholder. A scan
        that hid them would look complete while under-counting the one
        finding kind whose count is read literally, so the file is recorded
        as incomplete here and its finding carries ``secrets_limited`` (see
        ``_secret_finding``). Each format is named once per file, however
        many passes observe the quota.
        """
        new = limited - secrets_limited.get(rel, set())
        if not new:
            return
        secrets_limited.setdefault(rel, set()).update(new)
        # A credential limit is never declared, discounted or budgeted, under any
        # profile. Its reason is given, not read from the message, whose path may
        # hold another category's word ('src/http_client/keys.py' read as upstream).
        self.ctx.error(
            f"code.filesystem: {rel}: credential quota limit reached: more than {MAX_SECRETS_PER_SIGNAL} "
            f"credentials matched {', '.join(sorted(new))}; credential evidence incomplete",
            reason="analysis-limit",
        )

    def _syntax_warning(self, file: _SourceFile, message: str, *, notebook_cells: bool = False) -> None:
        """Record source that did not parse: a gap when ``_syntax_gap`` says so, else a plain warning.

        A gap goes through ``_gap``, so the ci profile declares it under a
        template, example or test path, and is counted as unparsed input.

        ``notebook_cells`` says other cells of the notebook parsed and hold code
        (blank, comment-only, magic-only and foreign cells do not count). Jupyter
        runs each cell alone, so the binder still read those cells and the
        failed ones keep their lexical evidence; tutorial notebooks hold
        placeholders (``api_key = <YOUR API KEY>``) and shell lines pasted into
        code cells on purpose. Such a notebook is one partial gap charged to the coverage budget
        at a whole entry, unless the accounting is strict, it is agent configuration (never budgeted)
        or the ci profile declares it; a tree of them still exhausts the budget.
        """
        if not self._syntax_gap(file):
            self.ctx.warn(message, incomplete=False)
        elif (
            notebook_cells
            and not self.walker._strict_accounting()
            and not self.walker._agent_configuration(file.rel)
            and not self.walker._declared_omission(file.rel)
        ):
            self.walker._ledger_gap(
                file.rel,
                f"{message}; the other cells were analyzed; coverage gap",
                full_weight=True,
                reason="unparsed-input",
            )
        else:
            self.walker._gap(file.rel, message, suffix=False, reason="unparsed-input")

    def _scan_undecodable_file(
        self,
        scan: _ScanState,
        proj: _Project,
        proj_root: str,
        rel: str,
        path: Path,
        fixture: _UndecodableFile,
        file_matches: list[Match],
    ) -> None:
        """Read a binary or undecodable file for credentials, the one evidence never discounted or declared.

        The file is a test fixture whose gap is discounted, or a documentation,
        example or generated file the ``ci`` profile declares
        (``_credential_only_read``). Its bytes are read as Latin-1 without NUL
        bytes (``read_credential_text``), so a key written in it is still found;
        nothing else is analyzed, no excerpt is cut from it, and its gap is
        recorded after: discounted, or declared with the read named. A file that
        cannot be read at all stays a gap.
        So does one whose text reads as an MCP configuration (``tests/agent.yaml``
        with ``mcpServers``, ``_binary_declares_mcp``), which is reported at full
        weight in test code too: a JSON, TOML or YAML fixture is read for that
        check even when credentials are not scanned, is then blinding like
        undecodable product content, never discounted or declared, and its
        servers are reported from that text when it parses. Strict accounting
        reads it too, and only then records its gap, as an error: it never finds
        fewer credentials than the default accounting.
        """
        message = f"code.filesystem: {rel}: {BINARY_CONTENT_ERROR}"
        analyzed = self.scan_secrets and not self.triage
        if not analyzed and not _guessed_mcp_name(rel, path.name):
            self.walker._discounted_gap(
                rel, f"{message}; not analyzed", reason="unparsed-input", charged_in_full=True
            )
            return
        errors: list[str] = []
        text = read_credential_text(
            fixture.on_disk, self.walker.size_limit(path.name), errors, dir_fd=scan.root_fd
        )
        if text is None:
            for issue in errors:
                self.ctx.error(f"code.filesystem: {rel}: {issue}", reason=_read_issue_reason(issue))
            return
        if analyzed:
            file = _SourceFile(
                rel=rel,
                path=path,
                proj_root=proj_root,
                proj=proj,
                text=text,
                lang=None,
                file_matches=file_matches,
            )
            # No structured context: none of a binary file's excerpts is emitted.
            file.excerpts = _ExcerptSource(rel, path, text, None)
            self._detect_secrets(scan, file)
        declares, document = self._binary_declares_mcp(rel, path.name, text)
        if declares:
            servers = _parse_mcp_servers(rel, text, [], document)
            if servers:
                scan.mcp_files.append((rel, servers))
            self.walker._unreadable_gap(rel, BINARY_CONTENT_ERROR, by_content=True)
            return
        self.walker._discounted_gap(
            rel,
            f"{message}; {'read for credentials only' if analyzed else 'not analyzed'}",
            reason="unparsed-input",
            charged_in_full=True,
        )

    def _binary_declares_mcp(self, rel: str, name: str, text: str) -> tuple[bool, Any]:
        """Whether the NUL-stripped text of an undecodable file declares MCP servers, and its parse.

        Decided as for a readable file the MCP parser judges by its content
        (``_guessed_mcp_name``): parsed with the same bounded loader
        (``_structured_context``), the structure decides (``_looks_like_mcp_config``),
        so a quoted (``'mcpServers':``), spaced, explicit (``? mcpServers``) or
        escaped key and a TOML inline table or literal key are read as the client
        reads them. Text that does not parse to a mapping or a list is read for
        any spelling of a server table key (``_may_declare_mcp``) instead of
        being taken to declare none. The parse is returned when it is a mapping
        or a list, else None.
        """
        if not _guessed_mcp_name(rel, name):
            return False, None
        try:
            document = _structured_context(rel, text)
        except (JSONIntegrityError, YAMLIntegrityError, YAMLResourceLimitError, SanitizationLimitError):
            document = None
        if isinstance(document, dict | list):
            return self._looks_like_mcp_config(rel, name, text, document), document
        return _may_declare_mcp(text.encode("latin-1", "replace").lower()), None


_WORKFLOW_FILE = re.compile(r"(?:^|/)\.github/workflows/[^/]+\.ya?ml$")


def _yaml_declares_mcp(text: str) -> bool | None:
    """Whether a YAML file's structure configures MCP servers; None when it cannot be read.

    The text search for MCP keys also finds them inside string values: a
    workflow step that writes an MCP configuration with a heredoc, a template
    or a transcript. Read with the configuration loader, which accepts
    non-string keys (a GitHub workflow's ``on:``), the structure decides. A
    file this loader cannot read is left to the MCP parser, so its defect or
    limit still marks coverage incomplete.
    """
    try:
        data = strict_bounded_safe_load(text, require_string_keys=False)
    except (ValueError, RecursionError, yaml.YAMLError):
        return None
    return _document_declares_mcp(data)


def _mentions_mcp_keys(text: str) -> bool:
    """Whether ``text`` names an MCP server table key anywhere: the cheap check that comes first.

    Used when no parse of the file is held. Substring and anchored searches are
    linear, so the whole (size-bounded) text is read rather than a prefix a server
    can be pushed past. A hit is only a candidate: a YAML file's structure then
    decides (``_yaml_declares_mcp``), and a file without a hit is never parsed for it.
    """
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


def _content_declares_mcp(rel: str, text: str, document: Any) -> bool:
    """Whether a file the MCP parser decides by its content declares servers; ``document`` is its parse.

    Decided from the parsed structure when it is held (JSON, TOML, and the YAML
    every structured file is parsed into once): leading padding before the keys
    then cannot hide a server table. A JSON object must be decided
    structurally; a string search of a prefix could miss the keys. An array
    declares servers only in a mapping it holds (``_document_declares_mcp``),
    never in a transcript's ``mcp_servers`` status list. Past the walk's
    bounds the text decides, by a key-shaped spelling only (``_names_mcp_key``):
    an issue export quoting a client's configuration in a string is no MCP
    configuration.

    With no parse held (it failed, or the syntax was rejected) any spelling of
    a key the client would read, quoted or escaped, keeps the file a candidate
    (``_text_may_declare_mcp``), so its defect is recorded at full weight; a
    YAML file's structure, parsed only now that the text names a key, then
    decides, and a file it cannot read goes to the MCP parser. Workflows keep
    the text search: their servers are JSON strings in step inputs, which
    ``_embedded_workflow_mcp`` reads.
    """
    if _WORKFLOW_FILE.search(rel) is not None:
        return _mentions_mcp_keys(text)
    if document is not None:
        declared = _document_declares_mcp(document)
        return declared if declared is not None else _names_mcp_key(rel, text)
    if not _text_may_declare_mcp(text):
        return False
    if rel.endswith(_YAML_SUFFIXES):
        declared = _yaml_declares_mcp(text)
        if declared is not None:
            return declared
    return True


def _text_may_declare_mcp(text: str) -> bool:
    """``_may_declare_mcp`` of decoded text: its bytes lower-cased, without NUL characters."""
    return _may_declare_mcp(text.replace("\x00", "").encode("utf-8", "replace").lower())
