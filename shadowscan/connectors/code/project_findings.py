"""Construction of the code scan's findings from the observations of one walk.

``ProjectFindings`` is the findings collaborator of ``FilesystemConnector``
(ADR-005). After the walk, ``emit_findings`` yields one root's findings: the
inventory findings the file scan built, a finding per project (and, with
``agent_granularity: source``, per named source construction), per coding agent
configured in a project, per MCP configuration, agent manifest, exported
workflow, IaC file and file holding credentials. A failure while building one
finding is contained to its own diagnostic.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from collections.abc import Set as AbstractSet
from dataclasses import replace
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.code.catalogs import (
    CATALOG_MIN_SIGNATURES,
    catalog_metadata,
    deny_list_file,
    project_catalog_files,
    references_could_change,
)
from shadowscan.connectors.code.file_scan import FileScanner
from shadowscan.connectors.code.mcp_config import _mcp_client_for
from shadowscan.connectors.code.mcp_tools import mcp_tool_capabilities
from shadowscan.connectors.code.model_identifiers import (
    MODEL_IDS_ONLY_MAX_CONFIDENCE,
    MODEL_LITERAL_MAX_WEIGHT,
)
from shadowscan.connectors.code.ownership import OwnershipResolver
from shadowscan.connectors.code.path_context import (
    DOCS_MAX_CONFIDENCE,
    EXAMPLE_PATH_MAX_CONFIDENCE,
    GENERATED_MAX_CONFIDENCE,
    NEGATIVE_CONTEXT_TAGS,
    _is_test_path,
    negative_context,
)
from shadowscan.connectors.code.project_evidence import (
    ENV_ONLY_MAX_CONFIDENCE,
    WEAK_MENTION_WEIGHT,
    _mention,
    _Observation,
    _ProjectEvidence,
    _uncorroborated_signatures,
    _weak_mention_signatures,
)
from shadowscan.connectors.code.scan_records import _MCP_TRANSPORTS, FindingBase, _Project
from shadowscan.connectors.code.semantic_config import (
    a2a_card_metadata,
    a2a_card_tags,
    a2a_unsupported_protocol_version,
    parse_agent_manifest,
)
from shadowscan.connectors.code.semantic_config import bounded_metadata as _clip
from shadowscan.connectors.code.walk import TreeWalker, _is_coding_agent_doc, isolated
from shadowscan.connectors.common import apply_matches, cap_confidence, finalize, looks_like_placeholder
from shadowscan.connectors.mcp_risk import record_server_risks
from shadowscan.connectors.posture import record_approval, record_posture
from shadowscan.models import Evidence, Finding, Kind
from shadowscan.signatures import Match
from shadowscan.signatures.matcher import language_for_path, reported_credential
from shadowscan.utils.redaction import sanitize, sanitize_text
from shadowscan.utils.text import redact, truncate

if TYPE_CHECKING:  # filesystem imports this module
    from shadowscan.connectors.code.filesystem import _ScanState

# Manifests that configure the code of the project containing them. A2A cards
# and M365 declarative agents declare a separately addressable agent (its own
# name, endpoint and authentication) and stay findings of their own.
_PROJECT_MANIFESTS = frozenset({"crewai", "langgraph"})

# Signal types that establish a library in a project (see _emit_project).
_LIBRARY_SIGNALS = frozenset({"import", "dependency", "code"})
# Signals that name a product without configuring it.
_MENTION_SIGNALS = frozenset({"env", "name"})

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
# The ":<line>" suffix of an evidence location.
_LOCATION_LINE = re.compile(r":\d+\Z")


class ProjectFindings:
    """Builds the findings of one scanned root from what the walk observed (ADR-005).

    Owners come from the ownership collaborator, approval gates read whether the
    walk listed the whole root, and parser issues are recorded as the file scan
    records them.
    """

    def __init__(
        self,
        ctx: ConnectorContext,
        *,
        ownership: OwnershipResolver,
        walker: TreeWalker,
        file_scanner: FileScanner,
        base: FindingBase,
        root_prefix: Callable[[str], str],
        include_tests: bool,
        agent_granularity: str,
        owner: str | None,
        scan_timeout: float,
    ) -> None:
        self.ctx = ctx
        self.index = ctx.index
        self.ownership = ownership
        self.walker = walker
        self.file_scanner = file_scanner
        # Every finding carries the connector's identity (``FilesystemConnector._base``).
        self._base = base
        # Names the scan root in a diagnostic when the connector scans several roots
        # (``FilesystemConnector._root_prefix``, which reads the connector's configuration).
        self._root_prefix = root_prefix
        self.include_tests = include_tests
        self.agent_granularity = agent_granularity
        self.owner = owner  # the configured owner, which overrides CODEOWNERS
        self.scan_timeout = scan_timeout

    def emit_findings(self, scan: _ScanState) -> Iterator[Finding]:
        """Yield the findings of one walk; a failure is isolated to its own file or project."""
        label, root = scan.label, scan.root
        yield from scan.inventory_findings
        # Project findings are held back until the manifests are read: a
        # manifest inside a reported project describes that project's agent
        # and is folded into its finding instead of counting it twice.
        project_findings: dict[str, Finding] = {}
        yield from self._emit_projects(scan, project_findings)
        for rel, servers in scan.mcp_files:
            with (
                isolated(self.walker, rel, "MCP analysis", by_content=lambda: True),
                self.index.scan_budget(seconds=self.scan_timeout),
            ):
                yield self._mcp_finding(label, root, rel, servers)
        yield from self._emit_manifests(scan, project_findings)
        yield from project_findings.values()
        for rel, hits in scan.workflow_files.items():
            with isolated(self.walker, rel, "workflow analysis"):
                yield self._workflow_finding(label, root, rel, [*hits, *scan.workflow_providers.get(rel, [])])
        for rel, infra_hits in scan.infra_files.items():
            with isolated(self.walker, rel, "infrastructure analysis"):
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
            # A file read again at a link path (an agent-configuration alias) holds the
            # credentials of its real path: each is reported once, at the real path.
            real = self.walker.alias_real_path(rel)
            if real is not None and real in scan.secret_hits:
                seen = {(m.signature_id, m.value) for m, _ in scan.secret_hits[real]}
                hits = [(m, snippet) for m, snippet in hits if (m.signature_id, m.value) not in seen]
                if not hits:
                    continue
            with isolated(self.walker, rel, "credential analysis"):
                f = self._secret_finding(
                    label,
                    root,
                    rel,
                    hits,
                    limited=scan.secrets_limited.get(rel, set()),
                    project_root=scan.secret_project.get(rel, "."),
                )
                if f:
                    yield f

    def _emit_projects(self, scan: _ScanState, project_findings: dict[str, Finding]) -> Iterator[Finding]:
        """Yield coding-agent findings and hold each project finding in ``project_findings``."""
        # MCP configs, agent manifests, exported workflows and IaC produce their
        # own findings; a project finding built only from them is a duplicate.
        covered_files = scan.covered_files()
        for proj in scan.projects.values():
            with isolated(self.walker, proj.root, "project analysis"):
                for finding in self._emit_project(scan.label, scan.root, proj, covered_files):
                    if finding.resource_type == "project":
                        project_findings[proj.root] = finding
                    else:
                        yield finding

    def _emit_manifests(self, scan: _ScanState, project_findings: dict[str, Finding]) -> Iterator[Finding]:
        """Yield agent manifest findings; a project manifest is folded into its project's finding."""
        for rel, text, kind, proj_root in scan.card_files:
            with (
                isolated(self.walker, rel, "agent manifest analysis"),
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
        *,
        limited: AbstractSet[str] = frozenset(),
        project_root: str = ".",
    ) -> Finding | None:
        # A structured value (e.g. a .env assignment) and the raw text pass can
        # both observe the same credential on the same line, one as the value
        # and one as the whole assignment; count it once.
        # Placeholders are filtered again here so every caller shares the rule.
        unique: dict[tuple[str, str, int | None], tuple[Match, str]] = {}
        for m, snip in hits:
            credential = reported_credential(m)
            if not looks_like_placeholder(credential):
                unique.setdefault((m.signature_id, credential, m.line), (m, snip))
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
        # The distinct credentials: one written on several lines, or matched by
        # several patterns, counts once, and its evidence lists each location.
        f.metadata["count"] = len({reported_credential(m) for m, _ in hits})
        if limited:
            # The matcher stopped at its per-signal quota for these formats:
            # ``count`` is a lower bound, and the scan is already incomplete
            # (``_record_secret_limit``).
            f.metadata["secrets_limited"] = sorted(limited)
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
