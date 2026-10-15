"""How a project's observations count toward its finding.

``_ProjectEvidence`` applies the precision safeguards of the
``shadowscan.connectors.code.filesystem`` module docstring: mentions and
lexical code patterns establish nothing without corroboration, evidence in
tests, documentation, examples and generated files is discounted, and a
project known only from environment-variable names or model identifiers is
capped below the strong confidence band.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from shadowscan.connectors.code.excerpts import _Snippet
from shadowscan.connectors.code.model_identifiers import MODEL_LITERAL_MAX_WEIGHT
from shadowscan.connectors.code.path_context import NegativeContext, _is_test_path, negative_context
from shadowscan.signatures import Match

# Signals that mention a product (a host, a variable, a display name) rather
# than declare, import, configure or run it. A model identifier read from a
# data file (``extra["data_mention"]``) and a job image in a CI pipeline
# (``extra["ci_image"]``) are mentions too; see ``_mention``.
_MENTION_SIGNAL_TYPES = frozenset({"domain", "env", "name"})
# Signals that corroborate a code pattern of the same signature: the library is
# declared, imported, configured by name, deployed, or one of its models is
# named (a model id in a Modelfile, in IaC, or as a literal in code or
# configuration). An import-bound call (``extra["import_bound"]``), a
# recognised configuration shape (``extra["config_projection"]``) and a
# manifest artifact (``extra["manifest_artifact"]``) corroborate as well; see
# ``_uncorroborated_signatures``.
_CORROBORATING_SIGNALS = frozenset({"import", "dependency", "file", "image", "iac", "model"})
# A signature whose evidence in a project is only mentions, none of them at
# this weight or more, is recorded as potential (``metadata.potential_*``),
# not established. The two-tier domain weights (``huggingface.co`` 0.15 against
# ``router.huggingface.co`` 0.8) were written as corroboration-only hints.
WEAK_MENTION_WEIGHT = 0.3


# Environment-variable names alone are a weak signal (see module docstring):
# weights are halved and confidence stays inside the "likely" band.
ENV_ONLY_WEIGHT_SCALE = 0.5
ENV_ONLY_MAX_CONFIDENCE = 0.8


_Observation = tuple[Match, str, _Snippet]  # match, relpath, snippet


def _mention(m: Match) -> bool:
    """Whether ``m`` names a product without declaring, importing, configuring or running it."""
    return (
        m.signal.type in _MENTION_SIGNAL_TYPES
        or bool(m.extra.get("data_mention"))
        or bool(m.extra.get("ci_image"))
    )


def _corroborates(m: Match) -> bool:
    """Whether ``m`` shows the library of its signature is declared, imported, configured or deployed.

    A CI job image (``extra["ci_image"]``) is a mention: the pipeline runs a
    container, it does not deploy or install the library, so it corroborates
    nothing, whatever its signal type.
    """
    if m.extra.get("ci_image"):
        return False
    return (
        m.signal.type in _CORROBORATING_SIGNALS
        or bool(m.extra.get("import_bound"))
        or bool(m.extra.get("config_projection"))
        or bool(m.extra.get("manifest_artifact"))
    )


def _uncorroborated_signatures(
    observations: Iterable[_Observation], in_tests: Callable[[str], bool]
) -> set[str]:
    """Signatures whose project evidence is lexical code patterns no library evidence backs.

    A lexical code match (``extra["lexical_source"]``: every code match in a
    language without an import binder, and in Python or JavaScript a framework
    pattern the binder did not claim) is a word that other code can use too,
    whatever the language: Spring AI's ``ToolCallback`` is a Rust trait name,
    LangChain's ``create_agent(`` a Goose function, ``AgentType.Validate(`` a
    Semantic Kernel method. It establishes the library only when the same
    signature also has an import, a dependency, a file-name, image, IaC or
    model match, an import-bound call, a recognised configuration shape or a
    manifest artifact somewhere in the project, or a mention (a host, a
    variable, a display name) strong enough to establish the product on its
    own (``WEAK_MENTION_WEIGHT`` after the test-path discount): a C# client
    built against ``contoso.openai.azure.com`` is Azure OpenAI, a Rust
    ``create_agent(`` next to a documentation link is not LangChain. Python
    and JavaScript code patterns of provider, protocol, platform and
    cloud-service signatures are written for idioms of generic SDKs
    (``boto3.client("bedrock-agent-runtime")``) and stay supporting evidence,
    as before. Heuristics are judged elsewhere.
    """
    corroborated: set[str] = set()
    lexical: set[str] = set()
    for m, rel, _ in observations:
        if m.signature.category == "heuristic":
            continue
        if _corroborates(m) or (
            m.signal.type != "code" and m.weight * (0.5 if in_tests(rel) else 1.0) >= WEAK_MENTION_WEIGHT
        ):
            corroborated.add(m.signature_id)
        elif m.signal.type == "code" and m.extra.get("lexical_source"):
            lexical.add(m.signature_id)
    return lexical - corroborated


def _weak_mention_signatures(
    observations: Iterable[_Observation], in_tests: Callable[[str], bool]
) -> set[str]:
    """Signatures whose project evidence is only mentions, all below ``WEAK_MENTION_WEIGHT``.

    A model-hub link in a comment, an OAuth endpoint or a gallery entry names a
    product at a weight written as corroboration. Alone, such mentions are
    recorded as potential technology, never as a provider or framework the
    project uses. The test-path discount applies; the env-names-only halving
    does not, so a configured variable at weight 0.5 still establishes.
    """
    strongest: dict[str, float] = {}
    anchored: set[str] = set()
    for m, rel, _ in observations:
        if m.signature.category == "heuristic":
            continue
        # A model id in a test file names what the test exercises, as a host there does.
        if _mention(m) or (m.extra.get("model_literal") and in_tests(rel)):
            weight = min(m.weight, MODEL_LITERAL_MAX_WEIGHT) if m.extra.get("model_literal") else m.weight
            scaled = weight * (0.5 if in_tests(rel) else 1.0)
            strongest[m.signature_id] = max(strongest.get(m.signature_id, 0.0), scaled)
        else:
            anchored.add(m.signature_id)
    return {sid for sid, weight in strongest.items() if sid not in anchored and weight < WEAK_MENTION_WEIGHT}


class _ProjectEvidence:
    """How a project's observations count toward its finding (see the module docstring)."""

    def __init__(
        self,
        observations: list[_Observation],
        *,
        discount_tests: bool,
        mcp_tools: dict[str, str],
        project_root: str = ".",
    ) -> None:
        self.discount_tests = discount_tests
        # Environment-variable and display-name references are weak
        # anchors, so they are judged before heuristics join: an agent
        # loop or subprocess.run next to a .env.example must not promote
        # the project to a strong agent with autonomous or code-exec
        # capabilities. Such a finding is built from the name references
        # alone. A live credential is not a name: it keeps full weights
        # and lets the heuristics count. Every anchor is non-heuristic,
        # so the judgement below is never vacuous.
        technology = [m for m, _, _ in observations if m.signature.category != "heuristic"]
        self.env_only = all(m.signal.type in {"env", "name"} for m in technology)
        # Model identifiers alone name what the code may call, not an SDK it
        # installs: the finding is built from them, capped below the strong
        # band, and heuristics are dropped as for name references.
        self.model_ids_only = bool(technology) and all(m.extra.get("model_literal") for m in technology)
        if self.env_only:
            self.matches = [t for t in observations if t[0].signal.type in {"env", "name"}]
        elif self.model_ids_only:
            self.matches = [t for t in observations if t[0].extra.get("model_literal")]
        else:
            self.matches = observations
        self.library_evidence = {
            m.signature_id for m, _, _ in self.matches if m.signal.type in {"import", "dependency"}
        }
        self.uncorroborated = _uncorroborated_signatures(self.matches, self.in_tests)
        self.weak_mentions = _weak_mention_signatures(self.matches, self.in_tests)
        # Capabilities describe what the deployed code can do. Evidence
        # from tests (unless the project is only tests) and vendor-neutral
        # idioms in an MCP tool server (whose tools are read below) is
        # kept as evidence but implies no capability.
        self.test_only = discount_tests and all(_is_test_path(rel) for _, rel, _ in self.matches)
        java_tool_types = {
            m.extra["java_tool_type"]
            for m, rel, _ in self.matches
            if m.extra.get("java_tool_type") and (self.test_only or not self.in_tests(rel))
        }
        for m, _, _ in self.matches:
            if m.extra.get("java_tool_registration_type"):
                verified = m.extra["java_tool_registration_type"] in java_tool_types
                m.extra["verified_agent"] = verified
                m.extra["source_capabilities"] = ["tool-use"] if verified else []
        # Tools registered only in tests imply nothing, like other test evidence.
        self.server_tools = {
            tool: rel for tool, rel in mcp_tools.items() if self.test_only or not self.in_tests(rel)
        }
        # The project implements an MCP server: a server construction, transport
        # or tool registration outside tests, corroborated by the SDK (an
        # import binding, or library evidence for a lexical pattern).
        self.server_implemented = any(
            self.mcp_server_evidence(m, rel) and m.signature_id not in self.uncorroborated
            for m, rel, _ in self.matches
        )
        # A tool server's capabilities come from its tools; vendor-neutral idioms
        # in its code describe the tools, not an agent. Execution sinks still
        # count (see implies_capabilities), as do the capabilities its own
        # protocol evidence implies when no tool name was recognised.
        self.mcp_server = (bool(self.server_tools) or self.server_implemented) and {
            m.signature_id for m, _, _ in self.matches if m.signature.category != "heuristic"
        } == {"protocol.mcp"}

        self.negative_contexts: dict[str, NegativeContext] = {}
        if discount_tests:
            for _, rel, _ in self.matches:
                if rel not in self.negative_contexts:
                    ctx = negative_context(rel, project_root)
                    if ctx is not None:
                        self.negative_contexts[rel] = ctx
        self.docs_only = (
            bool(self.negative_contexts)
            and all(rel in self.negative_contexts for _, rel, _ in self.matches if not _is_test_path(rel))
            and any(
                self.negative_contexts.get(rel, NegativeContext("", 1.0)).reason == "documentation"
                for _, rel, _ in self.matches
            )
        )
        self.example_only = (
            bool(self.negative_contexts)
            and all(rel in self.negative_contexts for _, rel, _ in self.matches if not _is_test_path(rel))
            and any(
                self.negative_contexts.get(rel, NegativeContext("", 1.0)).reason == "example-code"
                for _, rel, _ in self.matches
            )
        )
        self.generated_only = (
            bool(self.negative_contexts)
            and all(rel in self.negative_contexts for _, rel, _ in self.matches if not _is_test_path(rel))
            and any(
                self.negative_contexts.get(rel, NegativeContext("", 1.0)).reason == "generated-code"
                for _, rel, _ in self.matches
            )
        )
        # 4a: Cross-signal corroboration — track which independent signal
        # type categories are present so the scoring phase can reward diversity.
        signal_types: set[str] = set()
        for m, rel, _ in self.matches:
            if m.signature.category != "heuristic" and not self.in_tests(rel):
                signal_types.add(m.signal.type)
        self.has_library_and_code = bool(signal_types & {"import", "dependency"} and signal_types & {"code"})
        diverse_types = signal_types & {"import", "dependency", "code", "file", "domain", "env"}
        self.has_multi_signal = len(diverse_types) >= 3

    def in_tests(self, rel: str) -> bool:
        return self.discount_tests and _is_test_path(rel)

    def established(self, signature_id: str) -> bool:
        """Whether the project's evidence for ``signature_id`` establishes that technology.

        Code patterns without library evidence and mentions below
        ``WEAK_MENTION_WEIGHT`` stay potential: their evidence is kept, but
        they join neither ``frameworks[]`` nor ``model_providers[]``.
        """
        return signature_id not in self.uncorroborated and signature_id not in self.weak_mentions

    def mcp_server_evidence(self, match: Match, rel: str) -> bool:
        """Whether ``match`` is MCP server code evidence that counts (not test-only).

        The ambiguous ``Server(`` pattern names HTTP and socket servers in
        projects that only use an MCP client, and a lexical construction the
        binder did not resolve in a file without the SDK's server import may
        name a local class: neither establishes a server. The bound
        construction, the specific idioms and their registrations do.
        """
        return (
            match.signature_id == "protocol.mcp"
            and match.signal.type == "code"
            and "mcp-server" in match.signal.capabilities
            and not match.signal.ambiguous
            and not match.extra.get("mcp_construction_unbound")
            and (self.test_only or not self.in_tests(rel))
        )

    def verified_indicator(self, match: Match) -> bool:
        if match.signature.category == "heuristic" or match.signature_id == "protocol.mcp":
            return False
        if not self.established(match.signature_id):
            return False
        if "verified_agent" in match.extra:
            return bool(match.extra["verified_agent"])
        if match.extra.get("lexical_source"):
            return match.agent_indicator and match.signature_id in self.library_evidence
        return match.agent_indicator

    def implies_capabilities(self, match: Match, rel: str) -> bool:
        if match.signal.type in {"import", "dependency", "env", "name"} or match.extra.get("model_literal"):
            return False
        if not self.established(match.signature_id):
            return False
        if self.in_tests(rel) and not self.test_only:
            return False
        if match.extra.get("contextual_capabilities"):
            return False
        if (
            match.signature.category == "framework"
            and match.extra.get("lexical_source")
            and match.signature_id not in self.library_evidence
        ):
            return False
        # Tool names are not an exhaustive description of their implementations.
        # An independently observed execution sink must survive when a harmless
        # named tool is added, or when a tool's name does not mention commands.
        return not (
            self.mcp_server
            and match.signature.category == "heuristic"
            and match.signature_id not in {"heuristic.code-execution", "heuristic.llm-command-execution"}
        )

    def weight_scale(self, rel: str) -> float:
        base = ENV_ONLY_WEIGHT_SCALE if self.env_only else 1.0
        if self.in_tests(rel):
            base *= 0.5
        ctx = self.negative_contexts.get(rel)
        if ctx is not None:
            base *= ctx.weight_scale
        return base
