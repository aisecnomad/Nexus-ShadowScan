"""Core data model shared by every connector, the engine and the reporters.

Everything ShadowScan discovers is normalised into a :class:`Finding`. A finding
describes *one thing that behaves like, or enables, an AI agent* on one surface,
together with the evidence that led to it, the frameworks / model providers it
uses, a confidence score, a risk assessment and (once reconciled against the
sanctioned inventory) whether it is a *shadow* agent.
"""

from __future__ import annotations

import datetime as _datetime
import decimal
import hashlib
import json
import math
import uuid
from collections import Counter
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field, fields
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from shadowscan.coverage import tolerated_gap_entries
from shadowscan.utils.redaction import (
    SanitizationLimitError,
    _check_sanitization_structure,
    policy_token,
    sanitize,
)
from shadowscan.utils.redaction_entropy import withhold_random_literals
from shadowscan.utils.redaction_rules import _MAX_SANITIZATION_NODES

FINDING_IDENTITY_SCHEMA = "shadowscan.finding-identity/v2"
LEGACY_FINDING_IDENTITY_SCHEMA = "shadowscan.finding-identity/v1"
# Metadata keys computed from the rest of a finding at export (shadowscan.mappings).
# They are never read back, so they cannot feed identity, risk, diff state,
# merging or the incremental cache. ``compliance`` is the removed earlier name.
DERIVED_METADATA_KEYS = frozenset({"threats", "controls", "compliance"})

# Digest of the state a completed sanitize() pass left behind, together with
# the redaction policy that verified it. Never serialized or compared.
_CleanState = tuple[bytes, tuple[Any, ...]]
_UNSET = object()


def _opaque(value: Any) -> str:
    """Stand in for values the sanitizer never rewrites, keyed by identity."""
    return f"<{type(value).__qualname__}:{id(value)}>"


def _clean_state(state: Any, *, bounded: bool) -> _CleanState | None:
    """Digest ``state`` under the redaction policy currently in force.

    ``bounded`` says the state is the sanitizer's own output, whose expanded
    size it already limited. Any other state is bounded here first, so
    digesting an alias graph can never cost more than sanitizing it would.
    ``None`` means the state has no deterministic serialization; every later
    pass then runs the sanitizer in full.
    """
    if not bounded:
        _check_sanitization_structure(state)
    try:
        encoded = json.dumps(state, default=_opaque, separators=(",", ":"))
    except (TypeError, ValueError, RecursionError):
        return None
    return hashlib.sha256(encoded.encode()).digest(), policy_token()


def _invalidate_on_change(instance: Any, name: str, value: Any) -> None:
    """Drop a verified-clean marker when a different value is assigned.

    Only a completed ``sanitize()`` restores the marker. Assigning the very
    same object changes nothing the digest does not already cover, so a
    connector re-stamping its own name keeps the finding clean.
    """
    if (
        name != "_clean_digest"
        and getattr(instance, "_clean_digest", None) is not None
        and getattr(instance, name, _UNSET) is not value
    ):
        object.__setattr__(instance, "_clean_digest", None)
    object.__setattr__(instance, name, value)


def _verified_clean(instance: Any) -> bool:
    """Whether the instance's current state is the one its last full pass verified.

    The marker is withdrawn before the comparison and restored only on a
    match, so a comparison that fails or raises leaves the instance marked
    dirty rather than trusting a digest of some earlier state.
    """
    marker = instance._clean_digest
    if marker is None:
        return False
    object.__setattr__(instance, "_clean_digest", None)
    if marker != _clean_state(instance._digest_state(), bounded=False):
        return False
    object.__setattr__(instance, "_clean_digest", marker)
    return True


def _validate_number(
    value: Any, name: str, *, minimum: float | None = None, maximum: float | None = None
) -> None:
    """Validate imported numeric fields without reflecting untrusted values."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"finding {name} must be a finite number")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError(f"finding {name} must be a finite number")
    if (minimum is not None and value < minimum) or (maximum is not None and value > maximum):
        raise ValueError(f"finding {name} is outside its allowed range")


_TEXT_FIELDS = (
    "provider",
    "account",
    "region",
    "owner",
    "registry_match",
    "first_seen",
    "last_seen",
    "id",
    "identity_discriminator",
    "identity_schema",
)
_TEXT_LIST_FIELDS = ("frameworks", "model_providers", "models", "capabilities", "permissions", "tags")


def _validate_shapes(d: dict[str, Any]) -> None:
    """Reject imported field shapes the pipeline cannot process, without reflecting values.

    The dataclass does not check types, while merging, registry matching and
    risk scoring index these fields directly. A report or cache entry with the
    wrong shape must fail at import, where callers already handle ValueError,
    rather than abort a later scan.
    """
    for name in _TEXT_FIELDS:
        if d.get(name) is not None and not isinstance(d[name], str):
            raise ValueError(f"finding {name} must be a string or null")
    for name in _TEXT_LIST_FIELDS:
        value = d.get(name, [])
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise ValueError(f"finding {name} must be a list of strings")
    if d.get("shadow") is not None and not isinstance(d["shadow"], bool):
        raise ValueError("finding shadow must be a boolean or null")
    if not isinstance(d.get("metadata", {}), dict):
        raise ValueError("finding metadata must be an object")


class Surface(str, Enum):
    """Where an agent (or agent enabler) was discovered."""

    CODE = "code"
    IDENTITY = "identity"
    GATEWAY = "gateway"
    LOWCODE = "lowcode"
    SAAS = "saas"
    CLOUD = "cloud"
    ENDPOINT = "endpoint"  # workstations and hosts: agent configs, extensions, local models, host inventories
    NETWORK = "network"  # DNS, TLS SNI and flow records
    RUNTIME = "runtime"  # AI tools seen running in process inventories


class Kind(str, Enum):
    """What kind of thing the finding describes."""

    AGENT = "agent"  # an actual agent (orchestrator use, cloud agent resource, bot...)
    FRAMEWORK_USAGE = "framework-usage"  # a project using an agent framework / LLM SDK
    MCP_SERVER = "mcp-server"  # Model Context Protocol server or client config
    AGENT_CONFIG = "agent-config"  # coding-agent / declarative agent configuration file
    OAUTH_GRANT = "oauth-grant"  # an OAuth grant / consented application
    SERVICE_IDENTITY = "service-identity"  # service principal, service account, M2M client
    TOKEN = "token"  # analysed JWT / API token  # noqa: S105 - a finding kind, not a credential
    GATEWAY_CALLER = "gateway-caller"  # principal calling an LLM API observed in logs
    WORKFLOW = "workflow"  # low-code flow / scenario / recipe with AI steps
    BOT_APP = "bot-app"  # SaaS bot / app installation
    CLOUD_RESOURCE = "cloud-resource"  # managed AI resource (endpoint, deployment, function...)
    IAM_GRANT = "iam-grant"  # IAM role / policy enabling LLM or agent access

    SECRET = "secret"  # an LLM credential in code / config  # noqa: S105 - a finding kind, not a credential
    INFRA = "infra"  # IaC or container definitions provisioning AI agents
    AI_APP = "ai-app"  # AI assistant application or editor/browser extension installed on an endpoint
    LOCAL_MODEL = "local-model"  # model weights stored for a local runtime (Ollama, LM Studio...)
    NETWORK_CONTACT = "network-contact"  # a host resolved or connected to an AI service
    RUNTIME_PROCESS = "runtime-process"  # a running process observed connecting to an AI service


class Likelihood(str, Enum):
    """A heuristic bucket of ``Finding.confidence``. It is not a verification state."""

    STRONG = "strong"  # >= 0.85
    LIKELY = "likely"  # >= 0.6
    POSSIBLE = "possible"  # >= 0.3
    WEAK = "weak"  # < 0.3

    @classmethod
    def _missing_(cls, value: object) -> Likelihood | None:
        # Reports, diff baselines and cache entries written before the rename carry "confirmed".
        return cls.STRONG if value == "confirmed" else None

    @classmethod
    def from_confidence(cls, confidence: float) -> Likelihood:
        if confidence >= 0.85:
            return cls.STRONG
        if confidence >= 0.6:
            return cls.LIKELY
        if confidence >= 0.3:
            return cls.POSSIBLE
        return cls.WEAK


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_score(cls, score: float) -> RiskLevel:
        if score >= 75:
            return cls.CRITICAL
        if score >= 50:
            return cls.HIGH
        if score >= 25:
            return cls.MEDIUM
        if score > 0:
            return cls.LOW
        return cls.INFO


def _evidence_value(name: str, value: Any) -> Any:
    """A sanitized evidence field, with random-looking literals also withheld from snippets."""
    if name == "snippet" and isinstance(value, str):
        return withhold_random_literals(value)
    return value


@dataclass(slots=True)
class Evidence:
    """A single observation supporting a finding."""

    signal: str  # machine readable id, e.g. "dependency:pypi:langchain"
    description: str  # human readable explanation
    location: str | None = None  # file:line, ARN, URL, object id...
    snippet: str | None = None  # short excerpt (secrets must be redacted before storing)
    weight: float = 0.5  # 0..1 contribution to confidence
    signature: str | None = None  # signature id that produced it, if any
    attributes: dict[str, Any] = field(default_factory=dict)
    _clean_digest: _CleanState | None = field(default=None, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        self.sanitize()

    def __setattr__(self, name: str, value: Any) -> None:
        if name == "weight":
            # Noisy-OR clamps weights, which turns NaN or a huge value into certainty.
            # Refuse them where they are set: a corrupt cache entry, report or plugin
            # must fail instead of becoming a strong finding.
            _validate_number(value, "evidence weight", minimum=0, maximum=1)
        _invalidate_on_change(self, name, value)

    def _digest_state(self) -> list[Any]:
        return [getattr(self, name) for name in _EVIDENCE_FIELDS]

    def sanitize(self) -> None:
        """Redact every field in place; a pass over verified-clean state is a no-op."""
        if _verified_clean(self):
            return
        # The schema keys are trusted code, while attributes can contain
        # attacker-controlled keys. Keep the former outside the sanitizer.
        # A field that resembles an argv flag must not reinterpret the next
        # dataclass field as its value. Real argv lists inside a field retain
        # their normal pair-aware redaction.
        values = sanitize([(getattr(self, name),) for name in _EVIDENCE_FIELDS])
        for name, (value,) in zip(_EVIDENCE_FIELDS, values, strict=True):
            setattr(self, name, _evidence_value(name, value))
        object.__setattr__(self, "_clean_digest", _clean_state(self._digest_state(), bounded=True))


@dataclass(slots=True)
class RiskFactor:
    id: str
    description: str
    weight: int


@dataclass(slots=True)
class Risk:
    score: int = 0
    level: RiskLevel = RiskLevel.INFO
    factors: list[RiskFactor] = field(default_factory=list)
    # Score without governance factors (registration, ownership): what the
    # agent can do, independent of whether anyone approved it.
    danger_score: int = 0


@dataclass(slots=True)
class Finding:
    surface: Surface
    connector: str
    kind: Kind
    title: str
    resource: str  # canonical, stable identifier of the discovered object
    resource_type: str  # e.g. "repository", "lambda-function", "oauth-app"
    provider: str | None = None  # platform / vendor hosting it (aws, okta, slack, github...)
    account: str | None = None  # tenant / org / account / project id
    region: str | None = None
    owner: str | None = None  # best-effort owner (user, team, email)
    frameworks: list[str] = field(default_factory=list)  # signature ids (framework.langchain...)
    model_providers: list[str] = field(default_factory=list)  # signature ids (provider.openai...)
    models: list[str] = field(default_factory=list)  # concrete model ids seen
    capabilities: list[str] = field(default_factory=list)  # tool-use, code-exec, memory, browsing...
    permissions: list[str] = field(default_factory=list)  # scopes / IAM actions / roles
    evidence: list[Evidence] = field(default_factory=list)
    confidence: float = 0.0
    likelihood: Likelihood = Likelihood.WEAK
    risk: Risk = field(default_factory=Risk)
    shadow: bool | None = None  # None: no inventory supplied; True: unregistered
    registry_match: str | None = None  # agent_id from the sanctioned inventory
    tags: list[str] = field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = ""
    # Stable observation type, independent of inferred kind. Connectors emitting
    # several observations of one resource/type must supply distinct values.
    identity_discriminator: str = ""
    identity_schema: str = FINDING_IDENTITY_SCHEMA
    _clean_digest: _CleanState | None = field(default=None, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not self.identity_discriminator:
            # Suffixes describe mutable platform classifications (for example
            # service-principal/ManagedIdentity and auth0-client/non_interactive).
            self.identity_discriminator = self.resource_type.split("/", 1)[0]
        if not self.id:
            self.id = self.compute_id()
        self.likelihood = Likelihood.from_confidence(self.confidence)
        self.sanitize()

    def __setattr__(self, name: str, value: Any) -> None:
        _invalidate_on_change(self, name, value)

    def _digest_state(self) -> list[Any]:
        """Every reportable value, flattened so nested objects digest by content."""
        return [
            [getattr(self, name) for name in _FINDING_SCALAR_FIELDS],
            [ev._digest_state() for ev in self.evidence],
            [self.risk.score, self.risk.level, [[f.id, f.description, f.weight] for f in self.risk.factors]],
        ]

    # ------------------------------------------------------------------ helpers
    def compute_id(self) -> str:
        if self.identity_schema == LEGACY_FINDING_IDENTITY_SCHEMA:
            raw = (
                f"{self.surface.value}|{self.connector}|{self.kind.value}|"
                f"{self.provider}|{self.account}|{self.resource}"
            )
        else:
            raw = json.dumps(
                [
                    self.identity_schema,
                    self.surface.value,
                    self.connector,
                    self.provider,
                    self.account,
                    self.region,
                    self.resource,
                    self.identity_discriminator,
                ],
                separators=(",", ":"),
                ensure_ascii=True,
            )
        return "ss-" + hashlib.sha256(raw.encode()).hexdigest()[:16]

    def reattribute(self, connector: str, *, derive_id: bool = False) -> None:
        """Attribute this finding to ``connector``, recomputing its id if it named another connector.

        The connector enters the id, so a finding built under another connector's name and only
        re-stamped would keep that connector's id, and could replace or merge with that
        connector's own finding for the same resource: baselines, diffs and fleet merges key on
        the id. An id the finding claimed under another name is not kept either.

        ``derive_id`` recomputes the id even when the finding already names ``connector``. The
        engine passes it for every plugin finding: a plugin can set any id (``id=`` or
        ``dataclasses.replace`` of a finding built under another name), and only the id derived
        from the plugin's own name can never be a built-in finding's.

        A connector name or id that is already the very text it would be set to is left in
        place, so a finding that already carries them stays verified clean. Anything else,
        including a ``str`` subclass that compares equal, is replaced with the plain text.
        """
        if self.connector != connector or derive_id:
            if type(self.connector) is not str or self.connector != connector:
                self.connector = connector
            derived = self.compute_id()
            if type(self.id) is not str or self.id != derived:
                self.id = derived

    def sanitize(self, *, credential_context: Any = None) -> None:
        """Remove credentials from every persisted/reportable field in place.

        A finding is sanitized many times between collection and reporting,
        and most passes see unchanged content. A pass over state already
        verified clean under the current redaction policy returns at once.
        The digest covers every field, nested evidence, risk factors and
        metadata by content, so a mutation made in place through a container
        is caught by the next pass exactly as an attribute assignment is.

        Producers that project only part of a source record can supply that
        record as ``credential_context``. Known secrets in omitted fields then
        also redact their copies in report fields. The context is never stored,
        and supplying it always performs a fresh pass, even on clean state.
        """
        if credential_context is None and _verified_clean(self):
            return
        if credential_context is not None:
            object.__setattr__(self, "_clean_digest", None)
        identity_names = (
            "connector",
            "resource",
            "resource_type",
            "provider",
            "account",
            "region",
            "identity_discriminator",
            "identity_schema",
        )
        identity_before = tuple(getattr(self, name) for name in identity_names)
        # A generated digest is an opaque identifier, even if a one-character
        # credential happens to occur among its hexadecimal digits. Imported
        # arbitrary IDs must still pass through the sanitizer.
        generated_id = self.id == self.compute_id()
        trusted_schema = self.identity_schema in {FINDING_IDENTITY_SCHEMA, LEGACY_FINDING_IDENTITY_SCHEMA}
        names = [
            name
            for name in _FINDING_SCALAR_FIELDS
            if not (generated_id and name == "id") and not (trusted_schema and name == "identity_schema")
        ]
        state = (
            [(getattr(self, name),) for name in names],
            [[(getattr(ev, name),) for name in _EVIDENCE_FIELDS] for ev in self.evidence],
            [[(factor.id,), (factor.description,)] for factor in self.risk.factors],
        )
        if credential_context is None:
            values, evidence_values, risk_values = sanitize(state)
        else:
            (values, evidence_values, risk_values), _ = sanitize((state, credential_context))
        for name, (value,) in zip(names, values, strict=True):
            setattr(self, name, value)
        changed = {
            name
            for name, original in zip(identity_names, identity_before, strict=True)
            if getattr(self, name) != original
        }
        # A verified raw-identity digest distinguishes redacted resources and
        # scopes; registry matching already rejects their placeholders. Never
        # allow a changed connector/type/discriminator or an arbitrary ID to
        # yield a misleading or colliding finding.
        if (
            self.id == "[REDACTED]"
            or changed
            & {
                "connector",
                "resource_type",
                "identity_discriminator",
                "identity_schema",
            }
            or (changed and not generated_id)
        ):
            raise SanitizationLimitError("finding identity includes a credential; finding omitted")
        for ev, clean in zip(self.evidence, evidence_values, strict=True):
            for name, (value,) in zip(_EVIDENCE_FIELDS, clean, strict=True):
                setattr(ev, name, _evidence_value(name, value))
        for factor, ((identifier,), (description,)) in zip(self.risk.factors, risk_values, strict=True):
            factor.id = identifier
            factor.description = description
        object.__setattr__(self, "_clean_digest", _clean_state(self._digest_state(), bounded=True))

    def add_evidence(self, ev: Evidence) -> None:
        ev.sanitize()
        self.evidence.append(ev)
        object.__setattr__(self, "_clean_digest", None)

    def update_metadata(self, **values: Any) -> None:
        """Set metadata keys through the model so the change is visibly recorded.

        In-place ``metadata`` edits are caught by the next ``sanitize()`` pass
        as well; this method exists for callers that prefer an explicit seam.
        """
        self.metadata.update(values)
        object.__setattr__(self, "_clean_digest", None)

    def add_framework(self, sig_id: str) -> None:
        if sig_id and sig_id not in self.frameworks:
            self.frameworks.append(sig_id)
            object.__setattr__(self, "_clean_digest", None)

    def add_model_provider(self, sig_id: str) -> None:
        if sig_id and sig_id not in self.model_providers:
            self.model_providers.append(sig_id)
            object.__setattr__(self, "_clean_digest", None)

    def add_capability(self, cap: str) -> None:
        if cap and cap not in self.capabilities:
            self.capabilities.append(cap)
            object.__setattr__(self, "_clean_digest", None)

    def add_tag(self, tag: str) -> None:
        if tag and tag not in self.tags:
            self.tags.append(tag)
            object.__setattr__(self, "_clean_digest", None)

    def recompute_confidence(self) -> None:
        """Noisy-OR combination of evidence weights over correlated groups.

        Evidence that shares a ``confidence_group`` attribute is one correlated
        observation and contributes only its strongest weight. Outside the code
        surface, evidence without one is grouped by ``signal``, so repeated
        matches against one record (several scopes of one permission class,
        several system prompts) cannot inflate the score. Source analysis sets
        its own groups; the distinct files and patterns of a single-file code
        finding (a workflow export, IaC) still corroborate each other.
        Independent groups reinforce each other but never exceed 1.0.
        """
        p_none = 1.0
        groups: dict[str, float] = {}
        by_signal = self.surface != Surface.CODE
        for number, ev in enumerate(self.evidence):
            w = max(0.0, min(1.0, ev.weight))
            group = ev.attributes.get("confidence_group")
            if isinstance(group, str):
                key = f"group:{group}"
            else:
                key = f"signal:{ev.signal}" if by_signal else f"evidence:{number}"
            groups[key] = max(groups.get(key, 0.0), w)
        for w in groups.values():
            p_none *= 1.0 - w
        self.confidence = round(1.0 - p_none, 3)
        self.likelihood = Likelihood.from_confidence(self.confidence)

    def to_dict(self) -> dict[str, Any]:
        self.sanitize()
        d = asdict(self)
        # Verified-clean markers are process-local state, never report content.
        d.pop("_clean_digest", None)
        from shadowscan.mappings import finding_references

        # Derived from this finding's own state on every export: a value carried
        # in from an older report, a cache entry or a plugin is never republished.
        metadata = d["metadata"]
        for key in DERIVED_METADATA_KEYS:
            metadata.pop(key, None)
        threats, controls = finding_references(self)
        if threats:
            metadata["threats"] = threats
        if controls:
            metadata["controls"] = controls
        for item in d["evidence"]:
            item.pop("_clean_digest", None)
        d["surface"] = self.surface.value
        d["kind"] = self.kind.value
        d["likelihood"] = self.likelihood.value
        d["risk"]["level"] = self.risk.level.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Finding:
        if not isinstance(d, dict):
            raise TypeError("finding must be an object")
        # Reports can carry newer display fields. Only accept known model
        # fields, while requiring the fields that define a usable identity.
        for name in ("surface", "connector", "kind", "title", "resource", "resource_type"):
            if not isinstance(d.get(name), str) or not d[name].strip():
                raise ValueError(f"finding {name} is required")
        d = {name: d[name] for name in _FINDING_FIELDS if name in d}
        _validate_shapes(d)
        # The add_* methods keep these lists free of repeats; a report, cache
        # entry or plugin result is canonicalized the same way at import, so a
        # repeated tag cannot count twice in risk scoring, merging or diffs.
        for name in _TEXT_LIST_FIELDS:
            if name in d:
                d[name] = list(dict.fromkeys(d[name]))
        if "metadata" in d:
            d["metadata"] = {k: v for k, v in d["metadata"].items() if k not in DERIVED_METADATA_KEYS}
        # Reading an old report preserves its identity rather than silently
        # relabeling old ids as v2. Upgrades require a freshly collected baseline.
        d.setdefault("identity_schema", LEGACY_FINDING_IDENTITY_SCHEMA)
        d["surface"] = Surface(d["surface"])
        d["kind"] = Kind(d["kind"])
        d["likelihood"] = Likelihood(d.get("likelihood", "weak"))
        _validate_number(d.get("confidence", 0.0), "confidence", minimum=0, maximum=1)
        d["risk"] = _risk_from_dict(d.get("risk"))
        evidence = d.get("evidence", [])
        if not isinstance(evidence, list) or any(not isinstance(item, dict) for item in evidence):
            raise ValueError("finding evidence must be objects")
        for item in evidence:
            if not isinstance(item.get("signal"), str) or not isinstance(item.get("description"), str):
                raise ValueError("finding evidence must have a string signal and description")
            for name in ("location", "snippet", "signature"):
                if item.get(name) is not None and not isinstance(item[name], str):
                    raise ValueError(f"finding evidence {name} must be a string or null")
            if not isinstance(item.get("attributes", {}), dict):
                raise ValueError("finding evidence attributes must be an object")
            _validate_number(item.get("weight", 0.5), "evidence weight", minimum=0, maximum=1)
        d["evidence"] = []
        for item in evidence:
            values = {name: value for name, value in item.items() if name in _EVIDENCE_FIELDS}
            observation = Evidence(**values)
            # Evidence.__post_init__ sanitizes in isolation. Preserve its raw
            # input until the owning Finding can discover credentials across
            # all sibling fields; otherwise a secret in evidence.attributes
            # is erased before its opaque copy in title/metadata is known.
            # These observations remain local until cls.__post_init__ performs
            # the collective, schema- and generated-identity-aware export pass.
            for name, value in values.items():
                setattr(observation, name, value)
            d["evidence"].append(observation)
        return cls(**d)


_RISK_FACTOR_FIELDS = frozenset({"id", "description", "weight"})


def _risk_from_dict(risk: Any) -> Risk:
    """A finding's imported ``risk`` object, validated; an absent one is the zero risk."""
    if risk is None:
        risk = {}
    if not isinstance(risk, dict):
        raise ValueError("finding risk must be an object")
    _validate_number(risk.get("score", 0), "risk score", minimum=0, maximum=100)
    factors = risk.get("factors", [])
    if not isinstance(factors, list) or any(not isinstance(factor, dict) for factor in factors):
        raise ValueError("finding risk factors must be objects")
    for factor in factors:
        if not isinstance(factor.get("id"), str) or not isinstance(factor.get("description"), str):
            raise ValueError("finding risk factors must have a string id and description")
        _validate_number(factor.get("weight"), "risk factor weight")
    _validate_number(risk.get("danger_score", 0), "risk danger score", minimum=0, maximum=100)
    return Risk(
        score=risk.get("score", 0),
        level=RiskLevel(risk.get("level", "info")),
        danger_score=risk.get("danger_score", 0),
        factors=[
            RiskFactor(**{name: value for name, value in factor.items() if name in _RISK_FACTOR_FIELDS})
            for factor in factors
        ],
    )


# Public model fields, in declaration order. The verified-clean marker is
# private state: never accepted from a report, serialized, or sanitized.
_EVIDENCE_FIELDS = tuple(attr.name for attr in fields(Evidence) if attr.name != "_clean_digest")
_FINDING_FIELDS = tuple(attr.name for attr in fields(Finding) if attr.name != "_clean_digest")
_FINDING_SCALAR_FIELDS = tuple(
    name for name in _FINDING_FIELDS if name not in {"surface", "kind", "likelihood", "risk", "evidence"}
)

# The leaf values a sanitize() pass leaves in a finding: text, numbers, None and the
# standard scalars it keeps (see shadowscan.utils.redaction). Each is immutable, so a
# detached copy shares it. Matched by the identity of the exact type, which neither a
# subclass nor a class with its own metaclass can imitate, and which runs no code of theirs.
_DETACHED_LEAF_TYPES = frozenset(
    id(kind)
    for kind in (
        type(None),
        str,
        int,
        float,
        bool,
        _datetime.date,
        _datetime.datetime,
        _datetime.time,
        _datetime.timedelta,
        decimal.Decimal,
        uuid.UUID,
    )
)
# The sanitizer's nesting limit (see _check_sanitization_structure).
_DETACHED_MAX_DEPTH = 64
_EVIDENCE_TEXT = ("location", "snippet", "signature")


class _Detacher:
    """Copy the plain data of one finding, within the sanitizer's own size and nesting limits.

    Containers are exact dicts with text keys, lists and tuples; each is read once
    with a single C-level copy, so a holder appending meanwhile is seen before or
    after its change. Every occurrence of an aliased container counts, as in
    ``_check_sanitization_structure``, so an alias graph cannot cost more here than
    sanitizing it would.
    """

    def __init__(self) -> None:
        self.nodes = 0

    def copy(self, value: Any, depth: int = 0) -> Any:
        self.nodes += 1
        if self.nodes > _MAX_SANITIZATION_NODES or depth > _DETACHED_MAX_DEPTH:
            raise SanitizationLimitError("finding exceeds the sanitizer's limits; not copied")
        kind = type(value)
        if id(kind) in _DETACHED_LEAF_TYPES:
            return value
        if kind is dict:
            copied = {}
            for key, child in list(value.items()):
                if type(key) is not str:
                    raise ValueError("finding holds a mapping key that is not text")
                copied[key] = self.copy(child, depth + 1)
            return copied
        if kind is list or kind is tuple:
            children = [self.copy(child, depth + 1) for child in list(value)]
            return children if kind is list else tuple(children)
        raise ValueError("finding holds a value that is not plain data")

    def text(self, value: Any, name: str) -> str:
        copied = self.copy(value)
        if type(copied) is not str:
            raise ValueError(f"finding {name} must be text")
        return copied


def _detached_marker(marker: Any) -> _CleanState | None:
    """A source's verified-clean marker when it has the shape ``sanitize()`` writes, else none.

    It is only ever compared with the digest of the copy's own content, so a marker
    that no longer matches costs a full pass and is never trusted.
    """
    if type(marker) is tuple and len(marker) == 2 and type(marker[0]) is bytes and type(marker[1]) is tuple:
        return marker
    return None


def _detached_evidence(evidence: Any, detacher: _Detacher) -> list[Evidence]:
    if type(evidence) is not list:
        raise ValueError("finding evidence must be a list")
    copies = []
    for item in list(evidence):
        if type(item) is not Evidence:
            raise ValueError("finding evidence must be Evidence objects")
        values = {name: detacher.copy(getattr(item, name)) for name in _EVIDENCE_FIELDS}
        # The shapes Finding.from_dict accepts for imported evidence.
        if type(values["signal"]) is not str or type(values["description"]) is not str:
            raise ValueError("finding evidence must have a string signal and description")
        if any(values[name] is not None and type(values[name]) is not str for name in _EVIDENCE_TEXT):
            raise ValueError("finding evidence location, snippet and signature must be text or null")
        if type(values["attributes"]) is not dict:
            raise ValueError("finding evidence attributes must be an object")
        _validate_number(values["weight"], "evidence weight", minimum=0, maximum=1)
        copy = object.__new__(Evidence)
        for name, value in values.items():
            object.__setattr__(copy, name, value)
        object.__setattr__(copy, "_clean_digest", _detached_marker(item._clean_digest))
        copies.append(copy)
    return copies


def _detached_risk(risk: Any, detacher: _Detacher) -> Risk:
    if type(risk) is not Risk or type(risk.level) is not RiskLevel or type(risk.factors) is not list:
        raise ValueError("finding risk must be a Risk")
    factors = []
    for factor in list(risk.factors):
        if type(factor) is not RiskFactor:
            raise ValueError("finding risk factors must be RiskFactor objects")
        weight = detacher.copy(factor.weight)
        _validate_number(weight, "risk factor weight")
        factors.append(
            RiskFactor(
                id=detacher.text(factor.id, "risk factor id"),
                description=detacher.text(factor.description, "risk factor description"),
                weight=weight,
            )
        )
    score, danger = detacher.copy(risk.score), detacher.copy(risk.danger_score)
    _validate_number(score, "risk score", minimum=0, maximum=100)
    _validate_number(danger, "risk danger score", minimum=0, maximum=100)
    return Risk(score=score, level=risk.level, factors=factors, danger_score=danger)


def detached_copy(finding: Any) -> Finding:
    """A copy of ``finding`` that shares no mutable state with it, safe while another thread holds it.

    Only what a ``sanitize()`` pass leaves is read: exact ``Finding``, ``Evidence``,
    ``Risk`` and ``RiskFactor`` objects, the model's enums, and dicts with text keys,
    lists, tuples, text, numbers, None and the standard scalars the sanitizer keeps.
    No code that a value's own class defines runs, so the holder can neither change
    the copy nor act through it. Anything else raises ``ValueError``, as do the field
    shapes ``from_dict`` refuses; nesting deeper, or an alias graph larger, than the
    sanitizer accepts raises ``SanitizationLimitError``, and a container the holder
    resizes while it is read can raise ``RuntimeError``.

    The copy keeps the source's verified-clean marker. Its next ``sanitize()`` checks
    that marker against the copy's own content, so a finding nobody changed since
    its last full pass costs a digest, not another pass, while a changed one is
    sanitized in full. Callers sanitize the copy before reporting it.
    """
    if type(finding) is not Finding:
        raise ValueError("not a Finding")
    detacher = _Detacher()
    values = {name: detacher.copy(getattr(finding, name)) for name in _FINDING_SCALAR_FIELDS}
    _validate_shapes(values)
    for name in ("connector", "title", "resource", "resource_type"):
        if type(values[name]) is not str or not values[name].strip():
            raise ValueError(f"finding {name} is required")
    _validate_number(values["confidence"], "confidence", minimum=0, maximum=1)
    enums = {"surface": finding.surface, "kind": finding.kind, "likelihood": finding.likelihood}
    if type(enums["surface"]) is not Surface or type(enums["kind"]) is not Kind:
        raise ValueError("finding surface and kind must be the model's")
    if type(enums["likelihood"]) is not Likelihood:
        raise ValueError("finding likelihood must be the model's")
    values.update(enums)
    values["evidence"] = _detached_evidence(finding.evidence, detacher)
    values["risk"] = _detached_risk(finding.risk, detacher)
    copy = object.__new__(Finding)
    for name, value in values.items():
        object.__setattr__(copy, name, value)
    object.__setattr__(copy, "_clean_digest", _detached_marker(finding._clean_digest))
    return copy


@dataclass(slots=True)
class ScanStats:
    connector: str
    started_at: str
    finished_at: str | None = None
    findings: int = 0
    objects_examined: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str | None = None
    cached: bool = False
    incomplete: bool = False
    #: Unread content this connector accounted for, whether or not it changed
    #: ``incomplete``. Published so that a tolerated gap is never invisible.
    #: See :mod:`shadowscan.coverage`.
    coverage: dict[str, Any] | None = None
    # Why the scan is incomplete: a count per reason category (see
    # ``shadowscan.connectors.base.INCOMPLETE_REASONS``) of the diagnostics that
    # left it so. Empty when the scan is complete; the diagnostics themselves
    # are in ``errors`` and ``warnings``.
    incomplete_reasons: dict[str, int] = field(default_factory=dict)
    # Coverage omissions a profile declared in advance (warnings that leave the
    # scan complete), so a complete scan under a profile is never read as a
    # scan that read everything.
    declared_omissions: int = 0
    #: Where those omissions lie, one path per omission in the order declared,
    #: at most ``shadowscan.coverage.MAX_DECLARED_PATHS``: a count above the
    #: list's length leaves the rest unlocated, so ``shadowscan diff`` holds
    #: back every missing project finding of the connector.
    declared_paths: list[str] = field(default_factory=list)
    #: The connector this record accounts for, as its findings name it
    #: (``Finding.connector``). ``connector`` is the configured id, which is
    #: the label when one is set, so only this joins findings to their
    #: record. None for the engine's own records.
    name: str | None = None


def merged_incomplete_reasons(parts: Iterable[ScanStats]) -> dict[str, int]:
    """Merge per-part incomplete-reason counts into one count per category.

    The one merge ``ScanResult.summary()`` and the engine's split-run
    aggregation share, so the two cannot drift (#264).
    """
    reasons: Counter[str] = Counter()
    for part in parts:
        reasons.update(part.incomplete_reasons)
    return dict(reasons)


@dataclass(slots=True)
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    stats: list[ScanStats] = field(default_factory=list)
    # Empty only when the report cannot be dated (a fleet merge with an undated source); it is
    # published as null.
    started_at: str = field(default_factory=lambda: now_iso())
    finished_at: str | None = None
    version: str = ""
    inventory_size: int = 0
    collection_scope: dict[str, Any] | None = None
    inventory_present: bool = False

    def __post_init__(self) -> None:
        for finding in self.findings:
            finding.sanitize()

    @property
    def complete(self) -> bool:
        """Only a scan whose requested connectors all completed is successful."""
        return bool(self.stats) and not any(s.errors or s.skipped or s.incomplete for s in self.stats)

    def summary(self) -> dict[str, Any]:
        by_surface: dict[str, int] = {}
        by_kind: dict[str, int] = {}
        by_level: dict[str, int] = {}
        frameworks: dict[str, int] = {}
        providers: dict[str, int] = {}
        shadow = 0
        for f in self.findings:
            f.sanitize()
            by_surface[f.surface.value] = by_surface.get(f.surface.value, 0) + 1
            by_kind[f.kind.value] = by_kind.get(f.kind.value, 0) + 1
            by_level[f.risk.level.value] = by_level.get(f.risk.level.value, 0) + 1
            for fw in f.frameworks:
                frameworks[fw] = frameworks.get(fw, 0) + 1
            for p in f.model_providers:
                providers[p] = providers.get(p, 0) + 1
            if f.shadow:
                shadow += 1
        reasons = merged_incomplete_reasons(self.stats)
        return {
            "complete": self.complete,
            "status": "complete" if self.complete else "incomplete",
            "total": len(self.findings),
            "shadow": shadow,
            "by_surface": by_surface,
            "by_kind": by_kind,
            "by_risk_level": by_level,
            "frameworks": dict(sorted(frameworks.items(), key=lambda kv: -kv[1])),
            "model_providers": dict(sorted(providers.items(), key=lambda kv: -kv[1])),
            "errors": sum(len(s.errors) for s in self.stats),
            # Why an incomplete scan is incomplete, by reason category, most frequent first. A
            # timed-out connector, and one left unstarted by timed-out workers, counts `timeout`;
            # one that failed or was skipped before it recorded a diagnostic has no entry.
            "incomplete_reasons": dict(sorted(reasons.items(), key=lambda kv: (-kv[1], kv[0]))),
            "declared_omissions": sum(s.declared_omissions for s in self.stats),
            # Entries left unread that a run's coverage budget tolerated: a complete
            # scan that skipped content says so, as a profile scan's omissions do.
            "tolerated_gaps": sum(tolerated_gap_entries(s.coverage) for s in self.stats),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "finding_identity_schema": FINDING_IDENTITY_SCHEMA,
            "started_at": self.started_at or None,
            "finished_at": self.finished_at,
            "inventory_size": self.inventory_size,
            "inventory_present": self.inventory_present,
            "collection_scope": sanitize(self.collection_scope),
            "summary": self.summary(),
            "stats": sanitize([asdict(s) for s in self.stats]),
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self, indent: int | None = 2) -> str:
        # RFC 8259 JSON has no representation for NaN or infinity.  Refuse to
        # publish a report that downstream controls would parse inconsistently.
        return json.dumps(self.to_dict(), indent=indent, default=str, allow_nan=False)


def now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()
