"""Cross-surface correlation and gateway-to-code attribution.

``correlate`` links exact identifiers that share a verifiable scope and
reports name similarity, and identifiers whose shared scope cannot be
verified, as separate review candidates. ``correlate_runtime`` conservatively
attributes gateway telemetry to
static framework findings using only operator-configured exact caller/scope
bindings.  Gateway user agents are observations, not attestations: an
``observed`` result means the linked gateway recorded a timestamped request
bearing that framework fingerprint. ``correlate_lifecycle`` links endpoint
findings to running-process findings for the same tool on the same device.
"""

from __future__ import annotations

import gc
import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from itertools import combinations
from typing import Any

from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.utils.redaction import REDACTED
from shadowscan.utils.text import parse_timestamp, to_iso

# Display names, labels and identifiers compared after normalisation. They
# only ever produce review candidates.
_NAME_KEYS = (
    "agent_name",
    "name",
    "display_name",
    "app_slug",
    "okta_name",
    "developer_name",
    "schema_name",
    "app_id",
    "client_id",
    "msa_app_id",
    "bot_id",
    "principal",
    "caller",
    "repository",
    "project",
    "function_name",
    "agent_id",
)
# Metadata fields holding an identifier that is compared byte-for-byte.
_IDENTITY_KEYS = (
    "app_id",
    "client_id",
    "msa_app_id",
    "bot_id",
    "principal",
    "principal_id",
    "caller",
    "agent_id",
    "arn",
    "resource_id",
    "role",
)
# A Microsoft Entra application (client) id is reported as app_id or
# client_id by Entra and Azure managed identities, as the bot id of a Teams
# app and as an Azure Bot Service msaAppId: one identifier type.
_ENTRA_APPLICATION_ID = "entra-application-id"
_ENTRA_APPLICATION_FIELDS = frozenset(
    {"metadata.app_id", "metadata.client_id", "metadata.msa_app_id", "metadata.bot_id"}
)
_ENTRA_APPLICATION_CONNECTORS = frozenset({"identity.entra", "saas.microsoft-teams", "cloud.azure"})
# The identity namespace Finding.account holds, for connectors that document
# it as one. Elsewhere account and provider are labels (a gateway name, a JSON
# scope string, a vendor) and are never compared as identity scope.
_ACCOUNT_SCOPE = {
    "identity.entra": "entra-tenant",
    "saas.microsoft-teams": "entra-tenant",
    "cloud.aws": "aws-account",
    "cloud.azure": "azure-subscription",
    "cloud.gcp": "gcp-project",
}
_METADATA_SCOPE = {
    "tenant": "tenant",
    "tenant_id": "tenant",
    "workspace": "workspace",
    "workspace_id": "workspace",
}
# Scope keys a local identifier type must share before an equal value is an
# exact link. Other local identifiers need at least one shared scope key.
_REQUIRED_SCOPE = {_ENTRA_APPLICATION_ID: ("entra-tenant",)}
_GLOBAL_PREFIXES = ("arn:", "projects/", "/subscriptions/", "ocid1.")
_CONTROL_CHARACTER = re.compile(r"[\x00-\x1f\x7f]")
_PATTERN_CHARACTER = re.compile(r"[*?\[\]]")
_SPACE_OR_PATTERN = re.compile(r"[\s*?\[\]]")
_MAX_CORRELATION_GROUP = 25
_MAX_CORRELATION_PEERS = 24
_CANDIDATE_LIMITATION = (
    "Name similarity, or an identifier match whose shared tenant or account could not be verified, "
    "is a review hint, not proof of identity, ownership, runtime execution or authorization."
)


def _identity_text(value: object, *, allow_patterns: bool = False) -> str | None:
    """Keep exact identity bytes; never repair a missing, padded or redacted identity."""
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 2048
        or REDACTED.lower() in value.lower()
        or _CONTROL_CHARACTER.search(value)
        or (not allow_patterns and _PATTERN_CHARACTER.search(value))
    ):
        return None
    return value


def _normalise_key(s: Any) -> str | None:
    """Normalise a value for fuzzy cross-surface matching."""
    text = _identity_text(s, allow_patterns=True)
    if text is None:
        return None
    t = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return t if len(t) >= 5 else None


@lru_cache(maxsize=65536)
def _global_resource(value: str) -> tuple[str, tuple[tuple[str, str], ...]] | None:
    """Recognize fully qualified resource references without normalising their identifiers.

    The identifier itself is the scope: an ARN, a GCP resource name, an Azure
    resource id or an OCI OCID names its partition, account, project or
    subscription, so it needs no scope from the finding that reported it.
    """
    if _SPACE_OR_PATTERN.search(value):
        return None
    parts = value.split(":", 5)
    if len(parts) == 6 and parts[0] == "arn" and all(parts[i] for i in (1, 2, 5)):
        if parts[4] and not re.fullmatch(r"[0-9]{12}", parts[4]):
            return None
        # A missing account cannot turn a truncated workload ARN into a global
        # identity. Only accountless namespaces whose names are globally unique
        # (an S3 bucket, a Route 53 zone) are. AWS-managed policies
        # (arn:aws:iam::aws:policy/...) and Bedrock foundation models are
        # shared catalog entries every account references: an equal reference
        # says nothing about one workload, so it is neither a link nor a
        # candidate.
        if not parts[4] and parts[2] not in {"s3", "route53"}:
            return None
        scope = {"provider": "aws"}
        if parts[3]:
            scope["region"] = parts[3]
        if parts[4]:
            scope["account"] = parts[4]
        return "resource:aws-arn", tuple(sorted(scope.items()))
    components = value.split("/")
    if value.startswith("projects/") and len(components) >= 4 and all(components):
        if components[1] in {"-", ".", ".."} or any(p in {".", ".."} for p in components):
            return None
        scope = {"provider": "gcp", "account": components[1]}
        if len(components) >= 6 and components[2] in {"locations", "regions"}:
            scope["region"] = components[3]
        return "resource:gcp-name", tuple(sorted(scope.items()))
    if (
        value.startswith("/subscriptions/")
        and len(components) >= 7
        and all(components[1:])
        and not any(p in {".", ".."} for p in components)
    ):
        return "resource:azure-id", (("account", components[2]), ("provider", "azure"))
    if re.fullmatch(r"ocid1\.[a-z0-9]+\.[a-z0-9]+\.[a-z0-9-]*\.[A-Za-z0-9.]+", value):
        return "resource:oci-id", (("provider", "oci"),)
    return None


def _declared_scope(finding: Finding) -> dict[str, str] | None:
    """The identity scope a connector declares for its findings; ``None`` when it is unusable.

    Only namespaces with a documented meaning are used: a Microsoft tenant, a
    cloud account, subscription or project, or an explicit tenant/workspace
    in metadata. A redacted, padded or wildcard scope value refuses every link.
    """
    scope: dict[str, str] = {}
    account_key = _ACCOUNT_SCOPE.get(finding.connector)
    if account_key is not None and finding.account is not None:
        usable = _identity_text(finding.account)
        if usable is None:
            return None
        scope[account_key] = usable
    for key, canonical in _METADATA_SCOPE.items():
        value = finding.metadata.get(key)
        if value is None:
            continue
        usable = _identity_text(value)
        if usable is None or scope.get(canonical, usable) != usable:
            return None
        scope[canonical] = usable
    return scope


def _conflicts(left: dict[str, str], right: dict[str, str]) -> bool:
    return any(key in right and right[key] != value for key, value in left.items())


@dataclass
class _CorrelationKey:
    finding: Finding
    scope: dict[str, str]
    globally_scoped: bool
    fields: set[str] = field(default_factory=set)


_Groups = dict[tuple[str, str], dict[str, _CorrelationKey]]


def _identifier_kind(finding: Finding, source: str) -> str:
    if source in _ENTRA_APPLICATION_FIELDS and finding.connector in _ENTRA_APPLICATION_CONNECTORS:
        return _ENTRA_APPLICATION_ID
    if source == "resource":
        return f"resource:{finding.resource_type.split('/', 1)[0]}"
    if source == "metadata.agent_id":
        return f"{source}:{finding.resource_type.split('/', 1)[0]}"
    return source


def _correlation_keys(findings: list[Finding]) -> tuple[_Groups, _Groups]:
    """Group findings by exact identifier and by normalised name, computing each scope once."""
    exact: _Groups = {}
    names: _Groups = {}
    for finding in findings:
        declared = _declared_scope(finding)
        if declared is None:
            continue
        identifiers: list[tuple[str, object]] = [("resource", finding.resource)]
        identifiers.extend((f"metadata.{key}", finding.metadata.get(key)) for key in _IDENTITY_KEYS)
        identifiers.extend(
            (f"evidence[{number}].location", evidence.location)
            for number, evidence in enumerate(finding.evidence)
            if evidence.location and evidence.location.startswith(_GLOBAL_PREFIXES)
        )
        for source, raw in identifiers:
            value = _identity_text(raw)
            if value is None:
                continue
            qualified = _global_resource(value)
            if qualified is None and value.startswith(_GLOBAL_PREFIXES):
                continue
            if qualified is not None:
                kind, scope = qualified[0], dict(qualified[1])
            else:
                kind, scope = _identifier_kind(finding, source), declared
            group = exact.setdefault((kind, value), {})
            entry = group.setdefault(finding.id, _CorrelationKey(finding, scope, qualified is not None))
            entry.fields.add(source)
        labels: list[tuple[str, object]] = [
            (f"metadata.{key}", finding.metadata.get(key)) for key in _NAME_KEYS
        ]
        if finding.kind in {
            Kind.AGENT,
            Kind.BOT_APP,
            Kind.SERVICE_IDENTITY,
            Kind.OAUTH_GRANT,
            Kind.MCP_SERVER,
        }:
            tail = finding.title.split(":", 1)[1].strip() if ":" in finding.title else ""
            if len(tail) >= 8:
                labels.append(("title", tail))
        for source, raw in labels:
            normalised = _normalise_key(raw)
            if normalised is None:
                continue
            group = names.setdefault(("name", normalised), {})
            entry = group.setdefault(finding.id, _CorrelationKey(finding, declared, False))
            entry.fields.add(source)
    return exact, names


def _exact_scope(kind: str, left: _CorrelationKey, right: _CorrelationKey) -> bool:
    """Whether an equal identifier is exact: a global reference, or a local one in a verified shared scope."""
    if left.globally_scoped and right.globally_scoped:
        return True
    required = _REQUIRED_SCOPE.get(kind)
    if required is not None:
        return all(key in left.scope and key in right.scope for key in required)
    # One-sided tenant/account data must not silently widen a local identifier.
    return any(key in right.scope for key in left.scope)


def _add_link(
    links: dict[str, dict[str, list[dict[str, Any]]]],
    kind: str,
    first: str,
    second: str,
    left: _CorrelationKey,
    right: _CorrelationKey,
) -> None:
    first_links, second_links = links.get(first, {}), links.get(second, {})
    if (second not in first_links and len(first_links) >= _MAX_CORRELATION_PEERS) or (
        first not in second_links and len(second_links) >= _MAX_CORRELATION_PEERS
    ):
        return
    scope = dict(sorted({**left.scope, **right.scope}.items()))
    left_fields, right_fields = sorted(left.fields), sorted(right.fields)
    for source, target, own, other in (
        (first, second, left_fields, right_fields),
        (second, first, right_fields, left_fields),
    ):
        match = {"key_type": kind, "source_fields": own, "target_fields": other, "scope": scope}
        details = links.setdefault(source, {}).setdefault(target, [])
        if match not in details:
            details.append(match)


def _pairs(groups: _Groups) -> Any:
    shared = sorted(item for item in groups.items() if 1 < len(item[1]) <= _MAX_CORRELATION_GROUP)
    for (kind, _), members in shared:
        for first, second in combinations(sorted(members), 2):
            left, right = members[first], members[second]
            if (
                left.finding.connector == right.finding.connector
                and left.finding.surface == right.finding.surface
            ):
                continue
            if _conflicts(left.scope, right.scope):
                continue
            yield kind, first, second, left, right


def correlate(findings: list[Finding]) -> None:
    """Rebuild exact identifier relationships and separate, scoped review candidates.

    An exact edge proves only matching identifiers in the available declarations,
    not ownership, execution or approval. Provenance states which fields matched.
    Fuzzy names, and equal local identifiers without a verified shared tenant or
    account, are candidates: they never enter ``related`` or feed
    runtime/registry decisions. A conflicting declared tenant, account,
    subscription, project or workspace prevents both kinds of link; a vendor or
    gateway label is not scope.
    """
    for finding in findings:
        for key in ("related", "related_details", "related_candidates"):
            finding.metadata.pop(key, None)
    # The grouping below allocates many short-lived, acyclic containers. Cyclic
    # collection would rescan every finding repeatedly and make the pass
    # superlinear in large scans; reference counting frees them regardless.
    collecting = gc.isenabled()
    gc.disable()
    try:
        _correlate(findings)
    finally:
        if collecting:
            gc.enable()


def _correlate(findings: list[Finding]) -> None:
    identifier_groups, name_groups = _correlation_keys(findings)
    exact: dict[str, dict[str, list[dict[str, Any]]]] = {}
    fuzzy: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for kind, first, second, left, right in _pairs(identifier_groups):
        _add_link(exact if _exact_scope(kind, left, right) else fuzzy, kind, first, second, left, right)
    for kind, first, second, left, right in _pairs(name_groups):
        _add_link(fuzzy, kind, first, second, left, right)
    for finding in findings:
        if peers := exact.get(finding.id):
            finding.metadata["related"] = sorted(peers)
            finding.metadata["related_details"] = [
                {"finding_id": other, "assurance": "exact-identifier", "matches": peers[other]}
                for other in sorted(peers)
            ]
        candidates = {
            key: value
            for key, value in fuzzy.get(finding.id, {}).items()
            if key not in exact.get(finding.id, {})
        }
        if candidates:
            finding.metadata["related_candidates"] = [
                {
                    "finding_id": other,
                    "assurance": "candidate",
                    "matches": candidates[other],
                    "limitation": _CANDIDATE_LIMITATION,
                }
                for other in sorted(candidates)
            ]


def _usable_code_identity(code: Finding) -> bool:
    """Lossy report identities must never establish an exact workload binding."""
    return (
        isinstance(code.resource, str)
        and bool(code.resource)
        and REDACTED not in code.resource
        and all(
            value is None or (isinstance(value, str) and REDACTED not in value)
            for value in (code.provider, code.account, code.region)
        )
    )


def correlate_runtime(findings: list[Finding]) -> None:
    """Attach runtime_activity metadata without increasing risk or confidence."""
    bound = _trusted_bindings(findings)
    code_identities: dict[str, set[tuple[str | None, str | None, str | None, str]]] = {}
    for code in findings:
        if code.surface == Surface.CODE:
            code_identities.setdefault(code.resource, set()).add(
                (code.provider, code.account, code.region, code.connector)
            )

    for code in findings:
        if code.surface != Surface.CODE:
            continue
        # Repeated calls must replace earlier results, including after cache use.
        code.evidence[:] = [ev for ev in code.evidence if ev.signal != "runtime:gateway-observed"]
        code.metadata.pop("runtime_activity", None)
        if not code.frameworks:
            continue
        usable_identity = _usable_code_identity(code)
        ambiguous = len(code_identities.get(code.resource, set())) > 1
        relevant = [] if ambiguous or not usable_identity else bound.get(code.resource, [])
        matches, missing_timestamps = _framework_matches(code, relevant)
        if matches:
            activity = _observed_activity(code, matches)
        else:
            if not usable_identity:
                reason = "redacted-or-missing-code-identity"
            elif ambiguous:
                reason = "ambiguous-code-resource"
            elif not relevant:
                reason = "no-trusted-workload-binding"
            elif missing_timestamps:
                reason = "missing-event-timestamps"
            else:
                reason = "no-matching-framework-in-linked-telemetry"
            activity = {
                "status": "unknown" if not relevant or missing_timestamps else "unobserved",
                "reason": reason,
                "events": 0,
                "frameworks": [],
                "window": None,
                "last_seen": None,
                "production_observed": False,
                "production_label_verified": False,
                "sources": [],
                "limitations": (
                    "Absence in exported telemetry does not establish that the framework is inactive."
                ),
            }
        code.metadata["runtime_activity"] = activity


def _trusted_bindings(findings: list[Finding]) -> dict[str, list[tuple[Finding, dict[str, Any]]]]:
    """Map each code resource to the gateway observations that name it through a trusted binding."""
    bound: dict[str, list[tuple[Finding, dict[str, Any]]]] = {}
    for gateway in findings:
        if gateway.surface != Surface.GATEWAY:
            continue
        observations = gateway.metadata.get("runtime_observations", [])
        if not isinstance(observations, list):
            continue
        for observation in observations:
            if (
                not isinstance(observation, dict)
                or observation.get("identity_basis") != "configured-exact-caller-and-scope"
                or observation.get("identity_assurance")
                not in ("operator-asserted", "provider-authenticated-field")
            ):
                continue
            resources = observation.get("code_resources", [])
            if isinstance(resources, list):
                for resource in resources:
                    if isinstance(resource, str) and resource and REDACTED not in resource:
                        bound.setdefault(resource, []).append((gateway, observation))
    return bound


def _framework_matches(
    code: Finding,
    relevant: list[tuple[Finding, dict[str, Any]]],
) -> tuple[list[dict[str, Any]], bool]:
    """Return timestamped observations sharing a framework with ``code`` and whether any lacked timestamps."""
    matches: list[dict[str, Any]] = []
    missing_timestamps = False
    for gateway, observation in relevant:
        observed_frameworks = observation.get("frameworks", [])
        if not isinstance(observed_frameworks, list) or any(
            not isinstance(fw, str) for fw in observed_frameworks
        ):
            continue
        frameworks = sorted(set(code.frameworks).intersection(observed_frameworks))
        if not frameworks:
            continue
        first = parse_timestamp(observation.get("first_seen"))
        last = parse_timestamp(observation.get("last_seen"))
        events = observation.get("timestamped_events", 0)
        if not first or not last or last < first or not isinstance(events, int) or events <= 0:
            missing_timestamps = True
            continue
        matches.append(
            {
                "gateway_finding_id": gateway.id,
                "gateway_resource": gateway.resource,
                "source": observation.get("source", gateway.metadata.get("runtime_source", {})),
                "scope": observation.get("scope", {}),
                "frameworks": frameworks,
                "events": events,
                "first_seen": to_iso(first),
                "last_seen": to_iso(last),
                "environment": observation.get("environment"),
                "identity_basis": observation["identity_basis"],
                "identity_assurance": observation.get("identity_assurance", "unspecified"),
                "environment_assurance": observation.get("environment_assurance", "unspecified"),
            }
        )
    return matches, missing_timestamps


def _observed_activity(code: Finding, matches: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize matching observations and record them as zero-weight evidence on ``code``."""
    # Worker completion/configuration order cannot change provenance.
    matches.sort(key=lambda match: json.dumps(match, sort_keys=True))
    first_seen = min(match["first_seen"] for match in matches)
    last_seen = max(match["last_seen"] for match in matches)
    environments = sorted({match["environment"] for match in matches if match["environment"]})
    production_events = sum(
        match["events"] for match in matches if match["environment"] in {"production", "prod"}
    )
    activity = {
        "status": "observed",
        "basis": "gateway-telemetry",
        "events": sum(match["events"] for match in matches),
        "frameworks": sorted({fw for match in matches for fw in match["frameworks"]}),
        "window": {"start": first_seen, "end": last_seen},
        "last_seen": last_seen,
        "environments": environments,
        "production_observed": production_events > 0,
        "production_events": production_events,
        "production_label_verified": False,
        "sources": matches,
        "event_counting": (
            "Source observations; distinct exports may overlap and are not deduplicated into unique requests."
        ),
        "limitations": (
            "Export-window telemetry and spoofable framework fingerprints, not an execution "
            "attestation. Production is an event label, not a verified deployment identity; "
            "generic log identities require an operator assertion."
        ),
    }
    code.add_evidence(
        Evidence(
            signal="runtime:gateway-observed",
            description=(
                f"Linked gateway recorded {activity['events']} timestamped request(s) with matching "
                f"framework fingerprints between {first_seen} and {last_seen}"
            ),
            weight=0.0,
            attributes={
                "gateway_finding_ids": sorted({match["gateway_finding_id"] for match in matches}),
                "frameworks": activity["frameworks"],
            },
        )
    )
    return activity


# --------------------------------------------------------------------------
# Lifecycle corroboration: configured / installed → running

_LIFECYCLE_STATES: dict[tuple[Surface, Kind], str] = {
    (Surface.ENDPOINT, Kind.AGENT_CONFIG): "configured",
    (Surface.ENDPOINT, Kind.MCP_SERVER): "configured",
    (Surface.ENDPOINT, Kind.AI_APP): "installed",
    (Surface.ENDPOINT, Kind.LOCAL_MODEL): "installed",
    (Surface.RUNTIME, Kind.RUNTIME_PROCESS): "running",
}
_LIFECYCLE_ORDER = ("configured", "installed", "running")
_PACKAGE_VERSION = re.compile(r"(?<=.)@[^/@]*$")


def _device_key(value: str | None) -> str | None:
    """An exact device identity compared case-insensitively, retaining its DNS domain."""
    if not value or not isinstance(value, str):
        return None
    text = value.strip().lower()
    if not text or REDACTED.lower() in text:
        return None
    return text


def _package_key(value: object) -> str | None:
    if not isinstance(value, str) or not value or value.startswith("-"):
        return None
    return _PACKAGE_VERSION.sub("", value.strip().lower()) or None


# Runtime tool ids that name the same product as an endpoint client id.
_TOOL_ALIASES = {"kiro-cli": "kiro"}


def _tool_key(f: Finding) -> str | None:
    """The tool id of a client configuration or a running process (tools without a signature need it)."""
    if f.kind == Kind.RUNTIME_PROCESS:
        tool = f.metadata.get("tool")
    elif f.connector == "endpoint.inventory" and f.resource_type == "agent-config" and f.resource:
        tool = f.resource.rsplit(":", 1)[-1]
    else:
        return None
    if not isinstance(tool, str) or not tool:
        return None
    return _TOOL_ALIASES.get(tool, tool)


def _lifecycle_keys(f: Finding, device: str) -> set[tuple[str, str]]:
    """What a finding is about on its device: signature ids, the tool id, and MCP server packages."""
    keys = {(device, sid) for sid in f.frameworks + f.model_providers if sid != "protocol.mcp"}
    if (tool := _tool_key(f)) is not None:
        keys.add((device, f"tool:{tool}"))
    if f.kind == Kind.RUNTIME_PROCESS:
        packages = f.metadata.get("mcp_packages")
        for name in packages if isinstance(packages, dict) else ():
            if (key := _package_key(name)) is not None:
                keys.add((device, f"mcp-package:{key}"))
    elif f.kind == Kind.MCP_SERVER:
        servers = f.metadata.get("servers")
        for server in servers if isinstance(servers, list) else ():
            if not isinstance(server, dict) or server.get("disabled"):
                continue
            args = server.get("args")
            for arg in args if isinstance(args, list) else []:
                if (key := _package_key(arg)) is not None:
                    keys.add((device, f"mcp-package:{key}"))
    return keys


def correlate_lifecycle(findings: list[Finding]) -> None:
    """Link endpoint findings to processes of the same tool on the same device.

    A configured or installed tool with a running process on the same device
    is ``observed-running``. The link is recorded in ``metadata['lifecycle']``
    and as zero-weight evidence: corroboration changes neither confidence nor
    risk. Devices match by their full account/device identity; a short host name
    does not implicitly match an FQDN or a host in another DNS domain. MCP
    configurations match a running MCP server only through the same package.
    """
    groups: dict[tuple[str, str], list[Finding]] = {}
    for f in findings:
        # Repeated calls replace earlier results.
        f.metadata.pop("lifecycle", None)
        f.evidence[:] = [ev for ev in f.evidence if ev.signal != "lifecycle:observed-running"]
        if f.surface == Surface.ENDPOINT:
            # Endpoint runtime tags are derived from this pass. Runtime
            # process findings retain their own directly observed state.
            f.tags[:] = [tag for tag in f.tags if tag != "observed-running"]
        if _LIFECYCLE_STATES.get((f.surface, f.kind)) is None:
            continue
        device = _device_key(f.account)
        if device is None:
            continue
        for key in _lifecycle_keys(f, device):
            groups.setdefault(key, []).append(f)
    linked: dict[str, dict[str, Any]] = {}
    for (_, subject), members in groups.items():
        states = {_LIFECYCLE_STATES[(f.surface, f.kind)] for f in members}
        if "running" not in states or len(states) < 2 or len(members) > 50:
            continue
        running = [f for f in members if f.kind == Kind.RUNTIME_PROCESS]
        for f in members:
            entry = linked.setdefault(
                f.id, {"finding": f, "states": set(), "subjects": set(), "related": set()}
            )
            entry["states"].update(states)
            entry["subjects"].add(subject)
            entry["related"].update(o.id for o in members if o.id != f.id)
            if f.kind != Kind.RUNTIME_PROCESS:
                entry.setdefault("running", set()).update((o.owner or "", o.id) for o in running)
    for entry in linked.values():
        f = entry["finding"]
        lifecycle: dict[str, Any] = {
            "states": [s for s in _LIFECYCLE_ORDER if s in entry["states"]],
            "subjects": sorted(entry["subjects"]),
            "related": sorted(entry["related"])[:20],
        }
        if "running" in entry:
            same_user = sorted({fid for owner, fid in entry["running"] if owner and owner == f.owner})
            lifecycle["same_user"] = bool(same_user)
            f.add_tag("observed-running")
            f.add_evidence(
                Evidence(
                    signal="lifecycle:observed-running",
                    description=(
                        f"{len(entry['running'])} running-process finding(s) for the same tool on this device"
                        + (" and account" if same_user else "")
                    ),
                    weight=0.0,
                )
            )
        f.metadata["lifecycle"] = lifecycle
