"""Bounded, non-scoring CloudTrail provenance and exact assumed-session links.

Only allowlisted metadata is retained. Access keys, session tokens, request
bodies and response credentials are never part of a lineage observation.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, TypeGuard

from shadowscan.connectors.cloud.aws_registry import text
from shadowscan.utils.redaction import REDACTED
from shadowscan.utils.text import parse_timestamp, to_iso

MAX_LINEAGE_EVENTS = 10000  # per principal; the caller's invocation tally is never bounded by it
MAX_CALLER_OBSERVATIONS = 100
MAX_ASSUMPTION_HOPS = 8
ASSUME_OPERATIONS = frozenset({"AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity"})
_FIELDS = (
    "eventID",
    "eventName",
    "eventSource",
    "eventTime",
    "_region",
    "recipientAccountId",
    "principal",
    "identityType",
    "sessionIssuerArn",
    "sourceIdentity",
    "sessionCreatedAt",
    "assumedRoleArn",
    "roleArn",
    "sessionExpiresAt",
    "errorCode",
)
_ARN = re.compile(r"arn:(aws(?:-[a-z-]+)?):(iam|sts)::([0-9]{12}):(role|assumed-role)/(.+)")
# CloudTrail renders STS credential expirations as "Jan 20, 2024, 3:16:07 PM" (UTC).
_CLOUDTRAIL_TIME_FORMAT = "%b %d, %Y, %I:%M:%S %p"


def _object(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("malformed CloudTrail object")
    return value


def normalize_detail(detail: dict[str, Any], region: str | None = None) -> dict[str, Any]:
    """Project a raw event into the connector export contract; never copy credentials."""
    ident = _object(detail.get("userIdentity"))
    session = _object(ident.get("sessionContext"))
    issuer = _object(session.get("sessionIssuer"))
    attrs = _object(session.get("attributes"))
    request = _object(detail.get("requestParameters"))
    response = _object(detail.get("responseElements"))
    assumed = _object(response.get("assumedRoleUser"))
    credentials = _object(response.get("credentials"))
    raw = {
        "_kind": "cloudtrail-event",
        "_region": detail.get("awsRegion") or region,
        "eventID": detail.get("eventID"),
        "eventName": detail.get("eventName"),
        "eventTime": detail.get("eventTime"),
        "eventSource": detail.get("eventSource"),
        "recipientAccountId": detail.get("recipientAccountId"),
        "principal": ident.get("arn") or ident.get("principalId"),
        "identityType": ident.get("type"),
        "userAgent": detail.get("userAgent"),
        "sourceIp": detail.get("sourceIPAddress"),
        "modelId": request.get("modelId") or request.get("agentId"),
        "errorCode": detail.get("errorCode"),
        "sessionIssuerArn": issuer.get("arn"),
        "sourceIdentity": session.get("sourceIdentity") or request.get("sourceIdentity"),
        "sessionCreatedAt": attrs.get("creationDate"),
        "assumedRoleArn": assumed.get("arn"),
        "roleArn": request.get("roleArn"),
        "sessionExpiresAt": credentials.get("expiration"),
    }
    if any(v is not None and not isinstance(v, str) for v in raw.values()):
        raise ValueError("malformed CloudTrail field")
    # Identity fields must never be truncated into a different, apparently exact identity.
    if any(isinstance(v, str) and len(v) > 2048 for v in raw.values()):
        raise ValueError("oversized CloudTrail field")
    return {k: text(v, 2048) for k, v in raw.items()}


def _parse_time(value: Any) -> datetime | None:
    """CloudTrail's display format first: ``parse_timestamp`` reads it as RFC 2822 and drops the meridian."""
    if isinstance(value, str):
        try:
            return datetime.strptime(value, _CLOUDTRAIL_TIME_FORMAT).replace(tzinfo=UTC)
        except ValueError:
            pass
    return parse_timestamp(value)


def _usable(value: Any) -> TypeGuard[str]:
    return isinstance(value, str) and bool(value) and REDACTED.lower() not in value.lower()


class CloudTrailLineage:
    """Retain event provenance and link only an unambiguous, unexpired exact session."""

    def __init__(self, warn: Callable[..., None]) -> None:
        self.warn = warn
        self.seen: dict[tuple[str, str, str], str] = {}
        self.limits: set[str] = set()
        self.retained: dict[str, int] = {}
        # Principals whose ancestry the per-principal event limit bounded: a disclosed
        # provenance limit, never a coverage gap.
        self.partial: set[str] = set()
        # Callers whose observation sample the per-caller cap truncated: later
        # invocation events are counted, not listed.
        self.sampled: set[str] = set()
        self._events: dict[str, list[dict[str, Any]]] = {}
        # STS hops keyed by the exact pair ``_matches`` requires, the session ARN
        # they created and their normalized creation time, so a trace reads only
        # the candidates that can match instead of every hop into that session.
        self._assumptions: dict[tuple[str, str], list[dict[str, Any]]] = {}

    def _gap(self, reason: str) -> None:
        if reason not in self.limits:
            self.limits.add(reason)
            self.warn(f"cloud.aws: CloudTrail lineage {reason}; coverage incomplete")

    def _bound(self, observation: dict[str, Any]) -> None:
        """Stop retaining a principal's events; the invocation tally stays complete, the ancestry does not."""
        affected = {observation.get("principal") or ""}
        session = observation.get("assumedRoleArn")
        if observation.get("eventName") in ASSUME_OPERATIONS and _usable(session):
            # The session this hop created can no longer be traced through it.
            affected.add(session)
        if not self.partial:
            self.warn(
                f"cloud.aws: CloudTrail lineage retains at most {MAX_LINEAGE_EVENTS} events per principal; "
                "ancestry is partial beyond that, invocation counts are complete",
                incomplete=False,
            )
        self.partial.update(affected)

    def add(self, record: dict[str, Any]) -> bool:
        """Return false for exact duplicates; resource limits affect provenance, not detection."""
        observation = {}
        for name in _FIELDS:
            value = record.get(name)
            if value is not None:
                if not isinstance(value, str) or len(value) > 2048:
                    raise ValueError("invalid CloudTrail lineage field")
                observation[name] = text(value, 2048)
        for name in ("eventTime", "sessionCreatedAt", "sessionExpiresAt"):
            if observation.get(name):
                stamp = _parse_time(observation[name])
                if stamp is None:
                    self._gap("invalid-timestamp")
                    observation.pop(name)
                else:
                    observation[name] = to_iso(stamp)
        principal = observation.get("principal") or ""
        retained = self.retained.get(principal, 0)
        if all(_usable(observation.get(k)) for k in ("eventID", "recipientAccountId", "_region")):
            key = (
                str(observation["recipientAccountId"]),
                str(observation["_region"]),
                str(observation["eventID"]),
            )
            digest = hashlib.sha256(json.dumps(observation, sort_keys=True).encode()).hexdigest()
            previous = self.seen.get(key)
            if previous == digest:
                return False
            if previous is not None:
                self._gap("conflicting-event-id")
            elif retained < MAX_LINEAGE_EVENTS:
                self.seen[key] = digest
        if retained >= MAX_LINEAGE_EVENTS:
            self._bound(observation)
            return True
        self.retained[principal] = retained + 1
        self._events.setdefault(principal, []).append(observation)
        if observation.get("eventName") in ASSUME_OPERATIONS:
            created = (observation.get("assumedRoleArn") or "", observation.get("eventTime") or "")
            self._assumptions.setdefault(created, []).append(observation)
        return True

    @staticmethod
    def _matches(invocation: dict[str, Any], assumption: dict[str, Any]) -> bool:
        principal = invocation.get("principal")
        issuer = invocation.get("sessionIssuerArn")
        if not _usable(principal) or not _usable(issuer):
            return False
        if assumption.get("errorCode") or assumption.get("eventSource") != "sts.amazonaws.com":
            return False
        if assumption.get("assumedRoleArn") != principal or assumption.get("roleArn") != issuer:
            return False
        session_arn = _ARN.fullmatch(principal)
        role_arn = _ARN.fullmatch(issuer)
        if (
            not session_arn
            or not role_arn
            or session_arn[2] != "sts"
            or session_arn[4] != "assumed-role"
            or role_arn[2] != "iam"
            or role_arn[4] != "role"
            or session_arn[1] != role_arn[1]
            or session_arn[3] != role_arn[3]
            or assumption.get("recipientAccountId") != role_arn[3]
            or not _usable(invocation.get("recipientAccountId"))
            or not _usable(invocation.get("_region"))
        ):
            return False
        # IAM role ARNs retain their optional path; STS assumed-role ARNs use
        # only the role's final name followed by the session name. Two exports
        # repeating the same inconsistent strings cannot establish an edge.
        session_parts = session_arn[5].split("/")
        if (
            len(session_parts) != 2
            or not all(session_parts)
            or session_parts[0] != role_arn[5].rsplit("/", 1)[-1]
        ):
            return False
        when = parse_timestamp(invocation.get("eventTime"))
        created = parse_timestamp(assumption.get("eventTime"))
        expires = parse_timestamp(assumption.get("sessionExpiresAt"))
        session_created = parse_timestamp(invocation.get("sessionCreatedAt"))
        # An explicit lifetime and the session creation timestamp prevent a reused
        # role/session display name from silently becoming a persistent identity.
        if not when or not created or not expires or session_created != created:
            return False
        if not created <= when <= expires or expires - created > timedelta(hours=12):
            return False
        source = invocation.get("sourceIdentity")
        return not source or (_usable(source) and source == assumption.get("sourceIdentity"))

    def for_principal(self, principal: str) -> dict[str, Any]:
        observations: list[dict[str, Any]] = []
        bounded = principal in self.partial
        truncated = False
        for event in self._events.get(principal, []):
            if event.get("eventName") in ASSUME_OPERATIONS:
                continue
            if len(observations) >= MAX_CALLER_OBSERVATIONS:
                # The sample is bounded; the caller's invocation tally is not.
                truncated = True
                break
            trace = self._trace(event)
            bounded = bounded or any(
                (hop.get("principal") or "") in self.partial for hop in trace["assumption_chain"]
            )
            observations.append({**event, **trace})
        limitations = [
            "Exports may omit invocation events or STS hops; unlinked never means no role assumption.",
            "An API call or role session does not establish agent execution or effective access.",
            "STS region may differ from invocation region; recipient and region scopes are retained.",
            "No credential identifiers or values are retained; sourceIdentity is a provider assertion.",
        ]
        if bounded:
            limitations.append(
                f"The per-principal retention limit of {MAX_LINEAGE_EVENTS} lineage events was reached; "
                "ancestry beyond the retained events is unknown while invocation counts are complete."
            )
        if truncated:
            if not self.sampled:
                self.warn(
                    f"cloud.aws: CloudTrail lineage lists at most {MAX_CALLER_OBSERVATIONS} observations "
                    "per caller; later invocation events are counted, not listed",
                    incomplete=False,
                )
            self.sampled.add(principal)
            limitations.append(
                f"The observation sample is capped at {MAX_CALLER_OBSERVATIONS} per caller; later "
                "invocation events are counted in the finding, not listed here."
            )
        partial = bounded or truncated
        return {
            "observations": observations,
            "observations_truncated": truncated,
            "coverage": "incomplete" if self.limits else "partial" if partial else "export-observations-only",
            "limits": sorted(
                self.limits
                | ({"event-limit"} if bounded else set())
                | ({"caller-observation-limit"} if truncated else set())
            ),
            "identity_basis": "exact-session-arn-issuer-creation-time-and-lifetime",
            "limitations": limitations,
        }

    def _trace(self, event: dict[str, Any]) -> dict[str, Any]:
        """Walk observed STS ancestry without inferring missing hops or following cycles."""
        current = event
        chain: list[dict[str, Any]] = []
        seen = {id(event)}
        status = "partial"
        while True:
            # Both times are ISO-normalized by add(); equal strings are the equal
            # datetimes _matches compares, so no candidate outside this key can link.
            session = (current.get("principal") or "", current.get("sessionCreatedAt") or "")
            candidates = self._assumptions.get(session, [])
            matches = [e for e in candidates if self._matches(current, e)]
            if not matches:
                if current.get("identityType") in {"IAMUser", "Root", "AWSService"}:
                    status = "observed-origin"
                break
            if len(matches) != 1 or "conflicting-event-id" in self.limits:
                status = "ambiguous"
                break
            candidate = matches[0]
            if id(candidate) in seen:
                status = "cycle"
                self._gap("lineage-cycle")
                break
            if len(chain) >= MAX_ASSUMPTION_HOPS:
                status = "depth-limit"
                self._gap("chain-depth-limit")
                break
            chain.append(candidate)
            seen.add(id(candidate))
            current = candidate
        return {
            "assumption_status": "linked" if chain else "ambiguous" if status == "ambiguous" else "unlinked",
            "assumption": chain[0] if chain else None,
            "assumption_chain": chain,
            "chain_status": status,
            "chain_limit": MAX_ASSUMPTION_HOPS,
        }
