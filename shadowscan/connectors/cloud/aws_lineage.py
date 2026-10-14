"""Bounded, non-scoring CloudTrail provenance and exact assumed-session links.

Only allowlisted metadata is retained. Access keys, session tokens, request
bodies and response credentials are never part of a lineage observation.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from datetime import timedelta
from typing import Any, TypeGuard

from shadowscan.connectors.cloud.aws_registry import text
from shadowscan.utils.redaction import REDACTED
from shadowscan.utils.text import parse_timestamp, to_iso

MAX_LINEAGE_EVENTS = 2000
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


def _usable(value: Any) -> TypeGuard[str]:
    return isinstance(value, str) and bool(value) and REDACTED.lower() not in value.lower()


class CloudTrailLineage:
    """Retain event provenance and link only an unambiguous, unexpired exact session."""

    def __init__(self, warn: Callable[[str], None]) -> None:
        self.warn = warn
        self.events: list[dict[str, Any]] = []
        self.seen: dict[tuple[str, str, str], str] = {}
        self.limits: set[str] = set()

    def _gap(self, reason: str) -> None:
        if reason not in self.limits:
            self.limits.add(reason)
            self.warn(f"cloud.aws: CloudTrail lineage {reason}; coverage incomplete")

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
                stamp = parse_timestamp(observation[name])
                if stamp is None:
                    self._gap("invalid-timestamp")
                    observation.pop(name)
                else:
                    observation[name] = to_iso(stamp)
        if all(_usable(observation.get(k)) for k in ("eventID", "recipientAccountId", "_region")):
            key = (
                str(observation["recipientAccountId"]),
                str(observation["_region"]),
                str(observation["eventID"]),
            )
            encoded = json.dumps(observation, sort_keys=True)
            previous = self.seen.get(key)
            if previous == encoded:
                return False
            if previous is not None:
                self._gap("conflicting-event-id")
            elif len(self.seen) < MAX_LINEAGE_EVENTS:
                self.seen[key] = encoded
        if len(self.events) >= MAX_LINEAGE_EVENTS:
            self._gap("event-limit")
        else:
            self.events.append(observation)
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
        assumptions = [e for e in self.events if e.get("eventName") in ASSUME_OPERATIONS]
        observations: list[dict[str, Any]] = []
        for event in self.events:
            if event.get("principal") != principal or event.get("eventName") in ASSUME_OPERATIONS:
                continue
            if len(observations) >= MAX_CALLER_OBSERVATIONS:
                self._gap("caller-observation-limit")
                break
            observations.append({**event, **self._trace(event, assumptions)})
        return {
            "observations": observations,
            "coverage": "incomplete" if self.limits else "export-observations-only",
            "limits": sorted(self.limits),
            "identity_basis": "exact-session-arn-issuer-creation-time-and-lifetime",
            "limitations": [
                "Exports may omit invocation events or STS hops; unlinked never means no role assumption.",
                "An API call or role session does not establish agent execution or effective access.",
                "STS region may differ from invocation region; recipient and region scopes are retained.",
                "No credential identifiers or values are retained; sourceIdentity is a provider assertion.",
            ],
        }

    def _trace(self, event: dict[str, Any], assumptions: list[dict[str, Any]]) -> dict[str, Any]:
        """Walk observed STS ancestry without inferring missing hops or following cycles."""
        current = event
        chain: list[dict[str, Any]] = []
        seen = {id(event)}
        status = "partial"
        while True:
            matches = [e for e in assumptions if self._matches(current, e)]
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
