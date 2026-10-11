"""Shared contract between the nine-surface benchmark runner, corpus and tool adapters.

Everything an adapter needs is here: the surface and modality names, the
materialized case layout a tool is pointed at, the entity keys a tool's output
is mapped onto, and the declarative adapter protocol. Adapters never execute
the tool themselves; they return invocations, and the runner executes them in
the isolation the modality needs (no network; a fresh PID namespace unless the
case stages live processes or services the tool must see).

Surfaces and modalities
-----------------------

==========  ====================  ======================================================
surface     modality              what the tool is pointed at (under ``inputs/``)
==========  ====================  ======================================================
code        checkout              a repository working tree (``inputs/repo``)
identity    okta-export           ``okta/apps.json`` (``GET /api/v1/apps`` array),
                                  ``okta/grants/<appId>.json``, ``okta/tokens/<appId>.json``
identity    entra-export          Graph ``value`` arrays: ``entra/servicePrincipals.json``,
                                  ``entra/applications.json``, ``entra/oauth2PermissionGrants.json``,
                                  ``entra/appRoleAssignments.json``
gateway     litellm-export        ``litellm/spend_logs.jsonl`` (one ``/spend/logs`` row per line)
gateway     bedrock-export        ``bedrock/model_invocation_logs.jsonl`` (CloudWatch invocation log)
lowcode     powerplatform-export  ``power-platform/environments.json``, ``flows.json``, ``bots.json``,
                                  ``connections.json`` (admin API / Dataverse shapes)
lowcode     n8n-export            ``n8n/workflows.json`` (``GET /api/v1/workflows`` ``{"data": [...]}``)
saas        slack-export          ``slack/admin.apps.approved.list.json``,
                                  ``slack/admin.apps.requests.list.json``, ``slack/users.list.json``,
                                  ``slack/team.info.json``
saas        github-export         ``github/installations.json`` (``GET /orgs/{org}/installations``)
cloud       aws-export            ``aws/<service>/<operation>[.<id>].json`` AWS CLI JSON outputs
cloud       k8s-export            ``kubernetes/workloads.json`` (``kubectl get ... -A -o json`` List)
endpoint    home                  ``home/`` a user's home directory; tools get ``HOME=inputs/home``
network     passive               ``zeek/conn.log``, ``zeek/ssl.log``, ``zeek/dns.log`` and
                                  ``flows.json`` (one record per connection, all fields)
network     active                ``services.json``: the runner serves each listed service on
                                  127.0.0.1:<port> inside the tool's network namespace
runtime     snapshot              ``osquery_processes.json`` (``osqueryi --json`` rows) and
                                  ``osqueryd_results.jsonl`` (osqueryd result-log lines)
runtime     live                  ``processes.json``: the runner spawns each listed process (an
                                  inert binary with that name and command line) in the tool's
                                  PID namespace before the tool runs
==========  ====================  ======================================================

Entity keys
-----------

Ground truth and every adapter use the same keys so matching is exact:

* code: facts ``<category>:<value>`` from ``tools.discovery_benchmark.taxonomy``
* identity: ``app:<Okta app id | Entra appId>``
* gateway: ``caller:<api key alias | principal | user agent product>``
* lowcode: ``bot:<id>`` (Copilot Studio), ``flow:<id>`` (Power Automate), ``workflow:<id>`` (n8n)
* saas: ``app:<Slack app id | GitHub app slug>``
* cloud: ``resource:<ARN>`` or ``k8s:<namespace>/<Kind>/<name>``
* endpoint: ``artifact:<path relative to home>`` (POSIX, no leading ``./``)
* network passive: ``client:<source IP>``; network active: ``service:<ip>:<port>``
* runtime: ``process:<pid>`` (the pid the tool sees)

Labels are ``agent`` (an autonomous or tool-using AI agent, or an agent
integration such as a configured MCP server, Copilot Studio agent, Bedrock
agent, coding-agent CLI), ``llm`` (AI or LLM use without agent evidence: a
chat SaaS app, a model server, a single completion caller) or ``none`` (no AI;
decoys are labeled ``none``). A tool that cannot tell agents from plain AI use
reports ``ai``; it counts as a positive without agent tier.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol

SURFACES: tuple[str, ...] = (
    "code",
    "identity",
    "gateway",
    "lowcode",
    "saas",
    "cloud",
    "endpoint",
    "network",
    "runtime",
)

MODALITIES: Mapping[str, tuple[str, ...]] = {
    "code": ("checkout",),
    "identity": ("okta-export", "entra-export"),
    "gateway": ("litellm-export", "bedrock-export"),
    "lowcode": ("powerplatform-export", "n8n-export"),
    "saas": ("slack-export", "github-export"),
    "cloud": ("aws-export", "k8s-export"),
    "endpoint": ("home",),
    "network": ("passive", "active"),
    "runtime": ("snapshot", "live"),
}

LABELS: tuple[str, ...] = ("agent", "llm", "none")
Label = Literal["agent", "llm", "none"]
Reported = Literal["agent", "llm", "ai"]
Status = Literal["ok", "error", "unsupported"]


@dataclass(frozen=True)
class Entity:
    """One thing a tool reports (or the truth expects) on a surface."""

    kind: str
    key: str
    label: str
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"kind": self.kind, "key": self.key, "label": self.label}
        if self.attributes:
            out["attributes"] = self.attributes
        return out


@dataclass(frozen=True)
class TruthEntity(Entity):
    """An expected entity with the evidence that justifies its label."""

    evidence: str = ""

    def to_json(self) -> dict[str, Any]:
        out = super().to_json()
        out["evidence"] = self.evidence
        return out


@dataclass
class MaterializedCase:
    """A case written to disk for one tool run."""

    case_id: str
    surface: str
    modality: str
    family: str
    root: Path
    """Case directory; ``inputs`` lives under it."""
    inputs: Path
    """``root / "inputs"``; see the module docstring for the layout."""
    home: Path | None = None
    """For the ``home`` modality: the directory the tool gets as ``HOME``."""
    processes: list[dict[str, Any]] = field(default_factory=list)
    """For ``runtime/live``: the processes the runner spawned, with the pid each got."""
    services: list[dict[str, Any]] = field(default_factory=list)
    """For ``network/active``: the services the runner serves (``ip``, ``port``, ``product``)."""


@dataclass(frozen=True)
class Invocation:
    """One process the runner executes for an adapter."""

    argv: tuple[str, ...]
    cwd: Path
    env: dict[str, str] = field(default_factory=dict)
    timeout: int = 300
    ok_codes: frozenset[int] = frozenset({0})
    stdin: str | None = None


@dataclass
class RunResult:
    code: int
    stdout: str
    stderr: str
    seconds: float
    timed_out: bool = False


@dataclass
class AdapterResult:
    status: Status
    entities: list[Entity] = field(default_factory=list)
    note: str = ""
    raw: dict[str, Any] = field(default_factory=dict)
    """Verbatim tool output kept beside the normalized entities (never scored)."""

    def to_json(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "entities": [e.to_json() for e in self.entities],
            "note": self.note,
        }


@dataclass
class ToolEnv:
    """Where the installed tools live and what the runner was told about them."""

    tool_root: Path
    config: dict[str, Any] = field(default_factory=dict)

    def tool(self, name: str) -> dict[str, Any]:
        value = self.config.get("tools", {}).get(name)
        return value if isinstance(value, dict) else {}

    def binary(self, name: str) -> str | None:
        value = self.tool(name).get("bin")
        return value if isinstance(value, str) and value else None

    @classmethod
    def load(cls, path: Path) -> ToolEnv:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError(f"{path}: tool configuration must be an object")
        root = data.get("tool_root")
        return cls(tool_root=Path(root) if isinstance(root, str) else path.parent, config=data)


class Adapter(Protocol):
    """How to run one tool on one materialized case and read its output as entities.

    ``surfaces`` maps each supported surface to the modalities the tool handles.
    ``invocations`` returns the processes to run, in order; the runner executes
    them with the case's isolation and passes the results to ``normalize``.
    An adapter maps names, paths and identifiers onto entity keys and never
    interprets findings beyond the tool's own report.
    """

    name: str
    display: str
    surfaces: Mapping[str, frozenset[str]]

    def unavailable_reason(self, env: ToolEnv) -> str | None: ...

    def version(self, env: ToolEnv) -> str: ...

    def invocations(self, case: MaterializedCase, env: ToolEnv, work: Path) -> list[Invocation]: ...

    def normalize(self, case: MaterializedCase, work: Path, runs: list[RunResult]) -> AdapterResult: ...


def supports(adapter: Adapter, surface: str, modality: str) -> bool:
    return modality in adapter.surfaces.get(surface, frozenset())


def base_env(home: Path, work: Path) -> dict[str, str]:
    """A minimal environment: no inherited credentials, a case-local HOME."""
    return {
        "HOME": str(home),
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TMPDIR": str(work),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_DATA_HOME": str(home / ".local" / "share"),
        "XDG_CACHE_HOME": str(work / "cache"),
        "NO_COLOR": "1",
        "TERM": "dumb",
        "CI": "1",
        "DO_NOT_TRACK": "1",
    }


def tail(text: str, n: int = 300) -> str:
    return text[-n:].strip()


def relative_artifact(path: str, home: Path) -> str | None:
    """Map an absolute or ``~``-prefixed path a tool printed onto an ``artifact:`` key."""
    candidate = path.strip()
    if not candidate:
        return None
    if candidate.startswith("~/"):
        rel = candidate[2:]
    else:
        try:
            rel = Path(candidate).resolve().relative_to(home.resolve()).as_posix()
        except ValueError:
            try:
                rel = Path(candidate).relative_to(home).as_posix()
            except ValueError:
                return None
    rel = rel.strip("/")
    return f"artifact:{rel}" if rel else None
