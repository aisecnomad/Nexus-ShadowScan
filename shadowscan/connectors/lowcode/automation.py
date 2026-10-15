"""Automation platforms with native AI / agent steps: n8n, Make, Zapier, Workato.

Each connector lists workflows (and, where the platform has them, dedicated
agents), fingerprints AI steps with the platform signatures and emits one
``workflow`` / ``agent`` finding per AI-enabled definition.

Offline exports:

* n8n     – ``/api/v1/workflows`` JSON (or exported workflow JSON files)
* Make    – ``/api/v2/scenarios`` list with embedded ``blueprint`` (or blueprint JSON files)
  and ``/api/v2/ai-agents``
* Zapier  – Zapier for Companies / Enterprise CSV or JSON export of Zaps (title, status, apps/steps, owner)
* Workato – ``/api/recipes`` JSON (``items`` with ``code`` and ``config``)
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Collection, Iterable, Iterator
from typing import Any, ClassVar
from urllib.parse import quote, urlsplit

from requests import RequestException

from shadowscan.connectors.agent_behavior import is_generation
from shadowscan.connectors.base import BaseConnector, ConnectorError
from shadowscan.connectors.common import (
    apply_matches,
    blob_matches,
    failure_summary,
    finalize,
    max_pages_limit,
    model_matches,
    name_matches,
)
from shadowscan.connectors.lowcode.graph import GraphAnalysis, analyze_workflow_graph
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.signatures import Match
from shadowscan.signatures.matcher import MatchTimeoutError
from shadowscan.utils.http import HttpClient, HttpError
from shadowscan.utils.safe_json import strict_json_loads
from shadowscan.utils.text import get_path, truncate

# Autonomy: what starts a run, read from a definition's triggers. A schedule or an event is
# initiation evidence (the ``scheduled`` and ``event-triggered`` tags with the ``autonomous``
# capability), not approval-bypass evidence: the connector does not inspect approval steps in
# the flow. A trigger a person operates records neither: autonomy has no tag for a person-started
# run, and an unrecorded initiation never counts as low.
SCHEDULE = "schedule"
EVENT = "event"
HUMAN = "human"

# Trigger names of the platform's own clock, and of a webhook, a poller or an event.
_SCHEDULE_NAMES = re.compile(r"cron|schedule|interval|timer|recurr", re.I)
_EVENT_NAMES = re.compile(r"webhook|trigger|event|poll", re.I)
# n8n trigger nodes a person operates: the workflow's "Execute workflow" button, chat window, form
# and evaluation runner. Every other trigger node reacts to something outside the workflow: a
# webhook, a polled service, another workflow or an MCP client.
_N8N_HUMAN_TRIGGERS = re.compile(
    r"\.(manualTrigger|chatTrigger|manualChatTrigger|formTrigger|evaluationTrigger)$", re.I
)
_N8N_SCHEDULE_TRIGGERS = re.compile(r"\.(scheduleTrigger|cron|interval)$", re.I)
# Make ``scheduling.type``: an on-demand scenario waits for the Run once button or a call (the
# API, another scenario, an AI agent or an MCP client), so it records no initiation either way; an
# instant trigger runs immediately on its webhook, and every other type is a schedule.
_MAKE_SCHEDULE_TYPES = frozenset({"indefinitely", "interval", "once", "daily", "weekly", "monthly", "yearly"})
_MAKE_WEBHOOK_MODULES = re.compile(r"hook", re.I)
# Workato trigger providers: Scheduler by Workato (``clock``) and Workbot, whose commands, menus,
# buttons, modals and shortcuts a person operates in Slack or Teams. A Workbot event trigger
# reacts to the workspace's events, a bot's messages included, like every other trigger line,
# which reacts to its app, a webhook, an API call or another recipe.
_WORKATO_SCHEDULE_PROVIDERS = re.compile(r"^(?:clock|scheduler)\b|schedul", re.I)
_WORKATO_HUMAN_PROVIDERS = re.compile(r"workbot", re.I)
_WORKBOT_HUMAN_TRIGGERS = re.compile(r"command|menu|modal|button|action|shortcut", re.I)
# Zapier apps a person operates: the Chrome extension's push, an Interfaces form and a chatbot.
# n8n HTTP Request nodes that POST to a model API. A path alone is weak: SMS
# and messaging APIs also take POST /v1/messages or /messages. A node counts as
# a model step when it POSTs to a generation route (agent_behavior's
# is_generation) and either (a) the host is a known model host, or (b) the
# route is versioned or namespaced (/v1/chat/completions, /v1/completions,
# /openai/deployments/.../chat/completions, /api/generate) and the host is not
# a known messaging API. /v1/messages, /v1/responses and /api/chat are also
# WhatsApp Business, messaging and help-desk chat routes, and a bare
# /chat/completions is unversioned, so on an unknown host they count only with
# request corroboration: an anthropic-version header, or a JSON body with a
# model key and a messages, prompt or input key. A bare /messages, /responses
# or /completions on an unknown host never counts.
_N8N_AI_NODE = re.compile(
    r"n8n-nodes-langchain|openAi|anthropic|gemini|mistral|ollama|huggingFace|\.agent$", re.I
)
# ``mcp`` as its own token in a node type: mcpClient, MCPServer, mcp_bridge, and
# a camelCase word after another word (githubMcpClient, acmeMCPTool, zapierMcp),
# but not a word or part number that contains it (smcpDecoder, mcp9808Sensor).
# The token starts after a non-alphanumeric character, or as ``Mcp``/``MCP``
# after a lower-case letter, and ends at a capital letter, a separator or the
# end, never a lower-case letter or a digit.
_N8N_MCP_NODE = re.compile(r"(?:(?<![A-Za-z0-9])[Mm][Cc][Pp]|(?<=[a-z])(?:Mcp|MCP))(?![a-z0-9])")
_N8N_HTTP_NODE = "n8n-nodes-base.httpRequest"
_UNQUALIFIED_GENERATION_ROUTE = re.compile(r"/(?:messages|responses|completions)/?", re.I)
_CORROBORATED_GENERATION_ROUTE = re.compile(r"/v1/(?:messages|responses)|/api/chat|/chat/completions", re.I)
_MODEL_REQUEST_KEYS = frozenset({"messages", "prompt", "input"})
# A request key in a template that is not plain JSON: an n8n expression outside
# a string, or JSON.stringify of an object literal ({ model: ..., messages: ... }).
_TEMPLATE_KEY = re.compile(r"(?<![\w$\"'])[\"']?(model|messages|prompt|input)[\"']?\s*:")
_MAX_REQUEST_TEMPLATE = 65_536
_NON_AI_MESSAGE_APIS = (
    "nexmo.com",
    "vonage.com",
    "messagebird.com",
    "bird.com",
    "twilio.com",
    "sinch.com",
    "plivo.com",
    "telnyx.com",
)
# Domain signals weighted below this are hints, not model hosts (as in gateway.logs).
_MIN_MODEL_HOST_WEIGHT = 0.3
_ZAPIER_HUMAN_APPS = re.compile(r"zapier (?:chrome extension|interfaces|chatbots)|\bmanual\b", re.I)


def _named_parameters(value: Any, key: str) -> set[str]:
    """Lower-cased names of an n8n ``{key: [{"name": ..., "value": ...}]}`` collection."""
    items = value.get(key) if isinstance(value, dict) else None
    if not isinstance(items, list):
        return set()
    return {
        item["name"].strip().lower()
        for item in items
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }


def _json_template_keys(value: Any) -> set[str]:
    """Top-level keys of an n8n JSON template, or the model-request keys it names when it is an expression."""
    if not isinstance(value, str):
        return set()
    text = value[:_MAX_REQUEST_TEMPLATE].strip().removeprefix("=").strip()
    try:
        parsed = strict_json_loads(text)
    except (ValueError, RecursionError):
        return set(_TEMPLATE_KEY.findall(text))
    return {key.lower() for key in parsed} if isinstance(parsed, dict) else set()


def _model_request(params: dict[str, Any]) -> bool:
    """Whether an HTTP Request node's headers or body describe a model API call.

    An ``anthropic-version`` header, or a JSON or key-value body with a
    ``model`` key and a ``messages``, ``prompt`` or ``input`` key (v3-v4 and
    v1-v2 parameter layouts). Headers or a body the node does not send never
    count.
    """
    headers: set[str] = set()
    if params.get("sendHeaders") is not False:
        headers |= _named_parameters(params.get("headerParameters"), "parameters")
        headers |= _named_parameters(params.get("headerParametersUi"), "parameter")
        headers |= _json_template_keys(params.get("jsonHeaders"))
        headers |= _json_template_keys(params.get("headerParametersJson"))
    if "anthropic-version" in headers:
        return True
    body: set[str] = set()
    if params.get("sendBody") is not False:
        body |= _named_parameters(params.get("bodyParameters"), "parameters")
        body |= _named_parameters(params.get("bodyParametersUi"), "parameter")
        body |= _json_template_keys(params.get("jsonBody"))
        body |= _json_template_keys(params.get("bodyParametersJson"))
    return "model" in body and bool(_MODEL_REQUEST_KEYS & body)


class _AutomationBase(BaseConnector):
    surface: ClassVar[Surface] = Surface.LOWCODE
    platform_signature: ClassVar[str] = ""

    def _trigger_initiation(self, trigger: str) -> str | None:
        """``schedule``, ``event`` or ``human`` for one trigger, or None when it names no initiation."""
        if _SCHEDULE_NAMES.search(trigger):
            return SCHEDULE
        if _EVENT_NAMES.search(trigger):
            return EVENT
        return None

    def _guarded_finding(
        self,
        rec: dict[str, Any],
        build: Callable[[dict[str, Any]], Finding | None],
        what: str,
    ) -> Finding | None:
        """Isolate one malformed record so the rest of the export is still analysed."""
        try:
            return build(rec)
        except (AttributeError, TypeError, ValueError, KeyError, RecursionError, MatchTimeoutError) as exc:
            detail = f": {exc}" if isinstance(exc, MatchTimeoutError) else ""
            self.ctx.warn(f"{self.name}: skipped a malformed {what} record ({type(exc).__name__}){detail}")
            return None

    @staticmethod
    def _identified(rec: dict[str, Any], *keys: str) -> bool:
        return any(rec.get(key) not in (None, "") for key in keys)

    def _workflow_finding(
        self,
        *,
        wid: str,
        name: str,
        blob: str,
        owner: str | None,
        account: str | None,
        active: bool | None,
        created: str | None,
        updated: str | None,
        triggers: list[str],
        ai_steps: list[str],
        kind: Kind = Kind.WORKFLOW,
        resource_type: str = "workflow",
        extra: dict[str, Any] | None = None,
        url: str | None = None,
        hints: list[Match] | None = None,
        initiations: Collection[str] | None = None,
    ) -> Finding | None:
        """One finding per AI-enabled definition; ``hints`` (model or step names) count at half weight.

        ``initiations`` are what starts the definition (:data:`SCHEDULE`, :data:`EVENT`,
        :data:`HUMAN`); by default each trigger is classified by :meth:`_trigger_initiation`.
        """
        matches = blob_matches(self.index, blob)
        if not matches and not ai_steps:
            return None
        platform = self.index.get(self.platform_signature)
        label = platform.name if platform else self.provider
        noun = "agent" if kind == Kind.AGENT else "workflow"
        f = Finding(
            surface=Surface.LOWCODE,
            connector=self.name,
            kind=kind,
            title=f"{label} {noun} with AI steps: {name}",
            resource=f"{self.provider}:{resource_type}:{wid}",
            resource_type=resource_type,
            provider=self.provider,
            account=account,
            owner=owner,
            first_seen=created,
            last_seen=updated,
        )
        f.add_framework(self.platform_signature)
        apply_matches(f, matches, location=url)
        if ai_steps:
            f.add_evidence(
                Evidence(
                    signal=f"{self.provider}:ai-steps",
                    description=f"AI steps: {', '.join(ai_steps[:10])}",
                    location=url,
                    weight=0.8,
                    signature=self.platform_signature,
                )
            )
            f.add_capability("tool-use")
        # Autonomy: a schedule or an event is initiation evidence (the scheduled and event-triggered
        # tags), not approval-bypass evidence; a trigger a person operates records neither.
        if initiations is None:
            found = {self._trigger_initiation(t) for t in triggers}
            initiations = {initiation for initiation in found if initiation is not None}
        if SCHEDULE in initiations:
            f.add_capability("autonomous")
            f.add_tag("scheduled")
        if EVENT in initiations:
            f.add_capability("autonomous")
            f.add_tag("event-triggered")
        if active is False:
            f.add_tag("inactive")
        f.metadata.update(
            {
                "active": active,
                "triggers": triggers[:10],
                "ai_steps": ai_steps[:20],
                "url": url,
                **(extra or {}),
            }
        )
        # Attach every observation before finalizing: confidence, likelihood and
        # --min-confidence filtering must reflect the hints too.
        apply_matches(f, hints or [], weight_scale=0.5)
        finalize(f, self.index)
        f.kind = kind
        return f


# ------------------------------------------------------------------ n8n
class N8nConnector(_AutomationBase):
    name: ClassVar[str] = "lowcode.n8n"
    provider: ClassVar[str | None] = "n8n"
    platform_signature: ClassVar[str] = "platform.n8n"
    description: ClassVar[str] = "n8n workflows using AI Agent / LLM / MCP nodes."
    config_keys: ClassVar[dict[str, str]] = {
        "api_url": "https://n8n.example.com/api/v1 (env N8N_API_URL)",
        "api_key": "X-N8N-API-KEY (env N8N_API_KEY)",
        "max_pages": "maximum 250-workflow pages, capped at 1000 (default 1000)",
        "input": "offline: workflow list JSON or directory of exported workflows",
    }

    def _http_model_node(self, node: dict[str, Any]) -> bool:
        """An HTTP Request node that POSTs to a model-generation route (see _N8N_HTTP_NODE)."""
        params = node.get("parameters")
        if node.get("type") != _N8N_HTTP_NODE or not isinstance(params, dict):
            return False
        # HTTP Request v1-v2 name the method ``requestMethod``; v3 and later ``method``.
        method = params.get("method")
        if method is None:
            method = params.get("requestMethod")
        url = params.get("url")
        if not isinstance(method, str) or method.upper() != "POST" or not isinstance(url, str):
            return False
        try:
            # An expression-mode URL starts with "="; its {{ }} parts are not resolved.
            parsed = urlsplit(url.strip().removeprefix("=").strip())
            host = parsed.hostname
        except ValueError:
            return False
        if parsed.scheme not in {"http", "https"} or not host:
            return False
        if "{{" in host or "}}" in host:
            return False  # a host chosen at run time cannot be classified
        path = parsed.path.rstrip("/") or "/"
        if not is_generation(path, method="POST"):
            return False
        if any(m.weight >= _MIN_MODEL_HOST_WEIGHT for m in self.index.match_domain(host)):
            return True
        if any(host == api or host.endswith(f".{api}") for api in _NON_AI_MESSAGE_APIS):
            return False
        if _UNQUALIFIED_GENERATION_ROUTE.fullmatch(path):
            return False
        if _CORROBORATED_GENERATION_ROUTE.fullmatch(path):
            return _model_request(params)
        return True

    def collect(self) -> Iterable[dict[str, Any]]:
        base = str(self.ctx.get("api_url", env="N8N_API_URL") or "").rstrip("/")
        key = self.ctx.get("api_key", env="N8N_API_KEY")
        if not (base and key):
            raise ConnectorError("lowcode.n8n: api_url and api_key required")
        http = HttpClient(base, headers={"X-N8N-API-KEY": key})
        yield from http.paginate_token(
            "/workflows",
            params={"limit": 250},
            items_key="data",
            token_key="nextCursor",
            token_param="cursor",
            max_pages=max_pages_limit(self.ctx.get("max_pages", 1000)),
        )

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        for w in records:
            self.ctx.examined()
            if not self._valid_workflow(w):
                self.ctx.warn("lowcode.n8n: missing or invalid workflow graph; definition coverage unknown")
                continue
            f = self._guarded_finding(w, self._n8n_finding, "workflow")
            if f:
                yield f

    def _valid_workflow(self, w: Any) -> bool:
        return self._record_fields_valid(
            w,
            strings=("name", "createdAt", "updatedAt"),
            mappings=("homeProject",),
            arrays=("nodes", "tags"),
        ) and isinstance(w.get("nodes"), list)

    @staticmethod
    def _workflow_graph(workflow: dict[str, Any]) -> GraphAnalysis:
        """The workflow's graph metadata; a graph that cannot be analysed is reported, never fatal.

        The graph is non-scoring, so a failure is contained to this workflow's
        ``workflow_graph`` (status ``incomplete``) and never drops its finding
        or another workflow's.
        """
        try:
            graph = analyze_workflow_graph(workflow, provider="n8n")
        except Exception as exc:  # noqa: BLE001 - one hostile workflow must not end the export
            graph = None
            reason = f"workflow graph analysis failed ({type(exc).__name__})"
        else:
            reason = "workflow graph shape not recognised"
        if graph is None:
            graph = GraphAnalysis(
                {
                    "provider": "n8n",
                    "status": "incomplete",
                    "scoring": False,
                    "potential_input_ai_egress_path": None,
                    "limitations": ["The workflow graph could not be analysed."],
                },
                [reason],
            )
        return graph

    def _trigger_initiation(self, trigger: str) -> str | None:
        if _N8N_HUMAN_TRIGGERS.search(trigger):
            return HUMAN
        if _N8N_SCHEDULE_TRIGGERS.search(trigger):
            return SCHEDULE
        return EVENT

    def _n8n_finding(self, w: dict[str, Any]) -> Finding | None:
        # Exported blueprints can contain useful AI evidence without a provider
        # object ID. A display name (or the string "None") is not that identity.
        workflow_id = w.get("id")
        identified = (isinstance(workflow_id, str) and bool(workflow_id.strip())) or (
            isinstance(workflow_id, int) and not isinstance(workflow_id, bool) and workflow_id > 0
        )
        if not identified:
            self.ctx.warn("lowcode.n8n: workflow has no valid provider id; identity coverage incomplete")
            workflow_id = hashlib.sha256(json.dumps(w, sort_keys=True, default=str).encode()).hexdigest()
        nodes = [
            node
            for node in w["nodes"]
            if self._record_fields_valid(
                node,
                required=("type",),
                strings=("name", "type"),
                mappings=("parameters",),
            )
        ]
        if len(nodes) != len(w["nodes"]):
            self.ctx.warn("lowcode.n8n: invalid workflow node; definition coverage unknown")
        # The graph covers the same nodes as the inventory, so its counts and
        # path ordinals (positions in this list, in export order) agree with
        # node_count. It is non-scoring metadata: a malformed or over-budget
        # graph is reported (status "incomplete"), but the AI inventory below
        # does not depend on it and is kept.
        graph = self._workflow_graph({**w, "nodes": nodes})
        for issue in graph.issues:
            self.ctx.warn(f"lowcode.n8n: {issue}; graph coverage incomplete")
        types = [str(n.get("type", "")) for n in nodes]
        ai_steps = [
            f"{n.get('name')} ({n.get('type')})"
            for n in nodes
            if _N8N_AI_NODE.search(str(n.get("type", ""))) or _N8N_MCP_NODE.search(str(n.get("type", "")))
        ]
        ai_steps.extend(
            f"{n.get('name')} ({n.get('type')}, model API)" for n in nodes if self._http_model_node(n)
        )
        # 'Respond to Webhook' is the reply step of a chat or form workflow, not a
        # trigger: counting it would read a person-operated workflow as event-run.
        triggers = [
            t
            for t in types
            if re.search(r"trigger|cron|schedule|interval|webhook", t, re.I)
            and not re.search(r"\.respondToWebhook$", t, re.I)
        ]
        models = [
            str(
                get_path(
                    n,
                    "parameters.model.value",
                    "parameters.model",
                    "parameters.modelId.value",
                    "parameters.options.model",
                )
            )
            for n in nodes
            if get_path(n, "parameters.model", "parameters.modelId")
        ]
        f = self._workflow_finding(
            wid=str(workflow_id),
            name=w.get("name") or "Unnamed workflow",
            blob=json.dumps(
                {"nodes": [{"type": n.get("type"), "parameters": n.get("parameters")} for n in nodes]},
                default=str,
            )[:300_000],
            owner=get_path(w, "homeProject.name", "shared.0.project.name", "owner", "createdBy"),
            account=self.ctx.get("api_url", env="N8N_API_URL"),
            active=w.get("active"),
            created=w.get("createdAt"),
            updated=w.get("updatedAt"),
            triggers=triggers,
            ai_steps=ai_steps,
            kind=(
                Kind.AGENT
                # openAiAssistant is n8n's registered OpenAI Assistant agent node.
                if any(t.endswith((".agent", "agentTool", ".openAiAssistant")) for t in types)
                else Kind.WORKFLOW
            ),
            resource_type="workflow" if identified else "unresolved-workflow",
            extra={
                "workflow_graph": graph.metadata,
                "node_count": len(nodes),
                "node_types": sorted(set(types))[:40],
                "tags": [t.get("name") for t in w.get("tags") or [] if isinstance(t, dict)],
            },
            hints=model_matches(self.index, *models),
        )
        if f:
            if not identified:
                f.metadata["identity_unresolved"] = True
                f.add_tag("unresolved-identity")
            f.models = sorted({m for m in models if m and m != "None"})
            if any(
                "toolCode" in t or "executeCommand" in t or "n8n-nodes-base.code" in t or "ssh" in t.lower()
                for t in types
            ):
                f.add_capability("code-exec")
        return f


# ------------------------------------------------------------------ Make
class MakeConnector(_AutomationBase):
    name: ClassVar[str] = "lowcode.make"
    provider: ClassVar[str | None] = "make"
    platform_signature: ClassVar[str] = "platform.make"
    description: ClassVar[str] = "Make (Integromat) scenarios with AI modules and Make AI Agents."
    config_keys: ClassVar[dict[str, str]] = {
        "api_url": "zone API base, e.g. https://eu1.make.com/api/v2 (env MAKE_API_URL)",
        "token": "API token (env MAKE_API_TOKEN)",
        "team_id": "team id to scan; or `organization_id`",
        "organization_id": "organization id whose teams are all scanned when `team_id` is unset",
        "max_pages": "maximum 100-item pages per list call, capped at 1000 (default 1000)",
        "input": "offline: scenarios JSON (with blueprint) / ai-agents JSON / blueprint files",
    }

    def _offset_pages(
        self,
        http: HttpClient,
        path: str,
        items_key: str,
        **params: Any,
    ) -> Iterator[dict[str, Any]]:
        seen: set[str] = set()
        for page in range(max_pages_limit(self.ctx.get("max_pages", 1000))):
            try:
                data = http.get_json(path, params={**params, "pg[limit]": 100, "pg[offset]": page * 100})
            except (HttpError, RequestException, RuntimeError, ValueError) as exc:
                status = failure_summary(exc)
                self.ctx.warn(f"lowcode.make: collection incomplete for {path} ({status})")
                return
            items = data.get(items_key) if isinstance(data, dict) else None
            if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
                self.ctx.warn(f"lowcode.make: invalid {items_key} page")
                return
            fingerprint = hashlib.sha256(json.dumps(items, sort_keys=True, default=str).encode()).hexdigest()
            if fingerprint in seen:
                self.ctx.warn(f"lowcode.make: repeated pagination page for {path}")
                return
            seen.add(fingerprint)
            yield from items
            if len(items) < 100:
                return
        self.ctx.warn(f"lowcode.make: pagination limit reached for {path}")

    def collect(self) -> Iterable[dict[str, Any]]:
        base = str(self.ctx.get("api_url", env="MAKE_API_URL") or "").rstrip("/")
        token = self.ctx.get("token", env="MAKE_API_TOKEN")
        if not (base and token):
            raise ConnectorError("lowcode.make: api_url and token required")
        http = HttpClient(base, headers={"Authorization": f"Token {token}"})
        teams: list[str] = []
        if self.ctx.get("team_id"):
            teams = [str(self.ctx.get("team_id"))]
        elif self.ctx.get("organization_id"):
            organization = self.ctx.get("organization_id")
            pages = self._offset_pages(http, "/teams", "teams", organizationId=organization)
            teams = [str(t["id"]) for t in pages]
        else:
            raise ConnectorError("lowcode.make: team_id or organization_id required")
        for team in teams:
            blueprint_errors: dict[str, int] = {}
            for s in self._offset_pages(http, "/scenarios", "scenarios", teamId=team):
                try:
                    bp = http.get_json(f"/scenarios/{quote(str(s['id']), safe='')}/blueprint")
                    response = bp.get("response") if isinstance(bp, dict) else None
                    blueprint = (response.get("blueprint") if isinstance(response, dict) else None) or bp
                    if not isinstance(blueprint, dict):
                        self.ctx.warn(f"lowcode.make: invalid blueprint for scenario {s['id']}")
                    else:
                        s["blueprint"] = blueprint
                except (HttpError, RequestException, RuntimeError, ValueError) as exc:
                    status = failure_summary(exc)
                    blueprint_errors[status] = blueprint_errors.get(status, 0) + 1
                yield {**s, "_kind": "scenario", "_team": team}
            if blueprint_errors:
                details = ", ".join(
                    f"{status}: {total}" for status, total in sorted(blueprint_errors.items())
                )
                self.ctx.warn(
                    f"lowcode.make: blueprints unreadable for {sum(blueprint_errors.values())} scenario(s) "
                    f"in team {team} ({details}); workflow inventory incomplete"
                )
            try:
                data = http.get_json("/ai-agents/v1/agents", params={"teamId": team})
            except (HttpError, RequestException, RuntimeError, ValueError) as exc:
                status = failure_summary(exc)
                self.ctx.warn(
                    f"lowcode.make: AI agents unreadable for team {team} ({status}); "
                    "agent inventory incomplete"
                )
                continue
            agents = data
            if isinstance(data, dict):
                agents = (
                    [data]
                    if data.get("id") and data.get("name")
                    else data.get("aiAgents", data.get("agents"))
                )
            if not isinstance(agents, list):
                self.ctx.warn(f"lowcode.make: invalid AI agents response for team {team}")
                continue
            for agent in agents:
                if not isinstance(agent, dict):
                    self.ctx.warn(f"lowcode.make: invalid AI agent record for team {team}")
                    continue
                yield {**agent, "_kind": "ai-agent", "_team": team}

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        for rec in records:
            kind = self._record_kind(rec)
            if kind is None:
                # Error bodies ({"message": ..., "code": ...}) must not pass as an empty inventory.
                self.ctx.warn("lowcode.make: unsupported or malformed provider record; coverage incomplete")
                continue
            self.ctx.examined()
            build = self._agent_finding if kind == "ai-agent" else self._scenario_finding
            f = self._guarded_finding(rec, build, kind)
            if f:
                yield f

    def _record_kind(self, rec: Any) -> str | None:
        if not self._record_fields_valid(
            rec,
            strings=("_kind", "name", "_team"),
            mappings=("blueprint", "createdByUser", "scheduling"),
            arrays=("tools",),
        ):
            return None
        kind = rec.get("_kind") or (
            "ai-agent" if "agentId" in rec or ("model" in rec and "systemPrompt" in rec) else "scenario"
        )
        if kind == "ai-agent":
            return kind if self._identified(rec, "id", "agentId", "name") else None
        if kind != "scenario":
            return None
        blueprint = rec.get("blueprint")
        identified = self._identified(rec, "id", "name") or (
            isinstance(blueprint, dict) and ("flow" in blueprint or bool(blueprint.get("name")))
        )
        return kind if identified else None

    def _agent_finding(self, rec: dict[str, Any]) -> Finding | None:
        model = rec.get("model") or rec.get("llmModel") or rec.get("defaultModel")
        return self._workflow_finding(
            wid=str(rec.get("id") or rec.get("agentId") or rec.get("name")),
            name=str(rec.get("name")),
            blob=json.dumps(rec, default=str)[:100_000],
            owner=str(rec.get("createdBy") or rec.get("ownerId") or "") or None,
            account=str(rec.get("_team") or rec.get("teamId") or "") or None,
            active=rec.get("active", True),
            created=rec.get("createdAt"),
            updated=rec.get("updatedAt"),
            triggers=[],
            ai_steps=[f"Make AI Agent (model {model or '?'})"],
            kind=Kind.AGENT,
            resource_type="ai-agent",
            extra={
                "model": model,
                "tools": [t.get("name") for t in rec.get("tools") or [] if isinstance(t, dict)][:20],
                "system_prompt": truncate(str(rec.get("systemPrompt") or ""), 200),
            },
            hints=model_matches(self.index, model),
        )

    @staticmethod
    def _scenario_initiations(scheduling: Any, triggers: list[str]) -> set[str]:
        """What starts a scenario: its ``scheduling.type`` when the export has it, and its webhooks.

        A module name alone says little: the first module of an on-demand scenario runs only when
        the scenario is run (a person's Run once, or a call from the API, another scenario, an AI
        agent or an MCP client, so no initiation is recorded either way; a webhook's queue waits
        for that run too), and a polling (``watch``) module runs on the scenario's schedule.
        """
        kind = scheduling.get("type") if isinstance(scheduling, dict) else None
        kind = kind.strip().lower() if isinstance(kind, str) else ""
        if kind == "on-demand":
            return set()
        found: set[str] = set()
        if kind == "immediately":
            found.add(EVENT)
        elif kind in _MAKE_SCHEDULE_TYPES:
            found.add(SCHEDULE)
        if any(_MAKE_WEBHOOK_MODULES.search(t) for t in triggers):
            found.add(EVENT)
        return found

    def _scenario_finding(self, rec: dict[str, Any]) -> Finding | None:
        bp = rec.get("blueprint") or rec
        flow = bp.get("flow") if isinstance(bp, dict) else None
        modules = [str(m.get("module", "")) for m in (flow or []) if isinstance(m, dict)]
        ai_steps = [
            m
            for m in modules
            if re.search(
                r"openai|anthropic|claude|gemini|mistral|ai-agents|perplexity|hugging|eden-ai"
                r"|cohere|groq|deepseek|assistants",
                m,
                re.I,
            )
        ]
        triggers = modules[:1] + [m for m in modules if re.search(r"webhook|watch|schedule|trigger", m, re.I)]
        return self._workflow_finding(
            initiations=self._scenario_initiations(rec.get("scheduling"), triggers),
            wid=str(rec.get("id") or rec.get("name")),
            name=str(rec.get("name") or bp.get("name") if isinstance(bp, dict) else rec.get("name")),
            blob=json.dumps(bp, default=str)[:300_000],
            owner=str(
                rec.get("createdByUser", {}).get("name")
                if isinstance(rec.get("createdByUser"), dict)
                else rec.get("createdBy") or ""
            )
            or None,
            account=str(rec.get("_team") or rec.get("teamId") or "") or None,
            active=rec.get("isActive", rec.get("active")),
            created=rec.get("createdAt") or rec.get("created"),
            updated=rec.get("lastEdit") or rec.get("updatedAt"),
            triggers=triggers,
            ai_steps=ai_steps,
            kind=Kind.AGENT if any("ai-agents" in m for m in modules) else Kind.WORKFLOW,
            resource_type="scenario",
            extra={
                "module_count": len(modules),
                "modules": sorted(set(modules))[:40],
                "scheduling": rec.get("scheduling"),
            },
        )


# ---------------------------------------------------------------- Zapier
# Fields that name or identify a zap in API records and account exports.
_ZAP_IDENTITY_FIELDS = ("title", "name", "Title", "Zap", "id", "Id")


class ZapierConnector(_AutomationBase):
    name: ClassVar[str] = "lowcode.zapier"
    provider: ClassVar[str | None] = "zapier"
    platform_signature: ClassVar[str] = "platform.zapier"
    description: ClassVar[str] = (
        "Zaps with AI steps (ChatGPT, Claude, Gemini, AI by Zapier) and Zapier Agents from account exports."
    )
    config_keys: ClassVar[dict[str, str]] = {
        "token": "OAuth bearer with `zap` scope for https://api.zapier.com/v2/zaps (env ZAPIER_TOKEN)",
        "max_pages": "maximum 100-zap pages, capped at 1000 (default 1000)",
        "input": "offline: Zapier for Companies CSV/JSON export of Zaps or Agents",
    }
    offline_formats: ClassVar[str] = "CSV / JSON export"

    def collect(self) -> Iterable[dict[str, Any]]:
        token = self.ctx.get("token", env="ZAPIER_TOKEN")
        if not token:
            raise ConnectorError("lowcode.zapier: token required (or use an offline export)")
        http = HttpClient("https://api.zapier.com", headers={"Authorization": f"Bearer {token}"})
        url: str | None = "/v2/zaps"
        seen: set[str] = set()
        for _ in range(max_pages_limit(self.ctx.get("max_pages", 1000))):
            if not url:
                return
            if not isinstance(url, str) or url in seen:
                self.ctx.warn("lowcode.zapier: invalid or repeated pagination link")
                return
            seen.add(url)
            data = http.get_json(url, params={"limit": 100})
            if not isinstance(data, dict) or not isinstance(data.get("data"), list):
                raise ConnectorError("lowcode.zapier: invalid collection response")
            yield from data["data"]
            url = get_path(data, "links.next")
        if url:
            self.ctx.warn("lowcode.zapier: pagination limit reached")

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        total = unnamed = 0
        for rec in records:
            self.ctx.examined()
            if self._blank_row(rec):
                # Spreadsheet exports often end with comma-only rows. They carry
                # no Zap and need no diagnostic, as in saas.generic.
                continue
            total += 1
            if isinstance(rec, dict) and not self._identified(rec, *_ZAP_IDENTITY_FIELDS):
                unnamed += 1
                continue
            f = self._guarded_finding(rec, self._zap_finding, "zap")
            if f:
                yield f
        # Renamed export columns must not look like an account without AI zaps.
        if unnamed and unnamed == total:
            self.ctx.warn(
                "lowcode.zapier: no record has a zap name or id; expected a column named one of "
                f"{', '.join(_ZAP_IDENTITY_FIELDS)}"
            )
        elif unnamed:
            self.ctx.warn(f"lowcode.zapier: skipped {unnamed} of {total} records without a zap name or id")

    @staticmethod
    def _blank_row(rec: dict[str, Any]) -> bool:
        """A padding row with a recognized Zapier identity column and blank text cells.

        Unknown columns cannot establish an empty Zapier export. Objects with
        null or non-text values also go to the record check and its diagnostics.
        """
        return (
            isinstance(rec, dict)
            and any(field in rec for field in _ZAP_IDENTITY_FIELDS)
            and all(isinstance(value, str) and not value.strip() for value in rec.values())
        )

    def _trigger_initiation(self, trigger: str) -> str | None:
        if _ZAPIER_HUMAN_APPS.search(trigger):
            return HUMAN
        return super()._trigger_initiation(trigger)

    def _zap_finding(self, rec: dict[str, Any]) -> Finding | None:
        # JSON exports may carry numeric titles; CSV columns are always text.
        title = str(
            rec.get("title") or rec.get("name") or rec.get("Title") or rec.get("Zap") or rec.get("id")
        )
        steps = rec.get("steps") or rec.get("Steps") or rec.get("apps") or rec.get("Apps") or []
        if isinstance(steps, str):
            steps_list = [s.strip() for s in re.split(r"[,;|>→]", steps) if s.strip()]
        else:
            steps_list = (
                [str(get_path(s, "app.title", "app", "title", "action") or s) for s in steps]
                if isinstance(steps, list)
                else []
            )
        blob = json.dumps(rec, default=str)[:100_000]
        ai_steps = [
            s
            for s in steps_list
            if re.search(
                r"(?i)chatgpt|openai|claude|anthropic|gemini|ai by zapier|zapier ai|agent"
                r"|copilot|gpt|perplexity|mistral|hugging",
                s,
            )
        ]
        owner = rec.get("owner") or rec.get("Owner") or get_path(rec, "owner.email", "user.email", "creator")
        agent = re.search(r"(?i)\bagent\b", title) or rec.get("type") == "agent" or "instructions" in rec
        kind = Kind.AGENT if agent else Kind.WORKFLOW
        return self._workflow_finding(
            wid=str(rec.get("id") or rec.get("Id") or title),
            name=title,
            blob=blob,
            owner=str(owner) if owner else None,
            account=str(rec.get("account") or rec.get("Account") or rec.get("team") or "") or None,
            active=_truthy(rec.get("is_enabled", rec.get("status", rec.get("Status")))),
            created=rec.get("created_at") or rec.get("Created"),
            updated=rec.get("updated_at") or rec.get("Modified") or rec.get("last_run"),
            triggers=steps_list[:1],
            ai_steps=ai_steps,
            kind=kind,
            # Title-based agent classification can change without changing
            # the source entity. Only structural source type selects its
            # namespace; a zap named "AI agent" remains the same zap.
            resource_type="agent" if rec.get("type") == "agent" or "instructions" in rec else "zap",
            extra={"steps": steps_list[:20], "status": rec.get("status") or rec.get("Status")},
            url=rec.get("url") or rec.get("editor_url"),
            hints=name_matches(self.index, " ".join(ai_steps)),
        )


# --------------------------------------------------------------- Workato
class WorkatoConnector(_AutomationBase):
    name: ClassVar[str] = "lowcode.workato"
    provider: ClassVar[str | None] = "workato"
    platform_signature: ClassVar[str] = "platform.workato"
    description: ClassVar[str] = "Workato recipes using GenAI / LLM connectors and agentic recipes."
    config_keys: ClassVar[dict[str, str]] = {
        "api_url": (
            "default https://www.workato.com/api (EU: https://app.eu.workato.com/api; env WORKATO_API_URL)"
        ),
        "token": "API client token (env WORKATO_API_TOKEN)",
        "max_pages": "maximum 100-recipe pages, capped at 1000 (default 1000)",
        "input": "offline: /api/recipes JSON",
    }

    def collect(self) -> Iterable[dict[str, Any]]:
        base = str(self.ctx.get("api_url", "https://www.workato.com/api", env="WORKATO_API_URL")).rstrip("/")
        token = self.ctx.get("token", env="WORKATO_API_TOKEN")
        if not token:
            raise ConnectorError("lowcode.workato: token required")
        http = HttpClient(base, headers={"Authorization": f"Bearer {token}"})
        seen: set[str] = set()
        for page in range(1, max_pages_limit(self.ctx.get("max_pages", 1000)) + 1):
            data = http.get_json("/recipes", params={"per_page": 100, "page": page})
            items = data.get("items") if isinstance(data, dict) else data
            if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
                raise ConnectorError("lowcode.workato: invalid recipe page")
            fingerprint = hashlib.sha256(json.dumps(items, sort_keys=True, default=str).encode()).hexdigest()
            if fingerprint in seen:
                self.ctx.warn("lowcode.workato: repeated pagination page")
                return
            seen.add(fingerprint)
            yield from items
            if len(items) < 100:
                return
        self.ctx.warn("lowcode.workato: pagination limit reached")

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        for r in records:
            if not self._valid_recipe(r):
                # Error bodies ({"message": ...}) must not pass as an empty inventory.
                self.ctx.warn("lowcode.workato: unsupported or malformed recipe record; coverage incomplete")
                continue
            self.ctx.examined()
            f = self._guarded_finding(r, self._recipe_finding, "recipe")
            if f:
                yield f

    def _valid_recipe(self, r: Any) -> bool:
        return (
            self._record_fields_valid(
                r,
                strings=("name", "author_name", "created_at", "updated_at", "last_run_at"),
                arrays=("config",),
            )
            and self._identified(r, "id", "name")
            and (r.get("code") is None or isinstance(r["code"], (str, dict, list)))
        )

    def _trigger_initiation(self, trigger: str) -> str | None:
        if not trigger:
            return None
        if _WORKATO_SCHEDULE_PROVIDERS.search(trigger):
            return SCHEDULE
        provider, _, name = trigger.partition(":")
        if _WORKATO_HUMAN_PROVIDERS.search(provider):
            if not name:
                # The export omitted the trigger name: a Workbot trigger may be a
                # command or an event, so record no initiation rather than guess.
                return None
            if _WORKBOT_HUMAN_TRIGGERS.search(name):
                return HUMAN
        return EVENT

    def _recipe_finding(self, r: dict[str, Any]) -> Finding | None:
        code = r.get("code") or ""
        config = r.get("config") or []
        providers = sorted(
            {str(c.get("provider") or c.get("keyword") or "") for c in config if isinstance(c, dict)}
        )
        ai_steps = [
            p
            for p in providers
            if re.search(
                r"(?i)openai|genai|anthropic|claude|gemini|vertex|bedrock|cohere|mistral"
                r"|azure_openai|workato_agent|agentic|copilot|llm",
                p,
            )
        ]
        blob = (code if isinstance(code, str) else json.dumps(code)) + " " + json.dumps(config, default=str)
        parsed: Any = code if isinstance(code, dict) else {}
        if isinstance(code, str) and code.startswith("{"):
            try:
                parsed = strict_json_loads(code)
            except (ValueError, RecursionError):
                # A corrupt recipe body loses only its trigger attribution.
                self.ctx.warn("lowcode.workato: recipe code is not valid JSON; trigger coverage incomplete")
        # The root line of a recipe is its trigger (keyword "trigger" on every recipe); the provider
        # and trigger name say what starts it, the keyword alone does not.
        triggers: list[str] = []
        if isinstance(parsed, dict) and str(parsed.get("keyword") or "").lower() == "trigger":
            parts = (parsed.get("provider"), parsed.get("name"))
            triggers.append(":".join(str(part) for part in parts if isinstance(part, str) and part))
        return self._workflow_finding(
            wid=str(r.get("id") or r.get("name")),
            name=str(r.get("name")),
            blob=blob[:300_000],
            owner=str(r.get("author_name") or r.get("user_id") or "") or None,
            account=str(r.get("folder_id") or "") or None,
            active=r.get("running"),
            created=r.get("created_at"),
            updated=r.get("updated_at") or r.get("last_run_at"),
            # The blob heuristic backs up a recipe whose trigger line classified
            # nothing; it must not override a classified line ('scheduler' in an
            # action step would turn a Workbot command into schedule evidence).
            triggers=triggers or (["schedule"] if "scheduler" in blob.lower() else []),
            ai_steps=ai_steps,
            kind=Kind.AGENT if any("agent" in p.lower() for p in providers) else Kind.WORKFLOW,
            resource_type="recipe",
            extra={
                "providers": providers[:30],
                "job_succeeded_count": r.get("job_succeeded_count"),
                "folder": r.get("folder_id"),
            },
        )


def _truthy(v: Any) -> bool | None:
    if v is None:
        return None
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in {"true", "1", "on", "enabled", "active", "yes", "running"}
