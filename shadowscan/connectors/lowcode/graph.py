"""Bounded declared workflow relationships, never runtime or exfiltration proof.

The supported type registry is deliberately exact. Unknown/community node types
keep their graph position but acquire no capability from their display name.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

MAX_GRAPH_DOCUMENTS = 16
MAX_GRAPH_NODES = 4096
MAX_GRAPH_EDGES = 16384
MAX_GRAPH_ID_CHARS = 512
MAX_PATH_NODES = 32
_ADJACENCY_ABSENT = object()

_N8N_PREFIX = "@n8n/n8n-nodes-langchain."
N8N_AGENT_TYPES = frozenset(_N8N_PREFIX + name for name in ("agent", "agentTool", "openAiAssistant"))
N8N_AI_TYPES = (
    N8N_AGENT_TYPES
    | frozenset(
        _N8N_PREFIX + name
        for name in (
            "chainLlm",
            "chainRetrievalQa",
            "chainSummarization",
            "lmChatOpenAi",
            "lmChatAnthropic",
            "lmChatOllama",
            "lmChatGoogleGemini",
            "lmChatGoogleVertex",
            "lmChatAzureOpenAi",
            "lmChatAwsBedrock",
            "lmChatGroq",
            "lmChatMistralCloud",
            "lmChatDeepSeek",
            "lmChatXAiGrok",
            "lmChatCohere",
            "lmOpenAi",
            "openAi",
        )
    )
    | {"n8n-nodes-base.openAi"}
)
# Auxiliary AI configuration is inventory evidence, not an AI processing step.
N8N_INVENTORY_TYPES = N8N_AI_TYPES | frozenset(
    _N8N_PREFIX + name
    for name in (
        "mcpTrigger",
        "mcpClientTool",
        "toolWorkflow",
        "toolCode",
        "toolHttpRequest",
        "memoryBufferWindow",
        "memoryPostgresChat",
        "memoryRedisChat",
        "vectorStorePinecone",
        "vectorStoreQdrant",
        "vectorStoreSupabase",
        "vectorStoreInMemory",
    )
)
_N8N_INPUT_TYPES = frozenset(
    {
        "n8n-nodes-base.webhook",
        "n8n-nodes-base.emailReadImap",
        "n8n-nodes-base.gmailTrigger",
        "n8n-nodes-base.slackTrigger",
        "n8n-nodes-base.formTrigger",
        _N8N_PREFIX + "chatTrigger",
        _N8N_PREFIX + "manualChatTrigger",
        _N8N_PREFIX + "mcpTrigger",
    }
)
_N8N_HTTP_TYPES = frozenset({"n8n-nodes-base.httpRequest", _N8N_PREFIX + "toolHttpRequest"})
# Every operation of the Send Email node delivers a message (v1 has no operation
# selector; v2 offers send and sendAndWait), so the type alone is a sink.
_N8N_SEND_TYPES = frozenset({"n8n-nodes-base.emailSend"})
# Operations that carry workflow data out, keyed by the node type n8n registers
# and named as each node declares them. An omitted, expression-valued or
# unlisted operation gives no role: reads (select, find, aggregate, getAll,
# search), updates of a node's own earlier message and deletions are not egress.
# Postgres and MySQL v2 name their delete operation deleteTable (v1 only has
# executeQuery, insert and update); executeQuery runs SQL the projection does
# not parse, so it counts as a potential write. MongoDB names its delete
# operation delete.
_N8N_SQL_WRITE_OPERATIONS = frozenset({"deleteTable", "executeQuery", "insert", "update", "upsert"})
_N8N_EGRESS_OPERATIONS: dict[str, frozenset[str]] = {
    "n8n-nodes-base.slack": frozenset({"post", "sendAndWait"}),
    "n8n-nodes-base.gmail": frozenset({"reply", "send", "sendAndWait"}),
    "n8n-nodes-base.postgres": _N8N_SQL_WRITE_OPERATIONS,
    "n8n-nodes-base.mySql": _N8N_SQL_WRITE_OPERATIONS,
    "n8n-nodes-base.mongoDb": frozenset(
        {"delete", "findOneAndReplace", "findOneAndUpdate", "insert", "update"}
    ),
}
FLOWISE_AGENT_TYPES = frozenset(
    {
        "toolAgent",
        "openAIFunctionAgent",
        "conversationalAgent",
        "reactAgentLLM",
        "supervisor",
        "worker",
        "agentflow",
        "agentAgentflow",
        "seqAgent",
        "conversationalRetrievalToolAgent",
        "openAIAssistant",
        "reactAgentChat",
    }
)
_FLOWISE_AI_TYPES = FLOWISE_AGENT_TYPES | {"chatOpenAI", "chatAnthropic", "chatOllama", "llmAgentflow"}
_LLM_HOSTS = frozenset(
    {
        "api.openai.com",
        "api.anthropic.com",
        "openrouter.ai",
        "api.groq.com",
        "aiplatform.googleapis.com",
    }
)


def literal_http_host(value: Any) -> str | None:
    """An exact literal HTTP host, excluding credentials and expression interpolation."""
    if not isinstance(value, str) or len(value) > 4096 or any(c in value for c in "{}$\\\r\n\t"):
        return None
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
            return None
        # Accessing port also rejects invalid/overflowing port specifications.
        _ = parsed.port
        return parsed.hostname.lower().rstrip(".") if parsed.hostname else None
    except ValueError:
        return None


def n8n_node_roles(node: dict[str, Any]) -> set[str]:
    if "disabled" in node and node["disabled"] is not False:
        return set()
    kind = node.get("type")
    if not isinstance(kind, str):
        return set()
    roles = set()
    if kind in N8N_AI_TYPES:
        roles.add("ai")
    if kind in _N8N_INPUT_TYPES:
        roles.add("untrusted-input")
    if kind in _N8N_HTTP_TYPES:
        params = node.get("parameters")
        host = literal_http_host(params.get("url")) if isinstance(params, dict) else None
        if host:
            roles.add("egress")
        if host in _LLM_HOSTS:
            roles.add("ai")
    if kind in _N8N_SEND_TYPES:
        roles.add("egress")
    operations = _N8N_EGRESS_OPERATIONS.get(kind)
    if operations is not None:
        params = node.get("parameters")
        operation = params.get("operation") if isinstance(params, dict) else None
        if isinstance(operation, str) and operation in operations:
            roles.add("egress")
    return roles


@dataclass
class GraphAnalysis:
    metadata: dict[str, Any]
    issues: list[str] = field(default_factory=list)


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and bool(value) and len(value) <= MAX_GRAPH_ID_CHARS


def _shape(data: dict[str, Any], provider: str | None) -> tuple[str, Any, Any] | None:
    # A caller that names its provider gets that provider's shape: an n8n
    # export can carry fields that look like a Dify app.
    if provider == "n8n":
        return "n8n", data.get("nodes"), data.get("connections", _ADJACENCY_ABSENT)
    if provider == "flowise":
        return "flowise", data.get("nodes"), data.get("edges", _ADJACENCY_ABSENT)
    workflow = data.get("workflow")
    if provider == "dify" or (data.get("kind") == "app" and isinstance(workflow, dict)):
        graph = workflow.get("graph") if isinstance(workflow, dict) else None
        if isinstance(graph, dict):
            return "dify", graph.get("nodes"), graph.get("edges", _ADJACENCY_ABSENT)
        if isinstance(workflow, dict) and "graph" in workflow:
            return "dify", None, None
        return None
    # Recognise the provider before applying the node budget: a long
    # ``nodes`` list alone (a diagram, a dataset) is not a workflow graph. The
    # scan stops at the first marker and reads only node types, so an
    # over-budget n8n or Flowise graph is still recognised and reported.
    nodes = data.get("nodes")
    if not isinstance(nodes, list):
        return None
    if any(
        isinstance(n, dict)
        and isinstance(n.get("type"), str)
        and n["type"].startswith(("n8n-nodes-base.", _N8N_PREFIX))
        for n in nodes
    ):
        return "n8n", nodes, data.get("connections", _ADJACENCY_ABSENT)
    if any(
        isinstance(n, dict)
        and isinstance(n.get("data"), dict)
        and isinstance(n["data"].get("name"), str)
        and n["data"]["name"] in _FLOWISE_AI_TYPES
        for n in nodes
    ):
        return "flowise", nodes, data.get("edges", _ADJACENCY_ABSENT)
    return None


def is_workflow_graph(data: dict[str, Any]) -> bool:
    """Shape detection over node types only, without traversing edges or constructing roles."""
    return _shape(data, None) is not None


def _roles(provider: str, node: dict[str, Any]) -> set[str]:
    if provider == "n8n":
        return n8n_node_roles(node)
    data = node.get("data")
    if not isinstance(data, dict) or node.get("disabled") or data.get("disabled"):
        return set()
    kind = data.get("type" if provider == "dify" else "name")
    if not isinstance(kind, str):
        return set()
    roles = set()
    if kind in ({"agent", "llm"} if provider == "dify" else _FLOWISE_AI_TYPES):
        roles.add("ai")
    if provider == "dify" and kind == "start":
        roles.add("untrusted-input")
    if provider == "flowise" and kind == "startAgentflow":
        inputs = data.get("inputs")
        if (
            isinstance(inputs, dict)
            and isinstance(inputs.get("startInputType"), str)
            and inputs["startInputType"]
            in {
                "chatInput",
                "formInput",
                "webhookTrigger",
            }
        ):
            roles.add("untrusted-input")
    # Flowise customTool can execute arbitrary code; its behavior is not inferred.
    if provider == "dify" and kind == "http-request" and literal_http_host(data.get("url")):
        roles.add("egress")
    if provider == "flowise" and kind == "httpAgentflow":
        inputs = data.get("inputs")
        if isinstance(inputs, dict) and literal_http_host(inputs.get("url")):
            roles.add("egress")
    return roles


def analyze_workflow_graph(data: dict[str, Any], *, provider: str | None = None) -> GraphAnalysis | None:
    """Project one recognized graph with O(nodes + edges) work and bounded output.

    Omitted adjacency is explicitly unavailable; a supplied malformed graph or
    exhausted budget reports an issue for the caller's incomplete mechanism.
    """
    shape = _shape(data, provider)
    if shape is None:
        return None
    platform, nodes, connections = shape
    metadata: dict[str, Any] = {
        "provider": platform,
        "status": "unavailable",
        "scoring": False,
        "potential_input_ai_egress_path": None,
        "limitations": [
            "Declared connectivity does not prove execution, access to private data or exfiltration.",
            "Only supported exact node types and literal HTTP destinations receive roles; "
            "expressions are unresolved.",
        ],
    }
    result = GraphAnalysis(metadata)

    def invalid(reason: str) -> GraphAnalysis:
        metadata["status"] = "incomplete"
        result.issues.append(reason)
        return result

    if not isinstance(nodes, list):
        return invalid("workflow graph has invalid nodes")
    if len(nodes) > MAX_GRAPH_NODES:
        return invalid("workflow graph exceeds node budget")
    if any(not isinstance(node, dict) for node in nodes):
        return invalid("workflow graph has invalid nodes")
    metadata["node_count"] = len(nodes)
    if connections is _ADJACENCY_ABSENT:
        metadata["limitations"].append("Adjacency was not supplied; reachability is unknown.")
        return result
    ids: dict[str, int] = {}
    roles: list[set[str]] = []
    disabled: set[int] = set()
    for number, node in enumerate(nodes):
        key = node.get("name" if platform == "n8n" else "id")
        if not _identifier(key) or key in ids:
            return invalid("workflow graph has missing, duplicate or oversized node identifiers")
        ids[key] = number
        roles.append(_roles(platform, node))
        node_data = node.get("data")
        if ("disabled" in node and node["disabled"] is not False) or (
            isinstance(node_data, dict) and node_data.get("disabled")
        ):
            disabled.add(number)
    adjacency: list[list[int]] = [[] for _ in nodes]
    edge_count = 0
    inspected = 0

    def edge(source: Any, target: Any, active: bool = True) -> bool:
        nonlocal edge_count
        edge_count += 1
        if edge_count > MAX_GRAPH_EDGES or not _identifier(source) or not _identifier(target):
            return False
        if source not in ids or target not in ids:
            return False
        if active and ids[source] not in disabled and ids[target] not in disabled:
            adjacency[ids[source]].append(ids[target])
        return True

    if platform == "n8n":
        if not isinstance(connections, dict) or len(connections) > MAX_GRAPH_NODES:
            return invalid("workflow graph has invalid connections")
        for source, outputs in connections.items():
            if source not in ids or not isinstance(outputs, dict):
                return invalid("workflow graph has invalid connection sources")
            for channel, branches in outputs.items():
                inspected += 1
                if inspected > MAX_GRAPH_EDGES or not isinstance(branches, list):
                    return invalid("workflow graph has invalid or oversized connection branches")
                for branch in branches:
                    inspected += 1
                    if inspected > MAX_GRAPH_EDGES:
                        return invalid("workflow graph has invalid or oversized connection branches")
                    if branch is None:
                        # n8n types each output slot as IConnection[] | null: an
                        # unconnected If/Switch output is exported as null.
                        continue
                    if not isinstance(branch, list):
                        return invalid("workflow graph has invalid or oversized connection branches")
                    for item in branch:
                        if not isinstance(item, dict):
                            return invalid("workflow graph has invalid edges or exceeds edge budget")
                        edge_type, input_index = item.get("type", channel), item.get("index", 0)
                        if (
                            not isinstance(edge_type, str)
                            or edge_type != channel
                            or isinstance(input_index, bool)
                            or not isinstance(input_index, int)
                            or input_index < 0
                        ):
                            return invalid("workflow graph has invalid connection type or input index")
                        if not edge(source, item.get("node"), channel == "main"):
                            return invalid("workflow graph has invalid edges or exceeds edge budget")
        metadata["limitations"].append(
            "Only main-channel edges establish order; AI tool/model attachments are excluded."
        )
    else:
        if not isinstance(connections, list) or len(connections) > MAX_GRAPH_EDGES:
            return invalid("workflow graph has invalid edges or exceeds edge budget")
        for item in connections:
            if not isinstance(item, dict) or not edge(item.get("source"), item.get("target")):
                return invalid("workflow graph has dangling or invalid edges")
        if platform == "flowise":
            metadata["limitations"].append(
                "Flowise edges declare dependencies and do not establish runtime execution order."
            )
    metadata["status"] = "analyzed"
    metadata["edge_count"] = edge_count
    metadata["role_counts"] = {
        role: sum(role in item for item in roles) for role in ("untrusted-input", "ai", "egress")
    }
    path = _find_path(adjacency, roles)
    metadata["potential_input_ai_egress_path"] = path is not None
    if path is not None:
        # Ordinals avoid retaining arbitrary node names, URLs or prompt content.
        metadata["path_node_indices"] = path[:MAX_PATH_NODES]
        metadata["path_length"] = len(path)
        metadata["path_truncated"] = len(path) > MAX_PATH_NODES
    return result


def _find_path(adjacency: list[list[int]], roles: list[set[str]]) -> list[int] | None:
    """Multi-source BFS over (node, AI-seen), safe for cycles and joins."""
    previous: dict[tuple[int, bool], tuple[int, bool] | None] = {}
    pending: deque[tuple[int, bool]] = deque()
    for number, role in enumerate(roles):
        if "untrusted-input" in role:
            state = (number, "ai" in role)
            previous[state] = None
            pending.append(state)
    while pending:
        state = pending.popleft()
        number, ai_seen = state
        if ai_seen and "egress" in roles[number]:
            path = []
            cursor: tuple[int, bool] | None = state
            while cursor is not None:
                path.append(cursor[0])
                cursor = previous[cursor]
            return list(reversed(path))
        for following in adjacency[number]:
            next_state = (following, ai_seen or "ai" in roles[following])
            if next_state not in previous:
                previous[next_state] = state
                pending.append(next_state)
    return None
