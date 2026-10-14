"""Gateway-surface families: LiteLLM spend logs and Bedrock model invocation logs.

Rubric. Every caller in an LLM gateway log uses a model, so the surface has no
``none`` entities; the question is agent tier. A caller is ``agent`` when its
requests show tool use or an agent loop: tool definitions in the request body
with ``tool_calls`` or ``tool_use`` stop reasons, an agent framework in the
user agent, or a Bedrock agent execution role as the calling identity. A caller
is ``llm`` when it sends plain completions or embeddings: a notebook, a chat UI,
a batch embedding job, a user invoking a model directly.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from tools.benchmark.common import ANTHROPIC_MODELS, OPENAI_MODELS, Rand
from tools.shadowbench.cases.contract import TruthEntity
from tools.shadowbench.cases.families import Draft, email

BASE = datetime(2026, 9, 7, 6, 0, tzinfo=UTC)
ACCOUNT = "123456789012"
BEDROCK_MODELS = (
    "anthropic.claude-3-5-sonnet-20241022-v2:0",
    "anthropic.claude-sonnet-4-20250514-v1:0",
    "amazon.nova-pro-v1:0",
    "meta.llama3-1-70b-instruct-v1:0",
)
AGENT_UAS = (
    "langchain/0.3.27 OpenAI/Python 1.106.1",
    "crewai/0.186.1 python-requests/2.32.5",
    "openai-agents/0.3.0 OpenAI/Python 1.106.1",
    "autogen-agentchat/0.7.4 OpenAI/Python 1.106.1",
    "langgraph/0.6.7 OpenAI/Python 1.106.1",
    "AnthropicPython/0.69.0 (claude-agent-sdk/0.1.0)",
)
PLAIN_UAS = (
    "OpenAI/Python 1.106.1",
    "python-requests/2.32.5",
    "OpenAI/JS 5.20.1",
    "Open WebUI/0.6.26",
    "curl/8.5.0",
    "node-fetch/1.0 (+https://github.com/bitinn/node-fetch)",
)


def _stamp(t: datetime) -> str:
    return t.isoformat().replace("+00:00", "+00:00")


def _row(
    rd: Rand,
    alias: str,
    t: datetime,
    *,
    model: str,
    provider: str,
    ua: str,
    ip: str,
    user: str,
    tools: bool,
    call_type: str = "acompletion",
    team: str = "",
) -> dict[str, Any]:
    prompt = rd.randint(200, 6000)
    completion = rd.randint(20, 900)
    body: dict[str, Any] = {"model": model, "messages": [], "stream": rd.chance(0.3)}
    finish = "stop"
    if tools:
        body["tools"] = [
            {"type": "function", "function": {"name": name, "parameters": {"type": "object"}}}
            for name, _d, _p in rd.tools(rd.randint(2, 5))
        ]
        body["tool_choice"] = "auto"
        finish = "tool_calls" if rd.chance(0.7) else "stop"
    if call_type == "aembedding":
        body = {"model": model, "input": ["..."] * rd.randint(1, 64)}
        completion = 0
    return {
        "request_id": "chatcmpl-" + rd.hexid(24) if call_type != "aembedding" else "emb-" + rd.hexid(24),
        "call_type": call_type,
        "api_key": "hashed-" + rd.hexid(40),
        "api_key_alias": alias,
        "team_id": team or None,
        "model": model,
        "custom_llm_provider": provider,
        "spend": round(prompt * 2.5e-6 + completion * 1e-5, 6),
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "total_tokens": prompt + completion,
        "startTime": _stamp(t),
        "endTime": _stamp(t + timedelta(milliseconds=rd.randint(400, 9000))),
        "user": user,
        "cache_hit": "False",
        "metadata": {
            "user_agent": ua,
            "requester_ip_address": ip,
            "user_api_key_alias": alias,
            "user_api_key_team_alias": team or None,
        },
        "proxy_server_request": {"url": "http://litellm.internal:4000/v1/chat/completions", "body": body},
        "response": {"choices": [{"finish_reason": finish}]} if call_type != "aembedding" else {},
        "status": "success",
    }


def _ip(rd: Rand) -> str:
    return f"10.{rd.randint(0, 40)}.{rd.randint(0, 255)}.{rd.randint(2, 250)}"


def _model(rd: Rand) -> tuple[str, str]:
    if rd.chance(0.5):
        return str(rd.choice(OPENAI_MODELS)), "openai"
    return str(rd.choice(ANTHROPIC_MODELS)), "anthropic"


# --- LiteLLM callers -------------------------------------------------------


def ll_agent_tool_loop(rd: Rand) -> Draft:
    alias = rd.choice(
        ("research-agent-prod", "support-triage-agent", "invoice-matcher", "sre-copilot-worker")
    )
    alias = f"{alias}-{rd.hexid(3)}"
    ua = rd.choice(AGENT_UAS + ("OpenAI/Python 1.106.1",))
    model, provider = _model(rd)
    ip = _ip(rd)
    t0 = BASE + timedelta(minutes=rd.randint(0, 600))
    rows = []
    for i in range(rd.randint(12, 60)):
        t = t0 + timedelta(seconds=i * rd.randint(3, 25))
        rows.append(_row(rd, alias, t, model=model, provider=provider, ua=ua, ip=ip, user="", tools=True))
    return Draft(
        "litellm-agent-tool-loop",
        "agent",
        "easy",
        "Service key sending back-to-back tool-enabled completions with tool_calls finish reasons.",
        {"rows": rows},
        expected=[
            TruthEntity(
                "caller",
                f"caller:{alias}",
                "agent",
                {"platform": "litellm"},
                "request bodies carry tools with tool_choice auto; finish_reason tool_calls; loop cadence",
            )
        ],
    )


def ll_agent_framework_ua(rd: Rand) -> Draft:
    alias = f"{rd.choice(('crew', 'graph', 'flow', 'pipeline'))}-{rd.ident()}"
    ua = rd.choice(AGENT_UAS)
    model, provider = _model(rd)
    ip = _ip(rd)
    t0 = BASE + timedelta(minutes=rd.randint(0, 600))
    rows = [
        _row(
            rd,
            alias,
            t0 + timedelta(seconds=i * rd.randint(10, 90)),
            model=model,
            provider=provider,
            ua=ua,
            ip=ip,
            user="",
            tools=rd.chance(0.4),
        )
        for i in range(rd.randint(4, 20))
    ]
    return Draft(
        "litellm-agent-framework-ua",
        "agent",
        "medium",
        "Key whose user agent names an agent framework.",
        {"rows": rows},
        expected=[
            TruthEntity(
                "caller",
                f"caller:{alias}",
                "agent",
                {"platform": "litellm"},
                f"metadata.user_agent {ua!r} names an agent framework",
            )
        ],
    )


def ll_notebook_user(rd: Rand) -> Draft:
    user = email(rd)
    alias = f"{user.split('@')[0]}-{rd.choice(('notebook', 'dev', 'laptop'))}"
    model, provider = _model(rd)
    ua = rd.choice(PLAIN_UAS[:3])
    ip = _ip(rd)
    rows = [
        _row(
            rd,
            alias,
            BASE + timedelta(minutes=rd.randint(0, 900)),
            model=model,
            provider=provider,
            ua=ua,
            ip=ip,
            user=user,
            tools=False,
        )
        for _ in range(rd.randint(2, 9))
    ]
    return Draft(
        "litellm-notebook-user",
        "llm",
        "easy",
        "A person's key sending occasional plain completions.",
        {"rows": rows},
        expected=[
            TruthEntity(
                "caller",
                f"caller:{alias}",
                "llm",
                {"platform": "litellm"},
                "plain chat completions without tools from a user-bound key",
            )
        ],
    )


def ll_chat_ui(rd: Rand) -> Draft:
    alias = rd.choice(("open-webui", "team-chat-ui", "librechat"))
    model, provider = _model(rd)
    ip = _ip(rd)
    rows = [
        _row(
            rd,
            alias,
            BASE + timedelta(minutes=rd.randint(0, 900)),
            model=model,
            provider=provider,
            ua="Open WebUI/0.6.26",
            ip=ip,
            user=email(rd),
            tools=False,
            team="chat",
        )
        for _ in range(rd.randint(10, 40))
    ]
    return Draft(
        "litellm-chat-ui",
        "llm",
        "medium",
        "Shared chat UI key with many users and no tools.",
        {"rows": rows},
        expected=[
            TruthEntity(
                "caller",
                f"caller:{alias}",
                "llm",
                {"platform": "litellm"},
                "Open WebUI user agent, plain completions on behalf of many users",
            )
        ],
    )


def ll_embeddings_batch(rd: Rand) -> Draft:
    alias = f"{rd.choice(('search-index', 'rag-ingest', 'doc-embed'))}-{rd.hexid(2)}"
    ip = _ip(rd)
    t0 = BASE + timedelta(minutes=rd.randint(0, 600))
    rows = [
        _row(
            rd,
            alias,
            t0 + timedelta(seconds=i * 2),
            model="text-embedding-3-small",
            provider="openai",
            ua="OpenAI/Python 1.106.1",
            ip=ip,
            user="",
            tools=False,
            call_type="aembedding",
        )
        for i in range(rd.randint(20, 80))
    ]
    return Draft(
        "litellm-embeddings-batch",
        "llm",
        "hard",
        "High-cadence embedding batch: looks like a loop but holds no tool use.",
        {"rows": rows},
        expected=[
            TruthEntity(
                "caller",
                f"caller:{alias}",
                "llm",
                {"platform": "litellm"},
                "call_type aembedding only; no messages, tools or finish reasons",
            )
        ],
    )


LITELLM_AGENT = (ll_agent_tool_loop, ll_agent_framework_ua)
LITELLM_LLM = (ll_notebook_user, ll_chat_ui, ll_embeddings_batch)
LITELLM_NONE: tuple[Any, ...] = ()


# --- Bedrock invocation logs -------------------------------------------------


def _bedrock_row(
    rd: Rand, t: datetime, arn: str, model: str, *, tools: bool, operation: str = "Converse"
) -> dict[str, Any]:
    body: dict[str, Any] = {"messages": [], "inferenceConfig": {"maxTokens": 2048}}
    stop = "end_turn"
    if tools:
        body["toolConfig"] = {
            "tools": [
                {"toolSpec": {"name": n, "inputSchema": {"json": {"type": "object"}}}}
                for n, _d, _p in rd.tools(rd.randint(2, 4))
            ]
        }
        stop = "tool_use" if rd.chance(0.7) else "end_turn"
    return {
        "schemaType": "ModelInvocationLog",
        "schemaVersion": "1.0",
        "timestamp": _stamp(t),
        "accountId": ACCOUNT,
        "region": "us-east-1",
        "requestId": rd.hexid(8) + "-" + rd.hexid(4),
        "operation": operation,
        "modelId": model,
        "identity": {"arn": arn},
        "input": {
            "inputContentType": "application/json",
            "inputBodyJson": body,
            "inputTokenCount": rd.randint(200, 5000),
        },
        "output": {
            "outputContentType": "application/json",
            "outputBodyJson": {"stopReason": stop},
            "outputTokenCount": rd.randint(20, 800),
        },
    }


def br_agent_role(rd: Rand) -> Draft:
    name = rd.choice(("ops", "claims", "research", "support"))
    role = f"AmazonBedrockExecutionRoleForAgents_{name}{rd.hexid(3)}"
    arn = f"arn:aws:sts::{ACCOUNT}:assumed-role/{role}/BedrockAgents"
    model = rd.choice(BEDROCK_MODELS[:2])
    t0 = BASE + timedelta(minutes=rd.randint(0, 600))
    rows = [
        _bedrock_row(rd, t0 + timedelta(seconds=i * rd.randint(4, 30)), arn, model, tools=True)
        for i in range(rd.randint(8, 40))
    ]
    return Draft(
        "bedrock-agent-role",
        "agent",
        "easy",
        "Invocations by a Bedrock agent execution role with tool configurations.",
        {"rows": rows},
        expected=[
            TruthEntity(
                "caller",
                f"caller:{arn}",
                "agent",
                {"platform": "bedrock"},
                "identity.arn is an AmazonBedrockExecutionRoleForAgents_* role; "
                "toolConfig and tool_use stop reasons",
            )
        ],
    )


def br_workload_tool_loop(rd: Rand) -> Draft:
    role = rd.choice(("eks-research-agent", "ecs-ticket-router", "lambda-invoice-agent"))
    arn = f"arn:aws:sts::{ACCOUNT}:assumed-role/{role}/{rd.hexid(10)}"
    model = rd.choice(BEDROCK_MODELS)
    t0 = BASE + timedelta(minutes=rd.randint(0, 600))
    rows = [
        _bedrock_row(rd, t0 + timedelta(seconds=i * rd.randint(3, 20)), arn, model, tools=True)
        for i in range(rd.randint(10, 50))
    ]
    return Draft(
        "bedrock-workload-tool-loop",
        "agent",
        "medium",
        "A workload role running a tool loop through Converse.",
        {"rows": rows},
        expected=[
            TruthEntity(
                "caller",
                f"caller:{arn}",
                "agent",
                {"platform": "bedrock"},
                "toolConfig in every request and tool_use stop reasons in a tight loop",
            )
        ],
    )


def br_user_invoke(rd: Rand) -> Draft:
    user = rd.choice(("bob", "mei", "sasha", "tariq"))
    arn = f"arn:aws:iam::{ACCOUNT}:user/{user}"
    model = rd.choice(BEDROCK_MODELS)
    rows = [
        _bedrock_row(
            rd,
            BASE + timedelta(minutes=rd.randint(0, 900)),
            arn,
            model,
            tools=False,
            operation=rd.choice(("InvokeModel", "Converse")),
        )
        for _ in range(rd.randint(1, 8))
    ]
    return Draft(
        "bedrock-user-invoke",
        "llm",
        "easy",
        "An IAM user invoking a model directly without tools.",
        {"rows": rows},
        expected=[
            TruthEntity(
                "caller",
                f"caller:{arn}",
                "llm",
                {"platform": "bedrock"},
                "InvokeModel/Converse without toolConfig from an IAM user",
            )
        ],
    )


def br_embeddings_job(rd: Rand) -> Draft:
    role = rd.choice(("glue-embed-job", "sfn-index-builder", "batch-vectorizer"))
    arn = f"arn:aws:sts::{ACCOUNT}:assumed-role/{role}/{rd.hexid(8)}"
    t0 = BASE + timedelta(minutes=rd.randint(0, 600))
    rows = []
    for i in range(rd.randint(20, 80)):
        row = _bedrock_row(
            rd,
            t0 + timedelta(seconds=i),
            arn,
            "amazon.titan-embed-text-v2:0",
            tools=False,
            operation="InvokeModel",
        )
        row["input"]["inputBodyJson"] = {"inputText": "...", "dimensions": 1024}
        row["output"]["outputBodyJson"] = {"embeddingsByType": {"float": "..."}}
        rows.append(row)
    return Draft(
        "bedrock-embeddings-job",
        "llm",
        "hard",
        "High-cadence Titan embedding job: a loop shape without tool use.",
        {"rows": rows},
        expected=[
            TruthEntity(
                "caller",
                f"caller:{arn}",
                "llm",
                {"platform": "bedrock"},
                "embedding model invocations only",
            )
        ],
    )


BEDROCK_AGENT = (br_agent_role, br_workload_tool_loop)
BEDROCK_LLM = (br_user_invoke, br_embeddings_job)
BEDROCK_NONE: tuple[Any, ...] = ()
