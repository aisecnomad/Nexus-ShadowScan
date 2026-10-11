"""Low-code-surface families: Power Platform (Copilot Studio, Power Automate) and n8n.

Rubric. ``agent``: a Copilot Studio agent with generative orchestration and at
least one action, tool, agent flow or autonomous trigger; a Power Automate flow
that invokes a Copilot Studio agent; an n8n workflow with an AI Agent node, an
MCP client tool or an MCP server trigger. ``llm``: an AI step without agency: a
flow with an Azure OpenAI or AI Builder text action, a Copilot Studio bot with
generative answers but no actions, an n8n LLM chain, OpenAI node or raw HTTP
call to a model API. ``none``: no AI, including classic topic-only bots, plain
flows and workflows whose names mention AI or agents.
"""

from __future__ import annotations

import json
from typing import Any

from tools.benchmark.common import OPENAI_MODELS, Rand
from tools.shadowbench.contract import TruthEntity
from tools.shadowbench.families import Draft, email, guid, iso

ENV_NAME = "Default-acme"
ENV_DISPLAY = "Default (acme)"
PP_API = "/providers/Microsoft.PowerApps/apis"


def _flow(rd: Rand, name: str, actions: list[dict[str, Any]], refs: dict[str, str]) -> dict[str, Any]:
    fid = guid(rd)
    return {
        "name": fid,
        "id": f"/providers/Microsoft.ProcessSimple/environments/{ENV_NAME}/flows/{fid}",
        "type": "Microsoft.ProcessSimple/environments/flows",
        "properties": {
            "displayName": name,
            "state": rd.choice(("Started", "Started", "Stopped")),
            "createdTime": iso(rd, 2025),
            "lastModifiedTime": iso(rd),
            "creator": {"userId": guid(rd), "userPrincipalName": email(rd), "userType": "ActiveDirectory"},
            "environment": {"name": ENV_NAME, "type": "Microsoft.ProcessSimple/environments"},
            "definitionSummary": {
                "triggers": [
                    {"type": rd.choice(("Recurrence", "ApiConnection", "Request")), "kind": "Button"}
                ],
                "actions": actions,
            },
            "connectionReferences": {k: {"id": f"{PP_API}/{k}", "displayName": v} for k, v in refs.items()},
        },
    }


def _bot(rd: Rand, name: str, generative: bool, orchestration: bool, auth: int) -> dict[str, Any]:
    bot_id = guid(rd)
    config = {
        "$kind": "BotConfiguration",
        "settings": {
            "GenerativeActionsEnabled": orchestration,
            "GenerativeAnswersEnabled": generative,
            "GenerativeOrchestration": "Enabled" if orchestration else "Disabled",
            "Language": "en-US",
        },
    }
    return {
        "botid": bot_id,
        "name": name,
        "schemaname": "cr" + rd.hexid(3) + "_" + name.lower().replace(" ", "").replace("-", "")[:20],
        "authenticationmode": auth,
        "statecode": 0,
        "statuscode": 1,
        "publishedon": iso(rd),
        "createdon": iso(rd, 2025),
        "modifiedon": iso(rd),
        "language": 1033,
        "accesscontrolpolicy": 0,
        "_ownerid_value": guid(rd),
        "_environment": ENV_DISPLAY,
        "configuration": json.dumps(config),
    }


def _component(rd: Rand, bot_id: str, name: str, ctype: int, type_name: str, data: str) -> dict[str, Any]:
    return {
        "botcomponentid": guid(rd),
        "name": name,
        "componenttype": ctype,
        "componenttypename": type_name,
        "_parentbotid_value": bot_id,
        "data": data,
        "statecode": 0,
    }


# --- Power Platform families -------------------------------------------------


def pp_copilot_studio_agent(rd: Rand) -> Draft:
    name = rd.choice(("HR Helper", "Procurement Agent", "IT Support Agent", "Expense Assistant"))
    bot = _bot(rd, name, True, True, rd.choice((0, 1, 2)))
    comps = [
        _component(
            rd,
            bot["botid"],
            "Greeting",
            0,
            "Topic",
            "kind: AdaptiveDialog\nbeginDialog:\n  kind: OnConversationStart\n",
        ),
        _component(
            rd,
            bot["botid"],
            rd.choice(("Create ticket", "Look up order", "Send email", "Update CRM record")),
            9,
            "Action",
            "kind: TaskDialog\nmodelDescription: Creates a ticket for the user\n"
            "action:\n  kind: InvokeFlowAction\n",
        ),
        _component(
            rd,
            bot["botid"],
            "SharePoint policies",
            16,
            "KnowledgeSource",
            "kind: SharePointSearch\nsite: https://acme.sharepoint.com/sites/hr\n",
        ),
    ]
    if rd.chance(0.5):
        comps.append(
            _component(
                rd, bot["botid"], "Daily digest", 15, "Trigger", "kind: OnRecurringEvent\nschedule: daily\n"
            )
        )
    return Draft(
        "pp-copilot-studio-agent",
        "agent",
        "easy",
        "Copilot Studio agent with generative orchestration, an action and a knowledge source.",
        {"bots": [bot], "botcomponents": comps},
        expected=[
            TruthEntity(
                "bot",
                f"bot:{bot['botid']}",
                "agent",
                {"platform": "power-platform", "name": name},
                "configuration GenerativeOrchestration Enabled; botcomponent of type Action",
            )
        ],
    )


def pp_flow_invokes_agent(rd: Rand) -> Draft:
    name = rd.choice(("Route escalations to agent", "Nightly supplier follow-up", "Agentic refund review"))
    actions = [
        {
            "type": "OpenApiConnection",
            "swaggerOperationId": "InvokeAgent",
            "api": {"name": "shared_microsoftcopilotstudio"},
        },
        {
            "type": "OpenApiConnection",
            "swaggerOperationId": "SendEmailV2",
            "api": {"name": "shared_office365"},
        },
    ]
    flow = _flow(
        rd,
        name,
        actions,
        {
            "shared_microsoftcopilotstudio": "Microsoft Copilot Studio",
            "shared_office365": "Office 365 Outlook",
        },
    )
    return Draft(
        "pp-flow-invokes-agent",
        "agent",
        "medium",
        "Power Automate flow invoking a Copilot Studio agent and acting on the result.",
        {"flows": [flow]},
        expected=[
            TruthEntity(
                "flow",
                f"flow:{flow['name']}",
                "agent",
                {"platform": "power-platform", "name": name},
                "connectionReferences shared_microsoftcopilotstudio; action InvokeAgent",
            )
        ],
    )


def pp_flow_gpt_step(rd: Rand) -> Draft:
    name = rd.choice(
        ("Summarise support emails with GPT", "Draft reply suggestions", "Classify incoming invoices")
    )
    connector, op, display = rd.choice(
        (
            ("shared_azureopenai", "CreateTextWithGPT", "Azure OpenAI"),
            ("shared_aibuilder", "CreateTextWithGPTUsingPrompt", "AI Builder"),
            ("shared_openai", "CreateChatCompletion", "OpenAI"),
        )
    )
    actions = [
        {"type": "OpenApiConnection", "swaggerOperationId": "GetEmails", "api": {"name": "shared_office365"}},
        {"type": "OpenApiConnection", "swaggerOperationId": op, "api": {"name": connector}},
        {"type": "OpenApiConnection", "swaggerOperationId": "PostMessage", "api": {"name": "shared_teams"}},
    ]
    flow = _flow(
        rd,
        name,
        actions,
        {"shared_office365": "Office 365 Outlook", connector: display, "shared_teams": "Microsoft Teams"},
    )
    return Draft(
        "pp-flow-gpt-step",
        "llm",
        "easy",
        f"Flow with a {display} text-generation step and no agent.",
        {"flows": [flow]},
        expected=[
            TruthEntity(
                "flow",
                f"flow:{flow['name']}",
                "llm",
                {"platform": "power-platform", "name": name},
                f"action {op} on connector {connector}",
            )
        ],
    )


def pp_bot_generative_answers(rd: Rand) -> Draft:
    name = rd.choice(("Policy Q&A", "Benefits FAQ bot", "Travel policy assistant"))
    bot = _bot(rd, name, True, False, 1)
    comps = [
        _component(
            rd,
            bot["botid"],
            "Conversational boosting",
            0,
            "Topic",
            "kind: AdaptiveDialog\nactions:\n  - kind: SearchAndSummarizeContent\n",
        ),
        _component(
            rd,
            bot["botid"],
            "Public website",
            16,
            "KnowledgeSource",
            "kind: PublicWebSearch\nsite: https://acme.example/policies\n",
        ),
    ]
    return Draft(
        "pp-bot-generative-answers",
        "llm",
        "medium",
        "Copilot Studio bot with generative answers but no actions or orchestration.",
        {"bots": [bot], "botcomponents": comps},
        expected=[
            TruthEntity(
                "bot",
                f"bot:{bot['botid']}",
                "llm",
                {"platform": "power-platform", "name": name},
                "GenerativeAnswersEnabled true, GenerativeOrchestration Disabled, no Action components",
            )
        ],
    )


def pp_flow_plain(rd: Rand) -> Draft:
    name = rd.choice(
        (
            "Copy files nightly",
            "Approve expense reports",
            "Sync SharePoint list to Excel",
            "Notify on new lead",
        )
    )
    actions = [
        {
            "type": "OpenApiConnection",
            "swaggerOperationId": "GetItems",
            "api": {"name": "shared_sharepointonline"},
        },
        {
            "type": "OpenApiConnection",
            "swaggerOperationId": "StartAndWaitForAnApproval",
            "api": {"name": "shared_approvals"},
        },
    ]
    flow = _flow(
        rd, name, actions, {"shared_sharepointonline": "SharePoint", "shared_approvals": "Approvals"}
    )
    return Draft("pp-flow-plain", "none", "easy", "Ordinary approval flow.", {"flows": [flow]})


def pp_flow_decoy_name(rd: Rand) -> Draft:
    name = rd.choice(
        ("AI Weekly Digest", "Agent onboarding checklist", "Copilot licence report", "GPT-4 rollout tracker")
    )
    actions = [
        {
            "type": "OpenApiConnection",
            "swaggerOperationId": "GetItems",
            "api": {"name": "shared_sharepointonline"},
        },
        {
            "type": "OpenApiConnection",
            "swaggerOperationId": "SendEmailV2",
            "api": {"name": "shared_office365"},
        },
    ]
    flow = _flow(
        rd, name, actions, {"shared_sharepointonline": "SharePoint", "shared_office365": "Office 365 Outlook"}
    )
    return Draft(
        "pp-flow-decoy-name",
        "none",
        "hard",
        "Flow whose name mentions AI but uses no AI connector.",
        {"flows": [flow]},
    )


def pp_bot_classic(rd: Rand) -> Draft:
    name = rd.choice(("Store hours bot", "Parking FAQ", "Cafeteria menu bot"))
    bot = _bot(rd, name, False, False, 0)
    comps = [
        _component(
            rd,
            bot["botid"],
            "Opening hours",
            0,
            "Topic",
            "kind: AdaptiveDialog\nactions:\n  - kind: SendMessage\n    message: We open at 9.\n",
        ),
        _component(
            rd,
            bot["botid"],
            "Fallback",
            0,
            "Topic",
            "kind: AdaptiveDialog\nactions:\n  - kind: SendMessage\n"
            "    message: Sorry, I did not get that.\n",
        ),
    ]
    return Draft(
        "pp-bot-classic",
        "none",
        "hard",
        "Classic topic-only bot with generative AI disabled: a scripted chatbot, not an AI agent.",
        {"bots": [bot], "botcomponents": comps},
    )


def pp_canvas_app(rd: Rand) -> Draft:
    app_id = guid(rd)
    app = {
        "name": app_id,
        "id": f"/providers/Microsoft.PowerApps/apps/{app_id}",
        "type": "Microsoft.PowerApps/apps",
        "properties": {
            "displayName": rd.choice(("Visitor sign-in", "Asset checkout", "Shift swap")),
            "appType": "ClassicCanvasApp",
            "appVersion": iso(rd),
            "owner": {"email": email(rd)},
            "connectionReferences": {"shared_sharepointonline": {"id": f"{PP_API}/shared_sharepointonline"}},
        },
    }
    return Draft("pp-canvas-app", "none", "easy", "Canvas app on SharePoint.", {"apps": [app]})


PP_AGENT = (pp_copilot_studio_agent, pp_flow_invokes_agent)
PP_LLM = (pp_flow_gpt_step, pp_bot_generative_answers)
PP_NONE = (pp_flow_plain, pp_flow_decoy_name, pp_bot_classic, pp_canvas_app)


# --- n8n families ------------------------------------------------------------


def _wf(rd: Rand, name: str, nodes: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "id": rd.hexid(16),
        "name": name,
        "active": rd.chance(0.75),
        "createdAt": iso(rd, 2025),
        "updatedAt": iso(rd),
        "homeProject": {"name": rd.choice(("Sales Ops", "Finance", "Platform", "Marketing"))},
        "nodes": nodes,
        "connections": {},
        "settings": {"executionOrder": "v1"},
        "tags": [],
    }


def _node(ntype: str, name: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"type": ntype, "name": name, "typeVersion": 1, "parameters": params or {}, "position": [0, 0]}


def _trigger(rd: Rand) -> dict[str, Any]:
    chosen: dict[str, Any] = rd.choice(
        (
            _node("n8n-nodes-base.scheduleTrigger", "Every hour"),
            _node("n8n-nodes-base.webhook", "Webhook", {"path": rd.ident()}),
            _node("n8n-nodes-base.slackTrigger", "Slack message"),
        )
    )
    return chosen


def n8n_ai_agent(rd: Rand) -> Draft:
    name = rd.choice(("Lead qualifier agent", "Support reply drafter", "Inventory reorder agent"))
    nodes = [
        _trigger(rd),
        _node("@n8n/n8n-nodes-langchain.agent", "AI Agent", {"promptType": "define", "options": {}}),
        _node(
            "@n8n/n8n-nodes-langchain.lmChatOpenAi",
            "OpenAI Chat Model",
            {"model": {"value": rd.choice(OPENAI_MODELS)}},
        ),
        _node(
            rd.choice(
                (
                    "@n8n/n8n-nodes-langchain.toolCode",
                    "@n8n/n8n-nodes-langchain.toolHttpRequest",
                    "@n8n/n8n-nodes-langchain.toolWorkflow",
                )
            ),
            "Tool",
        ),
        _node("n8n-nodes-base.hubspot", "HubSpot"),
    ]
    wf = _wf(rd, name, nodes)
    return Draft(
        "n8n-ai-agent",
        "agent",
        "easy",
        "n8n workflow with an AI Agent node, a chat model and a tool.",
        {"workflows": [wf]},
        expected=[
            TruthEntity(
                "workflow",
                f"workflow:{wf['id']}",
                "agent",
                {"platform": "n8n", "name": name},
                "node type @n8n/n8n-nodes-langchain.agent with a tool node",
            )
        ],
    )


def n8n_mcp(rd: Rand) -> Draft:
    if rd.chance(0.5):
        name = "Expose CRM lookup to Claude"
        nodes = [
            _node("@n8n/n8n-nodes-langchain.mcpTrigger", "MCP Server Trigger", {"path": rd.ident()}),
            _node("n8n-nodes-base.hubspotTool", "Find contact"),
        ]
        evidence = "node type @n8n/n8n-nodes-langchain.mcpTrigger exposes the workflow as an MCP server"
        fam = "n8n-mcp-server-trigger"
    else:
        name = "Agent with GitHub MCP tools"
        nodes = [
            _trigger(rd),
            _node("@n8n/n8n-nodes-langchain.agent", "AI Agent"),
            _node("@n8n/n8n-nodes-langchain.lmChatAnthropic", "Anthropic Chat Model"),
            _node(
                "@n8n/n8n-nodes-langchain.mcpClientTool",
                "GitHub MCP",
                {"endpointUrl": "https://api.githubcopilot.com/mcp/"},
            ),
        ]
        evidence = "node type @n8n/n8n-nodes-langchain.mcpClientTool bound to an agent"
        fam = "n8n-mcp-client-tool"
    wf = _wf(rd, name, nodes)
    return Draft(
        fam,
        "agent",
        "medium",
        "n8n workflow using the Model Context Protocol.",
        {"workflows": [wf]},
        expected=[
            TruthEntity(
                "workflow", f"workflow:{wf['id']}", "agent", {"platform": "n8n", "name": name}, evidence
            )
        ],
    )


def n8n_llm_chain(rd: Rand) -> Draft:
    name = rd.choice(("Summarise tickets", "Translate release notes", "Tag feedback"))
    style = rd.choice(("chain", "openai", "http"))
    if style == "chain":
        ai = [
            _node("@n8n/n8n-nodes-langchain.chainLlm", "Basic LLM Chain"),
            _node(
                "@n8n/n8n-nodes-langchain.lmChatOpenAi",
                "OpenAI Chat Model",
                {"model": {"value": rd.choice(OPENAI_MODELS)}},
            ),
        ]
        evidence = "chainLlm with a chat model and no agent or tool node"
    elif style == "openai":
        ai = [
            _node("@n8n/n8n-nodes-langchain.openAi", "OpenAI", {"resource": "text", "operation": "message"})
        ]
        evidence = "openAi node (text message operation) with no agent or tool node"
    else:
        ai = [
            _node(
                "n8n-nodes-base.httpRequest",
                "Call model",
                {
                    "method": "POST",
                    "url": "https://api.openai.com/v1/chat/completions",
                    "authentication": "predefinedCredentialType",
                },
            )
        ]
        evidence = "httpRequest to api.openai.com/v1/chat/completions"
    nodes = [_trigger(rd), *ai, _node("n8n-nodes-base.slack", "Slack")]
    wf = _wf(rd, name, nodes)
    return Draft(
        f"n8n-llm-{style}",
        "llm",
        "easy" if style != "http" else "medium",
        "n8n workflow with an LLM step and no agent.",
        {"workflows": [wf]},
        expected=[
            TruthEntity(
                "workflow", f"workflow:{wf['id']}", "llm", {"platform": "n8n", "name": name}, evidence
            )
        ],
    )


def n8n_plain(rd: Rand) -> Draft:
    name = rd.choice(("Backup sheets", "Post standup reminder", "Sync Jira to Sheets"))
    nodes = [
        _trigger(rd),
        _node("n8n-nodes-base.googleSheets", "Sheets"),
        _node("n8n-nodes-base.slack", "Slack"),
    ]
    return Draft("n8n-plain", "none", "easy", "Ordinary automation.", {"workflows": [_wf(rd, name, nodes)]})


def n8n_decoy_name(rd: Rand) -> Draft:
    name = rd.choice(
        ("Agent handoff rotation", "AI newsletter digest", "Copilot seat report", "MCP partner sync")
    )
    nodes = [
        _trigger(rd),
        _node(
            "n8n-nodes-base.httpRequest",
            "Fetch roster",
            {"method": "GET", "url": "https://rota.acme.example/api/agents"},
        ),
        _node("n8n-nodes-base.emailSend", "Email"),
    ]
    return Draft(
        "n8n-decoy-name",
        "none",
        "hard",
        "Workflow name mentions agents or AI; nodes hold no AI.",
        {"workflows": [_wf(rd, name, nodes)]},
    )


N8N_AGENT = (n8n_ai_agent, n8n_mcp)
N8N_LLM = (n8n_llm_chain,)
N8N_NONE = (n8n_plain, n8n_decoy_name)
