# Low-code connectors

Low-code connectors discover AI agents, bots, and automation workflows on
citizen-developer platforms like Power Platform, Salesforce, ServiceNow,
and workflow automation tools.

!!! info "Live and offline"
    All low-code connectors support both live API collection and offline
    export analysis.

See the [shared connector entry guide](../connectors.md#connector-entry-guide)
for the common modes, permissions, options, fail-closed and evidence-limit
references.

## `lowcode.power-platform`
BAP admin API (environments), Power Automate admin flows, Power Apps admin
apps (AI connector references: `shared_openai`, `shared_azureopenai`,
`shared_aibuilder`, `shared_microsoftcopilotstudio`…), Dataverse `bots` +
`botcomponents` (Copilot Studio agents: generative answers, actions, knowledge,
authentication mode, publish state). Auth: Entra app registered as a Power
Platform application user / tenant admin. Environment enumeration follows
`nextLink`; app enumeration uses the documented AdminApps 2024-10-01 API at
`api.powerplatform.com` with a separate `https://api.powerplatform.com/.default`
token audience. A denied child request or failed continuation marks coverage
incomplete while retaining findings from other environments. Before relying on
live coverage, verify the application's Power Platform roles and known apps
in a read-only tenant canary.

## `lowcode.salesforce`
SOQL/Tooling: `BotDefinition`/`BotVersion` (Einstein bots & Agentforce
agents), `GenAiPlannerDefinition`/`GenAiPluginDefinition`/`GenAiFunctionDefinition`
(topics, actions, Apex/Flow targets), `GenAiPromptTemplate`, `FlowDefinitionView`
with AI hints, `ConnectedApplication` + `OauthToken` (user-authorised apps,
aggregated). Auth: `access_token` or client-credentials connected app. A flow
whose `TriggerType` is `Scheduled`, `RecordAfterSave`, `RecordBeforeSave`,
`RecordBeforeDelete` or `PlatformEvent` carries `autonomous` as initiation
evidence, with the value in `metadata.trigger_type`.

## `lowcode.servicenow`
Table API: `sn_aia_agent`, `sn_aia_tool`, `sn_aia_usecase`, `sn_aia_trigger`,
`sys_hub_flow` (AI hints), `oauth_entity`. Auth: basic or bearer. Live
collection reads each table in windows of 500 rows (`sysparm_offset` 0, 500,
1000, ...). ACLs remove rows after `sysparm_limit` is applied, so a window can
come back short or even empty before the end of the table: collection stops
only when the windows cover the table's `X-Total-Count`, the number of rows the
query matches before that filtering. A response without a valid `X-Total-Count`
cannot prove where the table ends: an empty page then ends the table with a
warning and the scan is incomplete. `max_pages` bounds each table, and reaching
it is incomplete. An AI agent carries `tool-use` only when the export holds its
`sn_aia_tool` records, and `saas-actions` only when one of them is not a
retrieval tool; the `autonomous` capability needs the agent's `autonomous`
flag or an `agent_type` of exactly `autonomous`. A use case or its
`sn_aia_trigger` records add `scheduled` for a scheduled trigger and
`event-triggered` for a record or application trigger; a use case without a
trigger, which runs from a conversation, adds neither.

A `sys_hub_flow` is reported when its name, description or scope carries a
ServiceNow AI marker (Now Assist, generative AI, GPT, LLM, `sn_generative_ai`,
`sn_aia`, AI agent) or a name that establishes an AI product or provider (a
flow named for Claude or OpenAI). The generic AI-name hint ("Copilot",
"assistant") and ambiguous product names do not qualify a flow on their own,
so a "Copilot seat reclamation" flow that administers licences is not
reported. This is a known false-negative class: a genuine AI flow named only
with a generic word and no marker is missed.

## `lowcode.n8n` · `lowcode.make` · `lowcode.zapier` · `lowcode.workato`
Workflows/scenarios/zaps/recipes with AI or agent steps (n8n LangChain nodes,
Make AI modules and AI Agents, Zapier AI/Agents from account exports, Workato
GenAI/agentic providers); triggers, code steps (→ code-exec), models. A
schedule trigger adds the `scheduled` tag and a webhook, polled or chained
trigger the `event-triggered` tag, each with the `autonomous` capability as
initiation evidence (see [autonomy tiers](../concepts/autonomy.md)). A trigger
a person operates adds neither: an n8n manual, chat, form or evaluation
trigger, a Workato Workbot command, menu, button, modal or shortcut, or a
Zapier Chrome extension push or Interfaces form. A Make scenario scheduled on
demand adds neither either: a person or a call (the API, another scenario, an
AI agent or an MCP client) can start it. A Workbot event trigger reacts to
workspace events, a bot's messages included, and is event-triggered. n8n classifies its trigger
nodes by type, Make reads `scheduling.type` and webhook modules, Workato the
provider and trigger name of the recipe's trigger line (a Workbot line without
a trigger name records no initiation), and Zapier the first step's app. A
Zapier export record needs an `id`, `title`,
`name` or `Zap` field; any other object is reported as an unsupported record
and makes the scan incomplete. A CSV row whose cells are all blank is skipped
without a diagnostic.

An n8n step counts as AI when its node type is a LangChain, model-provider,
agent or MCP node (`mcp` matched as its own token: custom `mcpClient`,
`MCPServer` and `mcp_bridge` node types count, `mcp9808` sensor and `smcp`
decoder nodes do not), or when it is an HTTP Request node that calls a model
API. The HTTP rule: the node POSTs to a generation route (OpenAI, Anthropic,
Azure OpenAI, Bedrock, Vertex or Ollama style) and either the host is a known
model host, or the route is versioned or namespaced (`/v1/chat/completions`,
`/v1/completions`, `/api/generate`) on a host that is not a known SMS or
messaging API (Vonage, MessageBird, Twilio, Sinch, Plivo, Telnyx).
`/v1/messages`, `/v1/responses` and `/api/chat` are also WhatsApp Business,
messaging and help-desk chat routes, so on an unknown host they count only
when the node sends an `anthropic-version` header, or a JSON or key-value
body with a `model` key and a `messages`, `prompt` or `input` key. A bare
`/messages`, `/responses` or `/completions` on an unknown host, a GET, and a
request body on any other route never count. An HTTP model step makes the
workflow AI use, not an agent: only an agent or agent-tool node makes an n8n
workflow an agent.


See the [main connector reference](../connectors.md) for shared options and offline safety limits.

## Declared graph relationships

`lowcode.n8n` and the filesystem connector's n8n, Flowise and Dify export
readers share bounded graph analysis. Findings include `metadata.workflow_graph`
(or `workflow_graphs` for multiple distinct graph documents), with node/edge
counts, role counts and a bounded example of a directed input → AI → outbound
HTTP/message path. Relationships add **no confidence, capability or risk-score
weight**. A connected path does not prove execution, private-data access,
prompt injection or exfiltration; it does not by itself establish a "lethal
trifecta."

The graph adapter uses exact supported node identifiers, not display names or
serialized parameter searches, and those identifiers decide graph roles only:
the inventory rules above (namespace, provider name, `mcp` token, HTTP model
call, parameter text) still decide whether a workflow is reported, so no
workflow the previous rules found disappears. An unregistered type in the
LangChain namespace, a spoofed `agentPretend` type or a Set node whose
parameters name a model host still yield the inventory finding they did
before; the graph gives such nodes no role, and only an agent or agent-tool
type (now including `openAiAssistant`) makes the finding an agent. A disabled
node stays in the inventory (`metadata.disabled_node_count` counts them) and
does not connect paths. Literal HTTP URLs are parsed into hostnames, so
`api.openai.com.example.invalid` does not establish an OpenAI destination.
Expressions and environment-variable references are not resolved. Flowise
Agent Flows use their declared `startInputType` and HTTP node `inputs.url`;
scheduled starts are not treated as untrusted inputs. A malformed or
over-budget graph marks coverage incomplete and the finding records
`workflow_graph.status: incomplete`; it is never dropped.

Directed traversal handles cycles and joins. n8n `main` edges establish declared
order; `ai_tool`, model and memory attachments do not establish that order.
Flowise edges describe dependencies, so a path remains a declaration rather
than proof of runtime ordering. Model-only Dify configurations remain detectable
without pretending they contain a workflow graph.

Analysis permits at most 16 graph documents per file, 4,096 nodes per graph and
16,384 edges/connection-branch
inspections, with node identifiers capped at 512 characters. A malformed supplied
graph, dangling edge, duplicate identifier or exhausted budget marks coverage
incomplete. An inventory omitting adjacency can still establish AI node presence,
but its graph status is `unavailable` and its path result is `null`, not `false`.
Only a supplied and analyzed graph can produce `false`. Output uses node ordinals
instead of retaining prompts, node names or destination URLs; example paths are
capped at 32 nodes and explicitly disclose truncation.

The fixtures in `tests/fixtures/lowcode/graph_cases.json` cover connected,
disconnected, cyclic, reversed, disabled, non-AI and type-prefix decoy workflows.
They are synthetic regressions, not measured production precision. Registry
extensions should cite the provider's actual node declaration and add positive
and negative fixtures, including version differences where relevant. Provider
references include [n8n node implementations](https://github.com/n8n-io/n8n/tree/master/packages/%40n8n/nodes-langchain/nodes)
and Flowise's [Agent](https://github.com/FlowiseAI/Flowise/blob/main/packages/components/nodes/agentflow/Agent/Agent.ts),
[Start](https://github.com/FlowiseAI/Flowise/blob/main/packages/components/nodes/agentflow/Start/Start.ts),
and [HTTP](https://github.com/FlowiseAI/Flowise/blob/main/packages/components/nodes/agentflow/HTTP/HTTP.ts) declarations.
