# Signatures

The signature system is how ShadowScan recognises AI frameworks, model providers, protocols,
platforms and SaaS products without hard-coding product knowledge in connectors. Every
connector asks the `SignatureIndex` what a given observation means; the index answers with
`Match` objects that carry the matched signature and a weight.

## Signature packs

Signatures are YAML files under `shadowscan/signatures/data/` organised by category:

| Directory | Category |
|-----------|----------|
| `frameworks/` | AI orchestration frameworks (LangChain, LlamaIndex, AutoGen, …) |
| `providers/` | Model inference providers (OpenAI, Anthropic, AWS Bedrock, …) |
| `protocols/` | Agent communication protocols (MCP, A2A, OpenAPI, …) |
| `platforms/` | Cloud AI platforms (Vertex AI, Azure ML, …) |
| `identity/` | OAuth app signatures and permission policies |
| `coding_agents/` | Coding-agent products (GitHub Copilot, Cursor, …) |
| `heuristics/` | File-corpus and heuristic patterns |
| `observability/` | OTel GenAI semantic conventions |

Custom or overriding packs are loaded from the directories listed under `signatures:` in the
scan config, merged with the built-in packs in load order.

## Signal types

Each signature defines one or more signals that can fire on a surface:

`dependency`, `import`, `code`, `env`, `domain`, `user_agent`, `model`, `secret`, `iac`,
`scope`, `name`, `client_id`, `file`, `image`.

Signal weights are combined additively by `apply_matches()`; a single well-corroborating
signal (e.g. a unique domain match at weight 0.9) can already push confidence above the
default reporting threshold.

## Ambiguous signals

A signal may be marked `ambiguous: true` when the word or pattern that fires it is too common
to establish the product alone (e.g. the word "Copilot" without any Microsoft context).
Ambiguous signals add an `ai-name-hint` tag and a fractional weight but do not set `frameworks`
or `model_providers`. A corroborating non-ambiguous signal on the same finding converts the
ambiguous match into a full attribution.

## Extension

Add a YAML file to a custom signatures directory and list that directory under `signatures:` in
the config. Override an existing signature by using the same `id:` as the built-in one and
setting `allow_override: true` in the YAML header.

::: shadowscan.signatures
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
