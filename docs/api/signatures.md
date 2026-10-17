# Signatures

The signature system is how ShadowScan recognises AI frameworks, model providers, protocols,
platforms and products without hard-coding product knowledge in connectors. Connectors ask the
`SignatureIndex` what an observation means; its `match_*` methods return `Match` objects that
carry the signature, the signal that fired, the matched value and a weight.

## Signature packs

The built-in packs are YAML files under `shadowscan/signatures/data/`:

| Directory | Signatures |
|-----------|------------|
| `frameworks/` | Agent frameworks (`framework.*`: LangChain, LlamaIndex, AutoGen, Spring AI, …) |
| `providers/` | Model providers and inference APIs (`provider.*`: OpenAI, Anthropic, AWS Bedrock, Ollama, …) |
| `protocols/` | Agent protocols (`protocol.*`: MCP, A2A, ACP, OpenAI function calling, ChatGPT plugins) |
| `platforms/` | Agent platforms, AI gateways and low-code tools (`platform.*`: Dify, n8n, LiteLLM, Copilot Studio, …) and managed cloud AI services (`cloud.*`: Bedrock Agents, Vertex Agent Engine, Azure AI Foundry Agents, …) |
| `identity/` | AI SaaS apps seen as OAuth grants and bots (`identity-app.*`) and the permission policies the risk engine scores (`policy.*`) |
| `coding_agents/` | Coding agents (`coding-agent.*`: Claude Code, GitHub Copilot, Cursor, …) |
| `heuristics/` | Vendor-neutral idioms such as tool registration, agent loops and autonomy flags (`heuristic.*`), and file-corpus signatures |
| `observability/` | The OpenTelemetry GenAI conventions, observability tools, memory layers, sandboxes and tool providers (`observability.*`, `memory.*`, `sandbox.*`, `tool.*`) |

A pack file holds one signature, a list of signatures, or a mapping whose only key is
`signatures`. Each signature has an `id`, a `category` and at least one signal; the schema rejects
unknown fields (including `severity`, which the risk engine derives), duplicate YAML keys and
duplicate ids in a file.

## Signal types

A signal has one of 14 types: `dependency`, `import`, `code`, `file`, `env`, `domain`,
`user_agent`, `image`, `iac`, `name`, `scope`, `model`, `secret`, `client_id`. Its `weight` is
greater than 0 and at most 1 (0.5 when omitted).

`apply_matches()` in [`shadowscan.connectors.common`](common.md) attaches matches to a finding
as evidence, frameworks, model providers, tags and capabilities. `Finding.recompute_confidence()`
then combines the evidence weights by noisy-OR, counting each correlated group once; see
[Weights and confidence](../signatures.md#weights-and-confidence).

## Ambiguous signals

Only `code` and `name` signals accept `ambiguous: true`. The code connector counts an ambiguous
`code` match only when the same signature also has an import, a dependency or a non-ambiguous
code match in the same project.

An ambiguous `name` marks a product name that also names unrelated things: Gemini, in
`identity-app.google-gemini`, is also a cryptocurrency exchange. `apply_matches()` keeps such a
match as a hint. It adds the `ai-name-hint` tag, caps the evidence weight at 0.2 in one shared
confidence group, and lists the signature under `metadata.potential_frameworks` or
`metadata.potential_providers`. It adds none of the signature's tags and sets no framework,
provider, capability or agent indicator. A non-name match for the same signature establishes
the product on its own; an ambiguous name matched after that keeps its full weight but adds no
second agent indicator.

## Custom packs

Extra pack directories come from the config's top-level `signatures:` list and from
`--signatures`/`-s` (repeatable), which the CLI adds after the config's. They load after the
built-in packs, in that order. Symbolic links are not followed, and a custom directory without
any `.yaml` or `.yml` pack is an error. A later custom pack can replace an id from an earlier
one, but a repeated id within one directory is an error. A built-in id is reserved: a custom
signature that reuses one is refused unless `options.allow_signature_override: true` or
`--allow-signature-override` is set, and then it replaces the whole built-in signature.

```yaml
signatures:
  - ./custom-signatures/
options:
  allow_signature_override: true   # only to replace a built-in signature id
```

Validate a pack with `python -m shadowscan.signatures.validate DIR`; see
[Adding or overriding](../signatures.md#adding-or-overriding).

::: shadowscan.signatures
    options:
      show_root_heading: true
      members_order: source
      show_source: false
      docstring_style: google
