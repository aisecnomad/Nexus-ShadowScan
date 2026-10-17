# Endpoint and runtime inventories

Endpoint connectors inventory AI tools on workstations and hosts. Two kinds
are available:

- `endpoint.inventory` reads a fixed list of documented user-scope locations
  in home directories (or osquery extension exports) and reports the clients
  and coding agents a person has configured, their MCP servers, AI editor and
  browser extensions, local model stores and, when enabled, AI command-line
  tools named in shell history. It finds tools that never touch a repository,
  an identity provider or a gateway, such as a Claude Desktop MCP server or an
  Ollama model pulled onto a laptop.
- `endpoint.host`, `endpoint.mcp`, `endpoint.ollama`, `endpoint.models` and
  `endpoint.ebpf` consume bounded offline exports from host, MDM, MCP, model
  and eBPF collectors (see [offline inventories](#offline-host-mcp-model-and-ebpf-inventories)).
  `endpoint.mcp` can also fetch the A2A Agent Cards of agents the operator
  lists (see [A2A Agent Card probe](#a2a-agent-card-probe)); it probes
  nothing else.

Running processes are reported by [`runtime.processes`](runtime.md); the
engine links them to `endpoint.inventory` findings for the same tool and
device, through the tool's signature or tool id, or, for an MCP
configuration, the running server's package.

The `shadowscan endpoint` command (see
[developer endpoints](../scanning.md#developer-endpoints)) reads every
configuration file location listed below, plus further instruction files,
through the `code.filesystem` connector. Its findings are code-surface
findings with other identities than this connector's, so the two are not
deduplicated when merged. Use `endpoint.inventory` for the device inventory
and its lifecycle links (installed clients, extensions, local models, running
processes), and `shadowscan endpoint` to review the content of the
configuration and instruction files: MCP server definitions, coding-agent
posture, credentials and hidden or fetched instructions. The command does not
walk the client directories this connector records by existence (`~/.copilot`,
`~/.kiro`, the OpenClaw workspace), only the configuration files in them.

## `endpoint.inventory`

The connector reads a fixed list of documented user-scope locations below
each home directory, on Linux, macOS and Windows (`AppData`) layouts. It does
not walk the home directory, so unrelated personal files are never opened.

| Category | Locations | Finding |
|---|---|---|
| Client and agent configuration | Claude Desktop, Claude Code (`~/.claude.json`, `~/.claude/settings*.json`, `agents/`, `skills/`, `commands/`), Cursor, VS Code `mcp.json`, Windsurf, Gemini CLI, Codex `config.toml` and `AGENTS.md`, Kiro, Amazon Q, LM Studio, Continue, Goose, Cline and Roo Code global storage, Aider, OpenClaw, Copilot CLI | `agent-config` for a product with a coding-agent signature, else `ai-app`; plus an `mcp-server` finding per client listing its servers |
| Editor extensions | VS Code, VS Code Insiders, VS Code Server, VSCodium, Cursor and Windsurf extension directories | `agent-config` for an agentic extension (Cline, Roo Code, Copilot Chat, Claude Code, Codex, Amazon Q…), else `ai-app` |
| Browser extensions | Chrome, Chromium, Edge and Brave profiles; Firefox `extensions.json` | `ai-app`, only when the extension name matches an AI product |
| Local models | Ollama manifests, LM Studio, the Hugging Face hub cache, GPT4All, Jan | `local-model` listing up to 50 model names |
| Shell history (opt-in) | bash, zsh, fish and PowerShell history | evidence on the tool's configuration finding, or an `ai-app` finding when the tool has none |

MCP server findings carry the same static server risks as the code
connector (`mcp-unpinned-package`, `mcp-broad-filesystem`,
`mcp-shell-command`, plaintext transport, auto-approved tools), and agent
configuration findings carry the same posture checks
(`posture-permissions-bypassed`, `posture-unrestricted-shell`,
`posture-unsandboxed`, `posture-exposed-gateway`,
`posture-unauthenticated-gateway`). See [risk](../concepts/risk.md). Claude
Code, Codex and Goose settings that make a person approve actions are recorded
as `metadata.approval_gate`, as in the
[code connector](code.md#coding-agent-settings-posture-and-approval), and feed the
[autonomy tiers](../concepts/autonomy.md). Editor extensions, browser
extensions and commands from shell history count as person-started
(`initiation: human`); a configured client does not, because it can also run
unattended.

With [`options.mcp_registries`](../getting-started/configuration.md#mcp-registry-snapshots),
each client's MCP servers are matched against pinned MCP Registry snapshots by
package and remote URL, as for the code connector: see
[MCP registry provenance](code.md#mcp-registry-provenance). The matching runs
in the engine, so `--dump-records` exports and replays are unchanged.

Options:

- `path`: the home directory to inventory. The default is the home directory
  of the account running the scan.
- `paths`: a list of home directories, for example every directory under
  `/home` on a shared build host. Set `path` or `paths`, not both.
- `label`: the device name used in resource ids, titles and the finding's
  `account`. The default is the host name.
- `shell_history`: `true` to read shell history. Only the AI tool name and a
  run count are kept; command lines, arguments and timestamps are not. The
  default is `false`.
- `max_entries`: the number of directory entries examined per home directory
  (default 50,000). Reaching it makes the scan incomplete.
- `input`: offline records exported with `--dump-records`, or osquery
  results.

### Offline fleet inventory with osquery

`input` accepts the JSON output of these osquery queries, as an array of rows
or as osquery logger lines that carry `columns` and `hostIdentifier`:

```sql
SELECT u.username, e.* FROM users u CROSS JOIN vscode_extensions e USING (uid);
SELECT u.username, e.* FROM users u CROSS JOIN chrome_extensions e USING (uid);
SELECT u.username, a.* FROM users u CROSS JOIN firefox_addons a USING (uid);
```

Rows for extensions that are not AI products are ignored. The device comes
from `hostIdentifier` (or `label`), and the home from `username`, then the
user directory in the extension path, then `uid-<uid>`. Records exported with `--dump-records` replay unchanged, so a
collection on each laptop can be analysed centrally.

### Safety and completeness

- Every file and directory is opened without following a symbolic link in
  any path component. A link (a linked file, or a linked directory on the way
  to a location), an unreadable location, an oversized file or an exhausted
  entry budget is a coverage gap: a warning names the location and the scan
  is incomplete. A location that does not exist is not a gap. The one
  exception is the lock links a running Chromium browser (Chrome, Chromium,
  Edge, Brave) keeps in its user-data directory (`SingletonLock`,
  `SingletonCookie`, `SingletonSocket`, `RunningChromeVersion`): they hold no
  profile or extension, so they are skipped without a gap, and never
  followed.
- Shell history is read from its end, up to 8 MiB per file. A longer history
  is a gap, because tools used only in the older part are not counted.
- File contents never enter a record. MCP server entries are the sanitized
  projection the code connector uses (environment variable and header names,
  never values), browser extensions are kept only when their name matches an
  AI product, and posture and approval records hold enumerated setting values,
  never a token.
- Malformed configuration (invalid JSON, YAML or TOML) still produces the
  configuration finding, records a warning and makes the scan incomplete,
  because its MCP servers or its posture could not be read. Comments and
  trailing commas are accepted in JSON files; OpenClaw's other JSON5 forms
  (unquoted keys, single-quoted strings) are not, so such a file is a gap.
- A malformed offline record is ignored with a warning, and the scan is
  incomplete. So are malformed MCP server, posture, approval or model entries
  inside an otherwise valid record: they are dropped, and the rest of the
  record is kept. A dropped approval entry never gates an action. A replayed
  approval entry is kept only when this scanner could have written it for that
  record: exactly the keys `client`, `setting`, `value`, `scope` and `file`;
  a Claude Code, Codex or Goose client equal to the record's `client`; a `file`
  equal to the record's `location` and naming a settings file of that client;
  and a setting, value and scope the settings reader produces (for example
  `every-action` only for `permissions.defaultMode` `default` or `plan`, Codex
  `untrusted` or Goose `approve`). Anything else is dropped as malformed. An
  export can still describe settings a home directory does not have: replay
  exports only from hosts and storage you trust.

Findings are owned by the home directory name and scoped to the device, so
`owner` and `account` identify whose workstation a finding came from. An
endpoint inventory shows that a tool is installed or configured, not that it
ran; shell history is evidence of use on that account only.

## Offline host, MCP, model and eBPF inventories

The `endpoint.host`, `endpoint.mcp`, `endpoint.ollama`, `endpoint.models`,
`endpoint.ebpf` and `gateway.otel` connectors consume bounded offline JSON,
JSONL, or YAML exports. They do not discover local configuration files or
traverse model directories (`endpoint.inventory` above reads its fixed list of
local locations), and they probe no network service, with one opt-in
exception: `endpoint.mcp` fetches the A2A Agent Cards listed in
`agent_card_urls` ([below](#a2a-agent-card-probe)). MCP servers are never
contacted. Supply only synthetic or appropriately sanitized exports.

These offline inventories are not correlated with other surfaces. In
particular, MCP tool fingerprints are not compared with a rug-pull baseline.

| Connector | Offline input |
|---|---|
| `endpoint.host` | Host/MDM inventory records with a runtime or configuration name; a row is reported only when its name or path matches an AI product signature, its whole `name`, `path` file name or `process` is a known AI product or local model runtime ([below](#host-inventory-rows)), or its `type`/`category` names an AI category (`ai`, `agent`, `assistant`, `copilot`, `llm`, `mcp`, `model`) — filtered rows add one informational note, not a coverage gap |
| `endpoint.mcp` | Server records containing MCP tool-list responses, and A2A card records exported with `--dump-records` |
| `endpoint.ollama` | Ollama-compatible model inventory, including an `endpoint` and `models` list |
| `endpoint.models` | Artifact metadata records; do not serialize model contents |
| `endpoint.ebpf` | Native Tetragon, Falco, Tracee or Hubble event records, or flat records ([below](#ebpf-event-formats)) |
| `gateway.otel` | OTLP span records with GenAI semantic-convention attributes |

### Host inventory rows

osquery `apps` and `programs` rows and most MDM software lists carry an
application or executable name and no category, so `endpoint.host` also
reports a row whose name is, as a whole, a known AI product. The `name`,
the file name of `path` and the `process` are each compared without an
`.app` or `.exe` suffix or a trailing version, ignoring case, spaces and
punctuation: `LM Studio.app`, `/usr/local/bin/ollama`, `Jan.exe` and
`Ollama version 0.5.7` qualify. The known products are the product names of the
bundled provider and coding-agent signatures (Ollama, LM Studio, vLLM,
llama.cpp, LocalAI, SGLang, Aider, Goose, Continue, ...) and the local model
runtimes and AI command-line tools the endpoint inventory catalog lists
(GPT4All, Jan, Msty, `llama-server`, `lms`, `opencode`, ...). A name that
only contains one of them is not enough, and platform names such as Make are
left out, so ordinary software stays filtered.

### eBPF event formats

`endpoint.ebpf` reads each producer's native export shape and correlates the
destination, port and process it carries with known AI hosts and local model
ports:

| Producer | Export | Fields read |
|---|---|---|
| Tetragon | `tetra getevents -o json` events (`process_exec`, `process_kprobe`, …) | `process.binary`, `process.pod.namespace`/`name`, and the first `sock_arg` (`daddr`, `dport`) or `sockaddr_arg` (`addr`, `port`) kprobe argument; snake_case and lowerCamelCase keys are both read |
| Falco | JSON alerts (`json_output: true`) | `output_fields`: `proc.name`, `fd.sip.name`/`fd.rip.name`/`fd.sip`/`fd.rip`, `fd.sport`/`fd.rport`, `k8s.ns.name`, `k8s.pod.name` |
| Tracee | JSON events | `processName`, `kubernetes.podName`/`podNamespace`, and the first sockaddr map in `args` (`sin_addr`/`sin6_addr`, `sin_port`/`sin6_port`) |
| Hubble | `hubble observe -o json` flows, wrapped under `flow` or bare | `destination_names` (preferred) or `IP.destination`, the `l4` TCP/UDP `destination_port`, and the client workload from `source.namespace`/`pod_name` |
| Flat | Records exported by other collectors | `process_name`/`binary` or a `process` object, `destination`/`remote_addr`/`hostname`/`server.address`/`url`, `port`/`destination_port`, `namespace`, `pod`/`pod_name` |

Kernel-level events usually carry numeric destination addresses, so Tetragon
and Tracee connects contribute local model ports and process names; AI host
matching needs a name-bearing source such as Falco's `fd.sip.name`, Hubble's
`destination_names`, or a flat export. A record that matches none of these
shapes is not analyzed: the connector records one warning and marks the scan
incomplete rather than letting an unread export look clean. A recognized
event is scored on what can be read, and the scan is incomplete when any of
it cannot: a field above of the wrong type (a `process`, `pod`,
`kubernetes`, `IP`, `l4`, `source` or socket map that is not a map, `args`
or `destination_names` that is not a list, an argument that is not a map, a
name that is not text, a port that is neither a number nor text), or an
`args` or `destination_names` list longer than 100 entries, whose entries
past the hundredth are not read. Each producer records one warning for
malformed fields and one for the list limit, naming the producer and no
value from the export. See
`examples/ebpf/` for a Tetragon TracingPolicy and Falco rules that emit the
fields above.

MCP tool definitions are analyzed for risky capability names, prompt-injection
or exfiltration indicators, missing declared authentication, and duplicate tool
names across servers. The `tool-poisoning` tag keeps its description rules: an
`<IMPORTANT>` tag, "ignore previous instructions" wording, sending or forwarding
data, secrets, credentials or prompts, an invisible or bidirectional control
character (zero-width and directional marks, embeddings, overrides and isolates,
the word joiner and invisible operators U+2060-U+2064, a byte-order mark or Unicode
tag characters), a URL, a "use/call/invoke the ..." tool reference, or a model
provider host name, anywhere in the first 64 KiB, the window the instruction
audit reads. Descriptions are
also screened with the code surface's bounded instruction-content rules —
content concealed in raw HTML comments, fetch-and-execute or decode-and-execute
phrasing — and for terminal control sequences that can conceal or overwrite
what an operator reads; each hit raises `tool-poisoning` with zero-weight
explanatory evidence, and content-rule hits add their own tags
(`hidden-instructions`, `remote-code-fetch`, `invisible-text`). These rules also
match documentation links, quoted examples and prohibitions, so the tag
describes a review candidate, not verified intent or execution. A tool name
duplicating another installed server's tool carries the `tool-name-shadowing`
tag, which maps to threat references and a default risk weight of 10.

A bounded static sentence audit adds explanation on top of those rules. It
reports direct instruction-override and sensitive-value disclosure candidates
by rule identifier and line number in `metadata.static_instruction_audit`,
with zero-weight evidence and explicit limitations, and retains no description
excerpts. Quoted text, fenced code and explicit prohibitions are excluded from
this narrow English audit. A description is not a `SKILL.md`: a leading `---`
line is ordinary text, not YAML front matter, so the lines after it are
audited. An audit indicator also raises the
`tool-poisoning` tag; an audit that finds nothing never removes it.
Descriptions exceeding 64 KiB and unclosed fences mark coverage incomplete. A line over 4,096 characters is audited sentence by
sentence; only a single sentence over 4,096 characters is audited in its first
and last 4,096 characters and marks the audit `partial`, not the scan
incomplete. Tool definitions are fingerprinted
for downstream comparison, but baseline/rug-pull detection is not yet implemented. No tool is
invoked. With `options.mcp_registries`, a tool finding whose server is an
HTTP(S) URL is matched against the pinned MCP Registry snapshots by that URL
(`metadata.mcp_registry.matches`); a bare server name identifies nothing and
is counted as `unidentified`, so an approved registry never vouches for it.

OTLP analysis selects only service, agent, provider, model, and operation
attributes; prompt and completion content is not copied into findings.
`endpoint.models` consumes metadata supplied by an offline collector. It does
not parse GGUF/safetensors headers or hash files. Unsafe pickle-based extensions
are tagged and are never unpickled.

eBPF event correlation is heuristic and offline-only. ShadowScan does not load
eBPF programs; example operator policies are under `examples/ebpf/`.

## A2A Agent Card probe

An [A2A Agent Card](https://github.com/a2aproject/A2A/blob/main/docs/specification.md)
is the JSON document an Agent2Agent server publishes to describe itself: its
name, the interfaces (URL and protocol binding) peers call, its skills, the
security schemes it accepts and, optionally, JWS signatures over the card. It
is not ShadowScan's [Capability Card](../inventory.md#agent-capability-cards-one-yaml-per-agent)
(`agent-card.yaml`), which an operator writes to sanction findings; a
discovered A2A card never registers or approves anything, signed or not.

`endpoint.mcp` fetches cards only from the URLs you list. Card files in a
repository or on a workstation are read by [`code.filesystem`](code.md) and
`shadowscan endpoint` instead; both produce the same `metadata.agent_card`.

```yaml
connectors:
  - name: endpoint.mcp
    agent_card_urls:
      - https://planner.agents.example.com          # origin: well-known path
      - https://agents.example.com/cards/travel.json # exact card URL
    agent_card_jwks_url: https://keys.agents.example.com/jwks.json  # optional
```

Options:

- `agent_card_urls`: the HTTPS card URLs or agent origins to fetch. An origin
  (no path, or `/`) is fetched at `/.well-known/agent-card.json`; only an
  HTTP 404 there tries the older `/.well-known/agent.json`. Any other URL is
  fetched as written, query included. Each entry must be HTTPS without
  embedded credentials, and the list is checked when the connector is built:
  an invalid entry stops the connector (exit 3).
- `max_agent_cards`: the most entries `agent_card_urls` may hold (default
  100). A longer list is refused, never truncated.
- `agent_card_jwks_url`: an optional operator-trusted HTTPS JWKS endpoint.
  Signatures are verified against these keys only.
- `ca_bundle`: an optional PEM file trusted instead of the default CA store
  for the card and JWKS endpoints (a private CA). TLS verification stays on.
- `input`: replays records exported with `--dump-records`; without
  `agent_card_urls` or `input` the connector has nothing to read. A replay
  never probes, so a job that sets both `input` and `agent_card_urls` is
  refused when the connector is built (exit 3) instead of leaving the listed
  agents unchecked. `agent_card_jwks_url` may accompany `input`.

Fetch rules:

- URLs declared inside a card (interfaces, provider, documentation, icons,
  a signature header's `jku` or `x5u`) are never fetched, and no A2A method is
  called.
- Redirects must stay on the card URL's origin. Loopback, private,
  link-local and cloud-metadata addresses are refused unless `endpoint.mcp`
  sets `allow_private_origin` (or the scan sets `options.allow_private_origin`),
  and always under `--deny-private-origin`. Proxies are not used.
- A card is read up to 1 MiB, as strict JSON: duplicate keys and non-finite
  numbers are refused.
- Every failure is an error and the scan is incomplete (exit 3): an
  unreachable agent, an HTTP error, a redirect off the origin, an oversized or
  malformed body, a body that is not a JSON object, or a document that is not
  an Agent Card. One failing agent does not stop the others.

Findings: one per card, kind `agent` with framework `protocol.a2a` and
capability `multi-agent`, `resource` the card URL without query or fragment,
`resource_type` `a2a-agent-card` and `provider` `a2a`. A card that names its
agent and declares an endpoint, skills or capabilities but misses required
fields is reported as an `incomplete-agent-card` framework-usage finding with
`metadata.card_errors`, and the scan is incomplete. `metadata.agent_card`
holds the name, description, version, protocol version, skills, capabilities,
security scheme names, up to 20 interfaces (scheme, host, port and path only;
an interface URL with user information or a backslash before its host, which
HTTP clients can read as another host, is left out) and the signature state.
Both A2A 1.0 (`supportedInterfaces`) and 0.3 (`url`, `preferredTransport`,
`additionalInterfaces`) cards are read. A card that
declares any other `protocolVersion` (not 0.x or 1.x), at the top level or on
an interface, is still reported, with a warning that makes the scan
incomplete: its fields were read as 0.3 and 1.0 fields and tags can be missed.

Tags (see [risk](../concepts/risk.md)):

- `no-auth-declared` (10): the card declares no security scheme.
- `a2a-plaintext-interface` (10): an interface uses `http://` or `ws://` to a
  host not known to be loopback, including one left out of the projection
  because its host cannot be told. The URL is read as WHATWG URL parsers read
  it: tab, CR and LF are removed, leading control characters stripped, and
  `http:/host`, `http:\\host` or `http:///host` reaches `host`.
- `a2a-card-signature-invalid` (10): a signature is malformed or fails
  verification.

### Card signatures

`metadata.agent_card.signature` is one of:

| State | Meaning |
| --- | --- |
| `absent` | The card has no `signatures`. |
| `present-unverified` | The card is signed, but no operator key set checked it: `agent_card_jwks_url` is not set, the key set could not be read (an error; the scan is incomplete), or a replayed export redacted part of the card. |
| `verified` | At least one signature verifies with a key from `agent_card_jwks_url`. |
| `invalid` | A signature entry is malformed, or none verifies with the operator's keys. `signature_detail` gives the reason. |

A signature is an RFC 7515 JWS whose payload is the RFC 8785 (JCS) canonical
card without its `signatures` member. The A2A specification also removes
default values before canonicalizing, and signers differ on which: each
signature is checked against three payloads, and one match is enough:

1. the card as served;
2. the card with every null, empty string, array and object removed, at any
   depth (what the A2A Python SDK signs);
3. the card with empty members removed except those the A2A 1.0 schema marks
   REQUIRED or `optional`, such as an empty `description` (the specification's
   section 8.4.1 example).

The three differ only by nulls and empty values, so a card served with or
without them verifies, and any other change does not. A verified card is then
projected and tagged as the form its signature covers, not as served: an empty
value added after signing, such as `"securitySchemes": {"oauth2": {}}`, shows
no security scheme and leaves `no-auth-declared` in place. A signer that also
drops `false` or `0` defaults matches none of them, and such a card served with
those values reports `invalid`.

The protected header selects the algorithm (RS256, PS256, ES256 or EdDSA) and
the key ID; exactly one key of the operator's set must match. Keys or key
locations named by the card or its header (`jku`, `jwk`, `x5u`, `x5c`) are
never fetched or trusted, and critical header extensions and unencoded
payloads are refused. A card holding a number with no exact canonical form
(an integer beyond 2^53) is `invalid`. `verified` says the card was signed by
a key you trust and, apart from empty values, not changed since; it does not
check key expiry or revocation beyond the contents of your key set, and it is
not a review of what the agent does.

Records exported with `--dump-records` carry the card and are re-validated on
replay; a signature state in an export is never read. The export is sanitized
like every other, and the userinfo of a scheme-less `user:password@host:port`
address (a gRPC interface) is also withheld. Replaying with
`agent_card_jwks_url` verifies again, unless the export's redaction changed
the card (`present-unverified`).

See the [main connector reference](../connectors.md) for shared options and offline safety limits.
