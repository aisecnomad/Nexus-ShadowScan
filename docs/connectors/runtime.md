# Runtime connector

The runtime connector reports AI tools seen **running**: coding-agent CLIs,
AI desktop apps, MCP servers launched by a client, local model servers and
agent frameworks' development servers. A configured tool might never run; a
running process shows that it does. The engine links these findings to the
`endpoint.inventory` findings for the same tool on the same device.

## `runtime.processes`

| Matched | Examples |
|---|---|
| Coding-agent CLIs | `claude`, `codex`, `gemini`, `aider`, `goose`, `openclaw`, `opencode`, `cursor-agent`, and the same tools run as npm packages (`node …/@anthropic-ai/claude-code/cli.js`) or Python modules (`python -m aider`) |
| AI desktop apps | Claude Desktop, ChatGPT desktop and Ollama.app, matched by executable name *and* the vendor's app bundle or package path; Cursor, Windsurf and LM Studio, matched by executable name alone, so another program with the same name is reported as that app |
| MCP servers | packages launched through `npx`, `uvx`, `uv tool run`, `pipx run`, `bunx` or `node` whose names follow MCP conventions (`@modelcontextprotocol/server-*`, `mcp-server-*`, `*-mcp`), and `github-mcp-server` |
| Model servers | `ollama serve` / `run`, `llama-server`, `lms`, `python -m vllm.entrypoints…` |
| Frameworks and gateways | `crewai`, `langgraph` dev servers, Open WebUI, the LiteLLM proxy |

One `runtime-process` finding is reported per host, user and tool, with the
process count, up to ten process ids, the executable names and, for an MCP
server, its package name.

**Command lines never enter a finding.** They can carry credentials
(`--api-key …`), so only the matched tool, the executable's base name and an
MCP package name are kept.

### Input

- **Offline** (`input`): osquery `processes` results, as an array of rows or
  as logger lines with `columns` and `hostIdentifier`; Microsoft Defender
  `DeviceProcessEvents` (`DeviceName`, `AccountName`, `FileName`,
  `FolderPath`, `ProcessCommandLine`); CrowdStrike process events
  (`ComputerName`, `UserName`, `ImageFileName`, `CommandLine`); or any JSON or
  CSV with a command line or an executable. osquery's `processes` table has a
  `uid`, not a user name: join `users` to report names, as in
  `SELECT u.username, p.* FROM processes p LEFT JOIN users u USING (uid);`.
- **Live** (no `input`, Linux only): reads `/proc/<pid>/cmdline` without
  following the `exe` link. Processes of other users are visible only to an
  account allowed to read them; unreadable processes are reported and make the
  scan incomplete. Some views do not list other processes at all, and then
  the scan is marked incomplete with a warning that says why: a `/proc` that
  belongs to a container's own PID namespace (detected from the namespace's
  inode, not from `NSpid`, which shows one entry inside a container as on the
  host); `hidepid=invisible` or `noaccess`, unless the scanning account is in
  the mount's `gid=` group (group 0 by default, so root sees everything); and
  `hidepid=ptraceable`, which hides processes the account may not trace even
  from root. `subset=pid` hides no process. Elsewhere, export osquery results
  instead.

Options: `label` (host name for records that carry none; default the host
name), `max_processes` (live mode bound, default 100,000; reaching it makes
the scan incomplete) and `input`. A record with neither a command line nor an
executable nor a valid inspection record makes the scan incomplete.

### Optional Linux inspection

`inspect_maps: true` reads mapped-library names and `inspect_fds: true` reads
descriptor link metadata. Both default to false. This never opens descriptor
targets, reads process memory, executes code, or loads model weights. Recognized
library labels are `ggml`, `llama`, `torch`, `onnxruntime`, `tokenizers`, and
`vllm`; recognized descriptor extensions are `gguf`, `safetensors`, and `onnx`.
Only those labels are retained, not filesystem paths. An `_MEI` directory is
recorded as a packaging hint, not as evidence of an agent or a mount.

Environment inspection is separately opt-in through `inspect_env_keys`, a list
drawn from `OLLAMA_HOST`, `OLLAMA_MODELS`, `VLLM_WORKER_MULTIPROC_METHOD`,
`VLLM_ATTENTION_BACKEND`, `HF_HOME`, `CUDA_VISIBLE_DEVICES`, and `TGI_HOSTNAME`.
Only the selected **key names** are retained. Values are discarded, and raw
records remain excluded from `--dump-records`. Packaging and environment names
alone produce no finding.

```yaml
connectors:
  - name: runtime.processes
    label: build-host.example.invalid
    inspect_maps: true
    inspect_fds: true
    inspect_env_keys: [OLLAMA_MODELS]
```

An unrecognized process with a model descriptor is a `local-model` inventory
finding; one with mapped ML libraries is a `framework-usage` inventory finding.
Neither establishes agency, unauthorized use, model validity, or evasion.
Known tool findings retain their existing confidence; inspection adds metadata
without another scoring signal. Mappings cannot reliably discover arbitrary
Python imports or memory-only agents. Snapshots cannot establish activity
outside their observation time.

Process namespace and start ticks are checked before and after inspection;
changed or exited processes are omitted with a race warning. These identities
lack a boot ID, so they must not be used for joins across host restarts.
Permission denial, malformed input and exhausted budgets mark coverage
incomplete. No root privileges are requested; restricted non-root visibility
is reported through the existing incomplete-scan mechanism.
If only inspection identity or its budget is unavailable, independent readable
command-line detections are retained without inspection attribution. Actual
process exit or changed namespace/start identity omits that process observation.

| Limit | Default |
|---|---:|
| `max_inspection_bytes` per process | 262,144 bytes |
| `max_inspection_total_bytes` per scan | 16,777,216 bytes |
| `max_inspection_entries` per scan (mappings, FDs, environment entries) | 100,000 |
| `max_mappings` per process | 4,096 |
| `max_fds` per process | 1,024 |
| `inspection_timeout_seconds` per live collection | 30 seconds |

The connector also checks the engine deadline between reads and entries. Limits
are positive integers. Reaching a read cap is conservatively incomplete even
when a file ends exactly at the cap. Reads are bounded and do not block on FIFOs.

Sanitized offline inventories can provide an `inspection` object with the same
fixed labels, explicit `status` for `maps`, `fds` and `environ`, and process
`identity` (`pid_namespace`, `start_time_ticks`, both decimal strings). A valid
PID is required. Statuses are `ok`, `not_requested`, `denied`, `unreadable` or
`truncated`; indicators require `ok` for their respective source. Optional
`observed_at` is an ISO timestamp. Offline replay does no live inspection and
needs no inspection options. See the synthetic
[inspection fixture](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/tests/fixtures/runtime/inspection.jsonl).

### Lifecycle corroboration

After all connectors finish, the engine links `endpoint.inventory` findings
(`configured` agent and MCP configurations, `installed` apps, extensions and
model stores) to `running` process findings for the same tool on the same
device. The same tool means the same signature or, for a client configuration,
the same tool id, so Claude Desktop, Kiro and LM Studio, which have no
signature, link too. Code findings and the offline `endpoint.*` inventories
are not linked. Devices match by the complete trimmed, case-insensitive device
value: `dev-laptop-07.corp.example` does not match `dev-laptop-07` or a host in
another DNS domain. Use the same canonical device identifier or full hostname
in both exports; do not strip domains when combining different estates. An MCP configuration links
to a running MCP server only when one of its server's arguments names the
same package.

Linked findings carry `metadata.lifecycle` (`states`, `subjects`, `related`,
and on the endpoint side `same_user`), and the configured or installed side
gains the tag `observed-running` with zero-weight evidence. Corroboration
changes neither confidence nor risk. A process seen at export time says
nothing about other times: absence from a process list does not show that a
tool is unused.

See the [main connector reference](../connectors.md) for shared options and offline safety limits.
