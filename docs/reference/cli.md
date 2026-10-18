# Command reference

Every `shadowscan` command and its options. The
[README](https://github.com/aisecnomad/Nexus-ShadowScan/blob/main/README.md#command-reference)
lists them in one table; `shadowscan <command> --help` prints the options of
the installed version, which is authoritative where this page and it differ.

## Core scanning commands

### `shadowscan code [PATHS...]`

Scan repositories for AI agent evidence.

Scans local directories, remote GitHub organizations, and GitLab groups for agent frameworks,
MCP configurations, coding-agent settings, IaC provisioning, and hard-coded credentials.

```bash
shadowscan code .                                          # scan current directory
shadowscan code ./repo1 ./repo2                            # scan multiple paths
shadowscan code . --diff-base origin/main                  # PR-scoped diff (Git 2.45+)
shadowscan code --github-org acme                          # scan all repos in a GitHub org
shadowscan code --github-repo acme/api --mode clone        # scan specific remote repo
shadowscan code . --inventory ./inventory --fail-on high   # with inventory reconciliation
```

| Option | Description |
|---|---|
| `PATHS` | Local directories or files to scan |
| `--diff-base REF` | Git ref to diff against (PR scope, Git 2.45+) |
| `--github-org ORG` | Scan every repository in a GitHub organization (uses `GITHUB_TOKEN`) |
| `--github-repo OWNER/NAME` | Scan specific remote repositories (repeatable) |
| `--gitlab-group GROUP` | Scan every project in a GitLab group (uses `GITLAB_TOKEN`) |
| `--mode clone\|api` | Remote fetch mode for GitHub/GitLab |
| `--exclude PATTERN` | Extra directory names or globs to skip (repeatable) |
| `--no-default-excludes` | Also scan default-excluded dirs (`node_modules`, `.git`, `vendor`, etc.) |
| `--no-secrets` | Skip credential detection |
| `--strict-coverage` | Strict accounting: every coverage gap is an error and marks the scan incomplete, none is discounted as test code or declared (see [strict accounting](../scanning.md#coverage-budget-and-strict-accounting)) |
| `--include-tests` | Let test/fixture code establish agents at full weight |
| `--profile ci` | Declare unread links, non-regular entries, unparsed content, analysis limits and, with credential detection off, oversize files under test, fixture, documentation, example and generated paths (below the file's project root) as counted omissions instead of gaps; every other gap is judged by the coverage budget as usual, and agent configuration and credential limits are never declared (conflicts with `--strict-coverage` and `--max-coverage-gap 0`) |
| `--triage` | Fast subset scan (manifests, MCP/agent configs, flows, IaC only) |

### `shadowscan scan -c CONFIG`

Run a multi-connector scan from config.

Orchestrates all connectors defined in a YAML configuration file.

```bash
shadowscan scan -c shadowscan.yaml                          # run all connectors
shadowscan scan -c shadowscan.yaml --only identity.entra    # run one connector
shadowscan scan -c shadowscan.yaml --format sarif -o out.sarif
```

| Option | Description |
|---|---|
| `-c, --config FILE` | **(required)** Path to `shadowscan.yaml` configuration file |
| `--only NAME` | Run only these connector names or labels (repeatable) |

### `shadowscan run CONNECTOR`

Run a single connector ad-hoc.

Runs one connector with inline configuration, or re-analyzes an offline export.

```bash
shadowscan run identity.entra --set tenant_id=... --set client_id=...
shadowscan run cloud.aws --set regions=us-east-1,eu-west-1 --dump-records ./exports
shadowscan run saas.slack --input slack-export.json          # offline re-analysis
```

| Option | Description |
|---|---|
| `CONNECTOR` | Connector name (e.g. `identity.entra`, `cloud.aws`) |
| `--input FILE` | Offline export file instead of live API |
| `-S, --set KEY=VAL` | Connector configuration key-value pairs (repeatable; lists as `a,b,c`) |

### `shadowscan endpoint`

Scan workstation AI clients.

Scans well-known AI client configuration locations on the local workstation: Claude Desktop, Claude Code, Cursor, Windsurf, VS Code extensions, Ollama, and more.

```bash
shadowscan endpoint                                # scan current user's profile
shadowscan endpoint --home /Users/dana             # scan a specific profile
shadowscan endpoint --list                         # list known locations and exit
```

| Option | Description |
|---|---|
| `--home DIR` | Profile directory (default: current user's home) |
| `--label TEXT` | Resource prefix (default: `endpoint:<hostname>`) |
| `--list` | Print known client locations and exit |

### `shadowscan gateway LOGS...`

Analyze LLM gateway / provider logs.

Reconstructs AI callers from gateway, provider, or proxy log files.

```bash
shadowscan gateway access.log                                # auto-detect format
shadowscan gateway litellm-spend.jsonl --log-format litellm  # explicit format
shadowscan gateway logs/ --min-events 5                      # directory, filter noise
```

| Option | Description |
|---|---|
| `LOGS` | Log files or directories (variadic) |
| `--log-format FORMAT` | `auto` (default), `litellm`, `portkey`, `kong`, `cloudflare`, `helicone`, `langfuse`, `bedrock`, `azure-openai`, `vertex`, `openai-usage`, `anthropic-usage`, `access-log`, `generic` |
| `--min-events N` | Ignore callers with fewer than N requests (default: 1) |
| `--all-hosts` | Keep traffic to every host (default: LLM/agent hosts only) |
| `--internal-model-host HOST` | Exact internal model-server hostname (repeatable) |
| `--label TEXT` | Gateway name for findings' account/provider field |

### `shadowscan jwt [TOKENS...]`

Classify JWTs.

Classifies JWTs as human, service, or delegated-agent identities and assesses their privileges.

```bash
shadowscan jwt --file tokens.txt                                    # from file
echo "$TOKEN" | shadowscan jwt                                      # from stdin
shadowscan jwt --file t.txt --jwks-url https://.../.well-known/jwks.json  # verify signatures
```

| Option | Description |
|---|---|
| `TOKENS` | JWT strings (positional, also reads from stdin) |
| `-F, --file FILE` | File with one JWT per line or JSON list |
| `--jwks-url URL` | Verify signatures against trusted JWKS endpoint |
| `--expected-issuer ISS` | Require this exact issuer (requires `--jwks-url`) |
| `--jwt-algorithm ALG` | Allowed algorithms: `RS256`, `ES256`, `EdDSA`, `PS256` (repeatable) |

## Fleet & operations commands

### `shadowscan merge REPORTS...`

Combine multiple reports.

Merges JSON reports from several machines or scans into one fleet report.

```bash
shadowscan merge team-a.json team-b.json -o fleet.json
shadowscan merge reports/*.json --format html -o fleet.html
```

### `shadowscan dashboard REPORTS...`

Generate fleet dashboard.

Writes a static fleet dashboard (HTML) and optionally a `shadowscan.inventory/v1` JSON document.

```bash
shadowscan dashboard fleet.json -o dashboard.html
shadowscan dashboard fleet.json -o dash.html --inventory-json inv.json --baseline prev.json
shadowscan dashboard fleet.json -o dash.html --history ./weekly-reports/
```

| Option | Description |
|---|---|
| `-o, --output FILE` | **(required)** Dashboard HTML output |
| `--inventory-json FILE` | Also write `shadowscan.inventory/v1` JSON |
| `--baseline FILE` | Show drift against earlier report |
| `--history DIR` | Show trends from JSON reports in this directory |
| `--as-of TIME` | ISO 8601 timestamp to measure staleness against |

### `shadowscan diff BASELINE CURRENT`

Compare reports for drift.

Compares two JSON reports: new, resolved and changed findings, adverse drift.

```bash
shadowscan diff last-week.json this-week.json --json
shadowscan diff baseline.json current.json --fail-on-new --fail-on-drift inventory,capability
shadowscan diff old.json new.json --baseline-sha256 abc123... --max-baseline-age-days 30
```

| Option | Description |
|---|---|
| `BASELINE` | Earlier JSON report |
| `CURRENT` | Current JSON report |
| `--json` | Output as JSON |
| `--fail-on-new` | Exit 2 if new findings or risk level rose |
| `--fail-on-drift CLASSES` | Comma-separated: `inventory`, `capability`, `autonomy`, `governance`, `coverage` |
| `--baseline-sha256 HEX` | Refuse baseline unless SHA-256 matches |
| `--max-baseline-age-days N` | Mark comparison incomplete if baseline too old |
| `--shadow-only` | Display only unmatched shadow findings |

### `shadowscan controls REPORTS...`

Map findings to governance controls.

Lists findings per NIST AI RMF / ISO/IEC 42001 / EU AI Act / AIUC-1 control (evidence references, not compliance determinations).

```bash
shadowscan controls report.json --format markdown -o controls.md
shadowscan controls report.json --framework eu-ai-act-2024
```

| Option | Description |
|---|---|
| `-f, --format` | `markdown` (default), `csv`, `json` |
| `-o, --output FILE` | Output file |
| `--framework NAME` | Filter by control catalog prefix or framework (repeatable) |

## Inventory & registry commands

### `shadowscan inventory check PATHS...`

Validate inventory files.

```bash
shadowscan inventory check ./inventory/
shadowscan inventory check agent-card.yaml agents.csv
```

### `shadowscan inventory stubs REPORT`

Generate Agent Card skeletons.

Generates Agent Capability Card stubs from shadow findings to bootstrap your inventory.

```bash
shadowscan inventory stubs report.json -o ./inventory/
shadowscan inventory stubs report.json -o ./cards/ --min-risk high --kinds agent,mcp-server
```

| Option | Description |
|---|---|
| `-o, --out DIR` | **(required)** Directory to write one card YAML per shadow agent |
| `--kinds KINDS` | Finding kinds to register (default: `agent,mcp-server,workflow,bot-app,agent-config`) |
| `--min-risk LEVEL` | Minimum risk level: `critical`, `high`, `medium`, `low`, `info` (default: `low`) |

### `shadowscan mcp-registry snapshot`

Snapshot an MCP registry.

Lists every server version of an MCP registry into a pinned snapshot for `options.mcp_registries`.

```bash
shadowscan mcp-registry snapshot -o mcp-snapshot.json
shadowscan mcp-registry snapshot --url https://registry.example.com -o snap.json
```

| Option | Description |
|---|---|
| `--url URL` | Registry base URL (HTTPS only; default: `https://registry.modelcontextprotocol.io`) |
| `-o, --output FILE` | **(required)** Snapshot file to write (mode 0600) |
| `--max-pages N` | Maximum pages to fetch |
| `--ca-bundle FILE` | PEM CA bundle for private PKI |
| `--allow-private-origin` | Permit non-public IP addresses |

## Inspection commands

### `shadowscan signatures`

Inspect detection signature packs.

```bash
shadowscan signatures list                              # list all loaded signatures
shadowscan signatures list --category framework --json  # filter by category, JSON output
shadowscan signatures show protocol.mcp                 # print one signature as YAML
shadowscan signatures test fastmcp                      # test what a package name maps to
shadowscan signatures test api.openai.com --kind domain # test a specific match kind
```

**`signatures list`** options: `--category` (e.g. `framework`, `protocol`, `provider`, `coding-agent`, `platform`, `identity-app`, `policy`, `cloud-service`, `heuristic`, `observability`, `memory`, `sandbox`), `--json`, `-s/--signatures DIR`

**`signatures test`** options: `--kind` (`auto`, `dependency`, `domain`, `user-agent`, `model`, `name`, `env`, `scope`, `image`, `iac`, `file`, `text`, `secret`), `--ecosystem` (e.g. `pypi`, `npm`, `go`, `cargo`, `maven`, `nuget`)

### `shadowscan connectors`

List available connectors.

```bash
shadowscan connectors                        # human-readable table
shadowscan connectors --surface cloud        # filter by surface
shadowscan connectors --json                 # JSON with config keys and offline formats
```

| Option | Description |
|---|---|
| `--surface NAME` | Filter: `code`, `identity`, `gateway`, `lowcode`, `saas`, `cloud`, `endpoint`, `network`, `runtime` |
| `--json` | Print JSON output with configuration keys and supported offline formats |

## Shared options

These options are available on all scanning commands (`code`, `scan`, `run`, `endpoint`, `gateway`, `jwt`).
The global `-v`/`-vv` (info/debug) and `-q` (errors only) flags go before the command, as in `shadowscan -v code .`:

| Option | Description |
|---|---|
| `-f, --format FORMAT` | Output format (see [Output formats](#output-formats)) |
| `-o, --output FILE` | Write report to file |
| `-i, --inventory PATH` | Agent Capability Cards directory/file, `agents.yaml`, or CSV (repeatable) |
| `-s, --signatures DIR` | Extra signature pack directory (repeatable) |
| `--fail-on LEVEL` | Exit 2 if any finding reaches `critical`\|`high`\|`medium`\|`low`\|`info` |
| `--min-confidence FLOAT` | Drop findings below this confidence (0.0-1.0, default: 0.0) |
| `--max-rows N` | Limit table rows displayed |
| `--dump-records DIR` | Write sanitized connector records for offline re-analysis |
| `--incremental` / `--no-incremental` | Enable/disable content-addressed result caching |
| `--state-dir DIR` | Private incremental state directory |
| `--connector-timeout-seconds N` | Per-connector deadline in seconds (default: 120, raised up to 1800 for a large input when not set; a value you set is kept) |
| `--job-deadline-seconds N` | CLI process deadline; exits 3 on expiry |
| `--max-coverage-gap RATIO` | Share of examined entries that may be left unread before the scan is incomplete (default: 0.02); `0` is strict accounting, which fails on any gap (see [strict accounting](../scanning.md#coverage-budget-and-strict-accounting)), and a gap the scanner cannot bound (an early stop, a refused page) always fails closed |
| `--allow-private-origin` / `--deny-private-origin` | Permit non-public IP addresses |
| `--allow-instance-credentials` / `--deny-instance-credentials` | Permit cloud instance-metadata credentials |
| `--allow-credential-mixing` / `--deny-credential-mixing` | Permit repo + live tenant in one scan |
| `--allow-plugin NAME` | Allow a reviewed third-party connector (repeatable) |
| `--allow-signature-override` / `--deny-signature-override` | Permit custom signatures to replace built-in IDs |
| `--plugin-execution thread\|process` | Third-party connector execution backend |

## Output formats

| Format | Flag | Description |
|---|---|---|
| **Table** | `--format table` | Rich terminal table (default); writes JSON when `-o` is used |
| **JSON** | `--format json` | Full ShadowScan finding schema with evidence and metadata |
| **SARIF** | `--format sarif` | Static Analysis Results Interchange Format for GitHub Code Scanning |
| **CSV** | `--format csv` | Spreadsheet-compatible with formula injection protection |
| **Markdown** | `--format markdown` | Markdown table for documentation or reports |
| **HTML** | `--format html` | Standalone HTML report |
| **CycloneDX** | `--format cyclonedx` | CycloneDX 1.6 AI-BOM (Software Bill of Materials) |
| **OCSF** | `--format ocsf` | OCSF 1.1.0 Detection Finding for SIEM integration |

## Exit codes

| Exit | Meaning |
|---|---|
| **0** | Scan completed and passed |
| **1** | No scan result: invalid option, value, path or configuration, or a setup or output error |
| **2** | Scan completed but reached `--fail-on`; `diff` returns 2 with `--fail-on-new` or `--fail-on-drift` |
| **3** | Scan incomplete (API error, timeout, denied access, limit, malformed export); `diff` returns 3 when reports are not comparable |

Gate CI on any non-zero exit: exit 1 means nothing was scanned, and an
incomplete scan never reads as clean. On exit 3 the CLI names the reason
categories on stderr (`scan incomplete (exit 3): oversize-file 2`) and the
report counts them in `summary.incomplete_reasons`; `shadowscan code --profile ci`
declares the gaps a source gate accepts (fixtures, cassettes, documentation) in
advance and counts them in `summary.declared_omissions`. Exit 0 from a complete
static scan does not prove that no agent runs; see
[scan semantics](../scanning.md).
