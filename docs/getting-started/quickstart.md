# Quick start

## 1. Scan a local checkout

No credentials needed — scan a repository or directory:

```bash
shadowscan code .
```

Scanning the ShadowScan checkout itself this way reports an incomplete scan
(exit 3): a few redaction test files are built to exceed the sanitizer's own
safety limits, and a finding the sanitizer cannot bound is withheld rather than
published unredacted — that is unbounded, so no budget applies to it. Its
handful of unreadable entries, by contrast, stay within the coverage budget.
The scanner fails closed rather than skip them silently.
Scan one of your own projects, or start with the offline demo below. In a
ShadowScan checkout, `make self-scan` scans it with
`examples/shadowscan.self-scan.yaml`, which excludes those paths, each with a
documented reason, and completes with exit 0.
`shadowscan code tests/fixtures/sample_repo --inventory agent-card.yaml`
scans the bundled sample repository and completes in seconds.

To mark which agents are sanctioned, add `--inventory <path>` with an existing
card file or directory (for example the bundled `agent-card.yaml`); the path must
exist. See [inventory](../inventory.md).

## 2. Try the offline demo

Every connector also accepts offline exports. The bundled fixtures demonstrate
all surfaces without live credentials:

```bash
shadowscan scan -c examples/shadowscan.offline.yaml --format html -o report.html
```

Open `report.html` to explore findings with evidence drill-down.

The bundled `agent-card.yaml` and `examples/` directory come from a repository
checkout; the PyPI wheel does not ship them (see [installation](install.md)).

## 3. Scan with live connectors

Repository scans and live tenant collection run as separate scans: the scanner
rejects a configuration that mixes a live code connector with credentialed
tenant connectors unless `options.allow_credential_mixing` is set for reviewed
inputs (see [production deployment](../production.md#explicit-security-policy)).
Create one configuration per boundary:

```yaml
# shadowscan-code.yaml: repository scan
inventory: [./inventory]
connectors:
  - name: code.github
    org: acme
    token: ${GITHUB_TOKEN}
```

```yaml
# shadowscan-tenants.yaml: live tenant collection
inventory: [./inventory]
connectors:
  - name: identity.entra
    tenant_id: ${AZURE_TENANT_ID}
    client_id: ${AZURE_CLIENT_ID}
    client_secret: ${AZURE_CLIENT_SECRET}
  - name: saas.slack
    token: ${SLACK_TOKEN}
```

Then run each:

```bash
shadowscan scan -c shadowscan-code.yaml --format sarif -o shadowscan-code.sarif
shadowscan scan -c shadowscan-tenants.yaml --format json -o shadowscan-tenants.json
```

Add `--fail-on high` only once a validated threshold exists for your
environment; see [production deployment](../production.md#rollout-acceptance).

## 4. Analyze a single connector

```bash
shadowscan run identity.entra --set tenant_id=$AZURE_TENANT_ID
shadowscan run cloud.aws --set regions=us-east-1,eu-west-1 --dump-records ./exports
# Read exports/manifest.json and use the exported filename for this instance:
shadowscan run cloud.aws --input ./exports/0001-cloud_aws.jsonl   # re-analyse later, offline
```

## 5. Analyze tokens and logs

```bash
shadowscan gateway litellm-spend.jsonl bedrock-invocations/ egress-proxy.log
# Pass tokens on stdin (or with --file): a command-line argument is visible to
# other local users through the process list and is kept in shell history.
printf '%s\n' "$TOKEN" | shadowscan jwt --jwks-url https://acme.okta.com/oauth2/default/v1/keys
```

## 6. Scan developer workstations and combine them

`shadowscan endpoint` reads only the well-known AI client locations under a
profile (MCP client configuration, coding-agent settings, user-level skills,
rules and instruction files), never the whole home directory:

```bash
shadowscan endpoint --list                                     # which known locations exist here
shadowscan endpoint --format json -o laptop-$(hostname).json   # one report per machine
shadowscan merge laptop-*.json --format json -o fleet.json     # one fleet report; incomplete (3) if any source is
shadowscan dashboard fleet.json -o dashboard.html --inventory-json inventory.json
```

The dashboard is a static, self-contained page that shows coverage per source
before any count; see [fleet dashboard](../operations/dashboard.md).

## 7. Register, compare and report

```bash
shadowscan inventory stubs report.json -o inventory/pending/
shadowscan diff last-week.json today.json                 # informational: exit 0 unless the comparison is incomplete (3)
shadowscan diff last-week.json today.json --fail-on-new   # exit 2 on new findings or a higher risk level
shadowscan diff last-week.json today.json --fail-on-drift inventory,capability,autonomy,governance   # exit 2 on adverse drift
shadowscan controls today.json --format csv -o controls.csv   # findings per NIST AI RMF, ISO/IEC 42001, EU AI Act and AIUC-1 control
shadowscan scan -c shadowscan-code.yaml --format cyclonedx -o ai-bom.json   # CycloneDX 1.6 AI bill of materials
```

`controls` reports evidence references, not compliance determinations; see
[control evidence report](../operations/controls.md) and
[AI-BOM](../operations/ai-bom.md).

`diff` can complete for local repository scans, offline exports and complete
live `cloud.aws`, `cloud.azure`, `cloud.gcp` and `identity.entra` scans whose
provider confirmed the scanned account, tenant, projects or subscriptions (see
[live collection scope](../scanning.md#live-collection-scope)). Any other live
API connector or a third-party connector always gives 3, and `gateway.logs`
does unless both scans were keyed with the same identity key (see
[scan state](../scanning.md)).

## Read a finding

One finding from a JSON report (`--format json`), abridged:

```json
{
  "id": "ss-3f9c1e2a7b4d8c10",
  "surface": "cloud", "connector": "cloud.aws", "kind": "agent",
  "title": "Bedrock AgentCore runtime: strands_support_agent",
  "resource": "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/rt1",
  "account": "123456789012", "region": "us-east-1", "owner": null,
  "frameworks": ["cloud.aws-bedrock-agents"], "model_providers": ["provider.openai"],
  "capabilities": ["tool-use"], "tags": ["plaintext-credential", "secret-in-env"],
  "confidence": 1.0, "likelihood": "strong",
  "shadow": true, "registry_match": null,
  "risk": {"score": 90, "level": "critical", "factors": [
      {"id": "shadow", "description": "not present in the sanctioned agent inventory", "weight": 25},
      {"id": "tag:plaintext-credential", "description": "plaintext credential in environment/configuration", "weight": 25},
      {"id": "no-owner", "description": "no identifiable owner", "weight": 10}, "..."]},
  "evidence": [
      {"signal": "aws:agentcore-runtime", "description": "AgentCore runtime 'strands_support_agent' (READY) role arn:aws:iam::…", "weight": 0.97},
      {"signal": "secret:provider.openai", "description": "Plaintext OpenAI API key in environment variable OPENAI_API_KEY: credential:hmac-sha256:…", "weight": 0.6}],
  "metadata": {"status": "READY", "protocol": "HTTP", "network": "PUBLIC", "related": ["ss-…"],
      "threats": ["maestro-2025:L3", "mitre-atlas-2026.09:AML.T0055", "owasp-asi-2026:ASI03", "owasp-llm-2026:LLM02"],
      "controls": ["aiuc-1-2026q2:B", "aiuc-1-2026q2:E", "eu-ai-act-2024:Art.15", "..."]}
}
```

* **confidence** combines grouped evidence weights with noisy-OR. It is a heuristic evidence score, not a calibrated probability or proof that an agent executed.
* **risk** is additive and explainable: the listed factors always add up to `score`. **danger_score** is the same model without the governance factors (registration and ownership); `options.risk_basis: danger` bases `level` and `--fail-on` on it.
* **shadow** is `true` unless exactly one inventory entry matches an explicit resource pattern and its scope restrictions; a name match only suggests an entry for review.
* **autonomy** (`metadata.autonomy`) places the finding on the L0 Chatbot to L5 Fully Autonomous scale as an interval: the `floor` the evidence proves and the `ceiling` it has not ruled out.
* **related** links findings across surfaces only through an exact shared identifier; name similarity goes to `related_candidates` as a review hint.
* **threats** and **controls** are edition-qualified references to OWASP, MITRE ATLAS, MAESTRO, NIST AI RMF, ISO/IEC 42001, EU AI Act and AIUC-1 entries: author mappings, not compliance determinations.

For the full finding schema, risk model, and output format details, see
[risk scoring](../concepts/risk.md), [autonomy tiers](../concepts/autonomy.md),
[mappings](../concepts/mappings.md) and the
[output formats](../reference/cli.md#output-formats).

CSV output inserts a literal `'` at the start of a value, and after each `,`, `;`, tab, `|` or line break inside it, when the following text begins with `=`, `+`, `-` or `@` (also after whitespace or quotes), a tab or a carriage return; values beginning with a line feed are also marked. Strip markers for programmatic use or use `json`; see [output and inventory migration](../history/production-change-history.md#output-and-inventory-migration).

## Use the Python API

The CLI uses the same Python API. The JSON report (`--format json`) is
the stable contract; treat the Python objects as unstable between releases
until 1.0 and pin a reviewed commit.

```python
from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.engine import Engine

cfg = ScanConfig(
    connectors=[ConnectorSpec("code.filesystem", {"paths": ["./my-repo"]})],
    inventory=["./inventory"],
)
result = Engine(cfg).run()

if not result.complete:
    raise SystemExit(3)  # fail closed: an incomplete scan is never a clean one

for finding in result.findings:
    print(f"[{finding.risk.level.value}] {finding.title}  shadow={finding.shadow}")
```

`ScanConfig.from_yaml("shadowscan.yaml")` reads the same YAML file as `shadowscan scan -c`.
See the full [API reference](../api/index.md) for
engine, models, config, risk, autonomy, correlation, comparison, registry, signatures, reporters, and the HTTP client.

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Completed scan, passed `--fail-on` threshold |
| `1`  | No scan result: invalid option, value, path or configuration, or a setup or output error |
| `2`  | Completed scan, findings reached `--fail-on` level |
| `3`  | Incomplete scan (API failures, timeouts, permission denials) |

Treat any non-zero exit as a failure in CI. Do not test only for 2 and 3: exit 1
means nothing was scanned.

## Next steps

- [Configuration reference](configuration.md) for all options
- [Connector reference](../connectors.md) for credentials and scopes
- [Production deployment](../production.md) for CI and container usage
