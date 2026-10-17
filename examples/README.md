# Examples

Configuration you can copy, and the inputs the offline demo, the tests and the
tenant canaries read. Every file here is safe to publish: account IDs, hosts
and names are placeholders (`123456789012`, `acme.okta.com`) and no file holds
a credential. Replace image digests, revisions, scopes and identifiers with
reviewed values before you use a file outside this repository.

| Path | What it is | Guide |
|---|---|---|
| [`shadowscan.offline.yaml`](shadowscan.offline.yaml) | The offline demo: runs the fixture-backed connectors against `tests/fixtures/` with no credentials (`make demo`) | [Quick start](../docs/getting-started/quickstart.md) |
| [`shadowscan.self-scan.yaml`](shadowscan.self-scan.yaml) | Scans this checkout with its own scanner and finishes with a complete report: each path that would otherwise leave the scan incomplete is named with its reason (`make self-scan`) | [Quick start](../docs/getting-started/quickstart.md) |
| [`github-action-code-scan.yml`](github-action-code-scan.yml) | Consumer workflow: scans a checkout and uploads SARIF to code scanning | [CI integration](../docs/operations/ci.md) |
| [`github-action-drift.yml`](github-action-drift.yml) | Consumer workflow: weekly scan compared with a reviewed baseline | [Scheduled drift detection](../docs/operations/drift.md) |
| [`k8s-drift-cronjob.yaml`](k8s-drift-cronjob.yaml) | Kubernetes CronJob for the same weekly drift check | [Scheduled drift detection](../docs/operations/drift.md) |
| [`k8s-job.yaml`](k8s-job.yaml) | Disposable, egress-denied Kubernetes Job for an offline scan | [Operational controls](../docs/operations/operational-controls.md) |
| [`k8s-network-policy.yaml`](k8s-network-policy.yaml) | Baseline egress NetworkPolicies for ShadowScan pods | [Operational controls](../docs/operations/operational-controls.md) |
| [`inventory/`](inventory/) | Sanctioned-inventory formats: the `agents:` mapping (`agents.yaml`) and the bare list (`sanctioned.yaml`). The Agent Capability Card format is [`agent-card.yaml`](../agent-card.yaml) at the repository root | [Inventory](../docs/inventory.md) |
| [`canaries/`](canaries/) | Tenant canary definitions for `cloud.aws` and `saas.slack`: replay (with recorded `*-records.jsonl`), live and permission-denied expectations | [Tenant canaries](../docs/canaries.md) |
| [`ebpf/`](ebpf/) | Example operator policies (Falco rules, a Tetragon TracingPolicy) for collecting process and connection events that ShadowScan correlates offline; ShadowScan never loads eBPF programs itself | [Endpoint and runtime](../docs/connectors/endpoint.md) |

The consumer workflows and Kubernetes manifests are copied verbatim into other
repositories and clusters, so `make policy` holds them to the repository's own
rules: actions pinned by full commit SHA (Dependabot moves them with
`.github/workflows/`), images pinned by digest, and containers that run as
non-root with a read-only root filesystem.
