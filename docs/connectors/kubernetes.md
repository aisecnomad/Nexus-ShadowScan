# Kubernetes and OpenShift

`cloud.kubernetes` and `cloud.openshift` analyze offline JSON, JSONL, or YAML
exports. The current implementation does not connect to a Kubernetes API or
load a kubeconfig; collect an inventory separately with read-only `kubectl get
... -o json` commands and provide the resulting file as `input`.

Every connector entry requires a stable `cluster` label. Resource identities
use `k8s:<cluster>/<namespace>/<kind>/<name>`. Export Kubernetes `List`
envelopes or individual objects. Never include Secret values; this analyzer
does not need them. Provider environment values are not retained: only
configuration-presence tags are emitted. Secret references are not dereferenced.

Resource identities retain complete object names, including names longer than
160 characters. Names exceeding 253 characters leave coverage incomplete.
The 10,000-object analysis limit counts objects across the export; exhausting
an export exactly at the limit is complete, while any unread objects make it
incomplete. Empty trailing `List` envelopes do not count as unread objects.

Collect every page of a chunked API list (`?limit=` or a client library's
`limit`). A `List` whose `metadata.continue` is non-empty or whose
`metadata.remainingItemCount` is above zero is a partial page: its objects are
analyzed, but coverage is incomplete (exit 3). This applies to a single `List`
and to `List` envelopes in a JSON array or JSONL. Malformed values of either
field are also incomplete.

Namespaces are kept in full in resource identities. A `metadata.namespace`
that is not an RFC 1123 DNS label (lowercase letters, digits and inner hyphens,
at most 63 characters) is rejected with incomplete coverage instead of being
shortened, replaced by `default` or allowed to contain `/`, which could make two
objects share one identity. Objects without a namespace key keep the `default`
namespace.

Workload analysis includes Deployments, StatefulSets, DaemonSets, Jobs, Pods
and, for OpenShift, DeploymentConfigs.
CronJobs use `spec.jobTemplate.spec.template.spec` for image and posture
analysis. Missing or malformed nested templates leave coverage incomplete.

The analyzers identify known inference and agent images, GPU requests, exposed
Services/Ingresses/Routes, privileged and host-network workloads, hostPath
volumes, provider-related environment variable names, cluster-admin bindings,
and AI workload namespaces without an egress NetworkPolicy. These are
heuristics, not proof that a workload executed or is reachable from the public
internet.

`cloud.kubernetes` and `cloud.openshift` use no credentials and accept no
credential option: `allow_instance_credentials` is rejected on their entries.
The offline analyzers make no credential or tenant requests. Live Kubernetes
collection is not implemented.
