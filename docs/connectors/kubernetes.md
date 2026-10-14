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

Workload analysis includes Deployments, StatefulSets, DaemonSets, Jobs and Pods.
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
