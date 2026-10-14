# Kubernetes and OpenShift

`cloud.kubernetes` and `cloud.openshift` analyze offline JSON, JSONL, or YAML
exports. The current implementation does not connect to a Kubernetes API or
load a kubeconfig; collect an inventory separately with read-only `kubectl get
... -o json` commands and provide the resulting file as `input`.

Every connector entry requires a stable `cluster` label. Resource identities
use `k8s:<cluster>/<namespace>/<kind>/<name>`. Export Kubernetes `List`
envelopes or individual objects. Never include Secret values; this analyzer
does not need them.

kubectl writes each object's `kind`. A raw API list (`kubectl get --raw
/api/v1/pods`, or a client library's list call) is a typed `List` such as
`PodList` whose items carry no `kind`; each such item takes the kind its
envelope names (`PodList` items are Pods), and an item's own `kind` is never
replaced. An object with no `kind` outside a typed `List` (in an untyped
`List`, a JSON array or JSONL), or with a `kind` that is not a non-empty
string, cannot be analyzed: it is skipped with a warning that marks the scan
incomplete (exit 3). Provider environment values are not retained: only
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

Known images are matched by vendor image markers and by serving-engine names
(`vllm`, `ollama`, `sglang`, `llama.cpp`, `text-generation-inference`) that
start the image name, its last path component without tag or digest, so a
private-registry rebuild such as `registry.example/ml/vllm-serving` is
recognised. An engine name elsewhere in the path (`registry.example/vllm/server`,
`serving-vllm`), inside another word, or followed by an auxiliary role
(`ollama-exporter`, `vllm-operator`, `-metrics`, `-monitor`) is not. NVIDIA
Triton (`tritonserver`) also serves vision and tabular models, so it counts
only with an LLM backend in its name or tag (`24.05-trtllm-python-py3`,
`24.05-vllm-python-py3`). A GPU counts whether `nvidia.com/gpu` is set in `requests` or only
in `limits`. A `--model org/name` or `--model-id org/name` container argument
corroborates an AI image or AI resource kind: together they add the
`self-hosted-model-serving` tag and model-argument and GPU evidence. On their
own, a model argument and a GPU never make a workload an agent, because
training and computer-vision jobs take the same arguments; such a GPU workload
stays a cloud resource with unchanged confidence. Only the argument's presence
is recorded, never its value. A `command` or `args` field that is absent or
`null` is unset; one that is not a list of strings is skipped with a warning
that marks the scan incomplete.

`cloud.kubernetes` and `cloud.openshift` use no credentials and accept no
credential option: `allow_instance_credentials` is rejected on their entries.
The offline analyzers make no credential or tenant requests. Live Kubernetes
collection is not implemented.
