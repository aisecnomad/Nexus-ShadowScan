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

The analyzers identify known inference and agent images, GPU requests, exposed
Services/Ingresses/Routes, privileged and host-network workloads, hostPath
volumes, provider-related environment variable names, cluster-admin bindings,
and AI workload namespaces without an egress NetworkPolicy. These are
heuristics, not proof that a workload executed or is reachable from the public
internet.

Known images are matched by vendor image markers and by serving-engine names as
delimited image tokens (`vllm`, `ollama`, `sglang`, `llama.cpp`,
`text-generation-inference`, `tritonserver`), so a private-registry rebuild such
as `registry.example/ml/vllm-serving` is recognised; a substring inside another
word is not. A GPU counts whether `nvidia.com/gpu` is set in `requests` or only
in `limits`. A `--model org/name` or `--model-id org/name` container argument
corroborates an AI image or AI resource kind: together they add the
`self-hosted-model-serving` tag and model-argument and GPU evidence. On their
own, a model argument and a GPU never make a workload an agent, because
training and computer-vision jobs take the same arguments; such a GPU workload
stays a cloud resource with unchanged confidence. Only the argument's presence
is recorded, never its value. A `command` or `args` field that is not a list of
strings is skipped with a warning that marks the scan incomplete.

`cloud.kubernetes` and `cloud.openshift` use no credentials and accept no
credential option: `allow_instance_credentials` is rejected on their entries.
The offline analyzers make no credential or tenant requests. Live Kubernetes
collection is not implemented.
