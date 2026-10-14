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

Self-hosted serving stacks (including vLLM, TGI, Triton, llama.cpp, LocalAI,
LMDeploy, SGLang, OpenLLM and Ray Serve) are corroborated with a Hugging
Face-style `--model <org>/<name>` or `--model-id` argument and GPU resources.
An image name, model argument, GPU request/limit, or serving environment
variable is not sufficient by itself to establish likely model serving. The
connector inspects argument and environment names only; it never retains their
values.

`cloud.kubernetes` and `cloud.openshift` use no credentials and accept no
credential option: `allow_instance_credentials` is rejected on their entries.
The offline analyzers make no credential or tenant requests. Live Kubernetes
collection is not implemented.
