"""Offline Kubernetes and OpenShift workload inventory analysis."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Callable, Iterable, Iterator
from typing import Any, ClassVar

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError
from shadowscan.connectors.common import apply_matches, finalize
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.utils.redaction import sanitize_text

_AI_IMAGE_MARKERS = (
    "ollama/ollama",
    "vllm/vllm-openai",
    "ggerganov/llama.cpp",
    "text-generation-inference",
    "localai",
    "lmstudio",
    "litellm",
    "langgraph",
    "flowise",
    "dify",
    "open-webui",
    "mcp/",
    "mcp-server",
    "kagent",
)
_AI_RESOURCE_NAME = re.compile(r"(?:llm|model|agent|mcp|inference|ollama|vllm)", re.IGNORECASE)
# Serving-engine names that start an image's name (its last path component,
# without tag or digest), for private-registry rebuilds
# (registry.example/team/vllm-serving) that the vendor image markers miss. An
# engine name followed by an auxiliary role (ollama-exporter, vllm-operator)
# is a sidecar or controller, not a model server.
_AI_IMAGE_NAME = re.compile(
    r"(?:llama(?:\.cpp|-cpp|cpp)|ollama|sglang|text-generation-inference|vllm)"
    r"(?:$|[._-](?!(?:exporter|operator|metrics|monitor(?:ing)?)(?:$|[._-])))",
    re.IGNORECASE,
)
# NVIDIA Triton serves any model type (vision, tabular, ensembles), so its image
# counts only with an LLM backend in its name or tag (24.05-trtllm-python-py3,
# 24.05-vllm-python-py3).
_TRITON_IMAGE_NAME = re.compile(r"tritonserver(?:$|[._-])", re.IGNORECASE)
_TRITON_LLM_BACKEND = re.compile(r"(?:^|[.:_-])(?:trtllm|tensorrt-llm|vllm)(?:$|[.:_-])", re.IGNORECASE)
# A Hugging Face-style ``--model org/name`` (or ``--model-id``) argument. Only
# its presence is recorded, never the value.
_MODEL_ARGUMENT = re.compile(r"(?:^|\s)--model(?:-id)?(?:=|\s+)[\"']?[\w.-]+/[\w.-]+", re.IGNORECASE)
_ENV_MARKERS = ("API_KEY", "TOKEN", "BASE_URL", "ENDPOINT", "MODEL")
_RECOGNIZED = {
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "Job",
    "CronJob",
    "Pod",
    "Service",
    "Ingress",
    "ServiceAccount",
    "RoleBinding",
    "ClusterRoleBinding",
    "NetworkPolicy",
    "InferenceService",
    "ServingRuntime",
    "RayService",
    "Agent",
    "ToolServer",
    "ModelConfig",
    "Notebook",
    "LeaderWorkerSet",
}
_OPENSHIFT = {
    "DeploymentConfig",
    "Route",
    "ImageStream",
    "DataScienceCluster",
    "DSCInitialization",
    "DataSciencePipelinesApplication",
    "OdhDashboardConfig",
}
_AI_RESOURCE_KINDS = {
    "InferenceService",
    "ServingRuntime",
    "RayService",
    "Agent",
    "ToolServer",
    "ModelConfig",
    "Notebook",
    "LeaderWorkerSet",
    "DataScienceCluster",
    "DSCInitialization",
    "DataSciencePipelinesApplication",
    "OdhDashboardConfig",
}
_WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "DeploymentConfig"}
_MAX_OBJECTS = 10_000


def _serving_engine_image(image: str) -> bool:
    """Whether an image's name starts with a model-serving engine (see _AI_IMAGE_NAME)."""
    name, _, tag = image.partition("@")[0].rpartition("/")[2].partition(":")
    if _AI_IMAGE_NAME.match(name):
        return True
    return bool(_TRITON_IMAGE_NAME.match(name) and _TRITON_LLM_BACKEND.search(f"{name}:{tag}"))


def _name(obj: dict[str, Any]) -> str:
    metadata = obj.get("metadata")
    if not isinstance(metadata, dict):
        return ""
    value = metadata.get("name")
    return value if isinstance(value, str) else ""


# A namespace is an RFC 1123 DNS label. Without "/" in it, and with the kind
# from a fixed set, a resource identity reads one way even when names contain "/".
_NAMESPACE_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def _namespace(obj: dict[str, Any]) -> str | None:
    """Return the full namespace, or None when it cannot be a distinct identity.

    Namespaces are DNS labels of at most 63 characters. Any other value is
    malformed; shortening, defaulting or accepting it would merge distinct
    objects into one resource identity.
    """
    metadata = obj.get("metadata")
    if not isinstance(metadata, dict):
        return None
    if "namespace" not in metadata:
        return "default"
    value = metadata["namespace"]
    if not isinstance(value, str) or not _NAMESPACE_LABEL.fullmatch(value):
        return None
    return value


def _list_pagination_issue(data: dict[str, Any]) -> str | None:
    """Detect a chunked Kubernetes List page (``metadata.continue``).

    The API server returns ``continue`` and ``remainingItemCount`` on every
    page but the last when a client lists with ``limit``. Such a page is a
    partial collection and must never be reported as complete.
    """
    metadata = data.get("metadata")
    if metadata is None:
        return None
    if not isinstance(metadata, dict):
        return "offline export has invalid pagination metadata"
    token = metadata.get("continue")
    remaining = metadata.get("remainingItemCount")
    if token is not None and not isinstance(token, str):
        return "offline export has invalid pagination metadata"
    if remaining is not None and (type(remaining) is not int or remaining < 0):
        return "offline export has invalid pagination metadata"
    if token or (remaining is not None and remaining > 0):
        return "offline export contains an uncollected next page"
    return None


def _kind(obj: dict[str, Any]) -> str:
    value = obj.get("kind")
    return value[:100] if isinstance(value, str) else ""


# A typed List kind (PodList, DeploymentList), which names the kind of its items.
_TYPED_LIST_KIND = re.compile(r"([A-Z][A-Za-z0-9]{0,99})List")


def _with_list_item_kinds(data: Any) -> Any:
    """Fill a missing item ``kind`` from a typed List envelope.

    The API server strips each item's kind and apiVersion from a typed list
    (``GET /api/v1/pods`` returns a ``PodList`` whose items have none); kubectl
    adds them back. The envelope's kind names the kind of every item, so an
    item without one takes it. An item's own kind is never replaced, and an
    untyped ``List`` names no item kind.
    """
    if not isinstance(data, dict) or not isinstance(data.get("items"), list):
        return data
    envelope_kind = data.get("kind")
    typed = _TYPED_LIST_KIND.fullmatch(envelope_kind) if isinstance(envelope_kind, str) else None
    if typed is None:
        return data
    item_kind = typed.group(1)
    return {
        **data,
        "items": [
            {**item, "kind": item_kind} if isinstance(item, dict) and "kind" not in item else item
            for item in data["items"]
        ],
    }


# A Kubernetes resource quantity: a decimal number with an optional binary or
# decimal SI suffix or exponent (1, "2", "500m", "1Ki", "1e3").
_QUANTITY = re.compile(r"\s*\+?(\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+|[KMGTPE]i|[numkMGTPE])?\s*")


def _positive_quantity(value: Any) -> bool | None:
    """Whether a resource quantity is above zero; None when it is not a quantity.

    An unset (absent or null) quantity is zero. A GPU count of ``0`` or ``"0"``
    requests no GPU, so only a positive count makes a GPU workload.
    """
    if value is None:
        return False
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return value > 0 if math.isfinite(value) and value >= 0 else None
    if isinstance(value, str) and len(value) <= 64 and (match := _QUANTITY.fullmatch(value)):
        return float(match.group(1)) > 0
    return None


# A pod runs regular containers, init containers (a native sidecar is one with
# restartPolicy: Always) and debug ephemeral containers; all three share the container
# shape and can carry a model image, a GPU request or provider configuration.
_CONTAINER_FIELDS = ("containers", "initContainers", "ephemeralContainers")
# The optional container fields: a null one (common in Helm-rendered YAML, `initContainers:`
# with no entries) is absent, not malformed. Every pod has `containers`.
_OPTIONAL_CONTAINER_FIELDS = frozenset({"initContainers", "ephemeralContainers"})


def _malformed_container_fields(pod_spec: dict[str, Any]) -> bool:
    """Whether a container field of a pod spec is present but not a list (a null optional one is absent)."""
    return any(
        field in pod_spec
        and not isinstance(pod_spec[field], list)
        and not (pod_spec[field] is None and field in _OPTIONAL_CONTAINER_FIELDS)
        for field in _CONTAINER_FIELDS
    )


def _pod_containers(pod_spec: dict[str, Any]) -> list[Any]:
    """Every container entry of a pod spec across the three container fields, bounded.

    A field that is not a list (a null optional field, or one ``_malformed_container_fields``
    reports) contributes nothing.
    """
    entries: list[Any] = []
    for field in _CONTAINER_FIELDS:
        value = pod_spec.get(field)
        if isinstance(value, list):
            entries.extend(value)
    return entries[:100]


def _workload_images(spec: dict[str, Any]) -> list[str]:
    template = spec.get("template", spec)
    if not isinstance(template, dict):
        return []
    pod_spec = template.get("spec", template)
    if not isinstance(pod_spec, dict):
        return []
    return [
        image[:300]
        for container in _pod_containers(pod_spec)
        if isinstance(container, dict) and isinstance((image := container.get("image")), str) and image
    ]


def _ai_images(images: list[str]) -> list[str]:
    """The images that run an AI workload: a vendor image marker or a serving-engine name."""
    return [
        image
        for image in images
        if any(marker in image.lower() for marker in _AI_IMAGE_MARKERS) or _serving_engine_image(image)
    ]


def _egress_policy_namespaces(objects: list[dict[str, Any]]) -> set[str]:
    """Namespaces a NetworkPolicy restricts egress in (an Egress policy type or egress rules).

    A policy whose namespace is malformed restricts no namespace.
    """
    egress_policies: set[str] = set()
    for obj in objects:
        if _kind(obj) == "NetworkPolicy":
            spec = obj.get("spec") if isinstance(obj.get("spec"), dict) else {}
            policy_types = spec.get("policyTypes", []) if isinstance(spec, dict) else []
            if isinstance(spec, dict) and (
                (isinstance(policy_types, list) and "Egress" in policy_types) or "egress" in spec
            ):
                policy_namespace = _namespace(obj)
                if policy_namespace is not None:
                    egress_policies.add(policy_namespace)
    return egress_policies


def _exposed_service(obj: dict[str, Any], resource_name: str, spec: dict[str, Any]) -> bool:
    """Whether a LoadBalancer or NodePort Service's name, labels or selector name an AI resource."""
    svc_type = spec.get("type")
    metadata = obj.get("metadata")
    labels = metadata.get("labels", {}) if isinstance(metadata, dict) else {}
    selector = spec.get("selector", {})
    service_context = " ".join(
        [
            resource_name,
            (json.dumps(labels, sort_keys=True, default=str) if isinstance(labels, dict) else ""),
            (json.dumps(selector, sort_keys=True, default=str) if isinstance(selector, dict) else ""),
        ]
    )
    return svc_type in {"LoadBalancer", "NodePort"} and bool(_AI_RESOURCE_NAME.search(service_context))


def _cluster_admin_binding(obj: dict[str, Any]) -> bool:
    """Whether a RoleBinding or ClusterRoleBinding grants cluster-admin to a ServiceAccount."""
    role_ref = obj.get("roleRef")
    subjects = obj.get("subjects", [])
    return bool(
        isinstance(role_ref, dict)
        and role_ref.get("name") == "cluster-admin"
        and isinstance(subjects, list)
        and any(isinstance(subject, dict) and subject.get("kind") == "ServiceAccount" for subject in subjects)
    )


def _exposure_tags(obj: dict[str, Any], kind: str, resource_name: str, spec: dict[str, Any]) -> list[str]:
    """Tags for an AI resource reachable from outside the cluster, or a ServiceAccount made cluster-admin.

    A Service counts by type, name, labels and selector (_exposed_service), an Ingress or
    Route by name, backend and target, and a role binding by what it grants to whom
    (_cluster_admin_binding).
    """
    tags: list[str] = []
    if kind == "Service" and _exposed_service(obj, resource_name, spec):
        tags.append("exposed-llm-server")
    exposure_context = " ".join(
        (
            resource_name,
            str(spec.get("backend", "")),
            str(spec.get("to", "")),
        )
    )
    if kind in {"Ingress", "Route"} and _AI_RESOURCE_NAME.search(exposure_context):
        tags.append("exposed-llm-server")
    if kind in {"RoleBinding", "ClusterRoleBinding"} and _cluster_admin_binding(obj):
        tags.append("cluster-admin")
    return tags


def _add_serving_evidence(finding: Finding, model_argument: bool, serving: bool, gpu_workload: bool) -> None:
    """Add a workload's model-argument and GPU evidence.

    Additive corroboration of an AI image or AI resource kind only: neither
    signal changes the kind or scores a non-AI workload.
    """
    if model_argument:
        finding.add_evidence(
            Evidence(
                signal="kubernetes:model-argument",
                description=(
                    "Container arguments name a Hugging Face-style model identifier"
                    + ("" if serving else " (not AI evidence without an AI image or resource kind)")
                ),
                weight=0.7 if serving else 0.0,
            )
        )
    if serving and gpu_workload:
        finding.add_evidence(
            Evidence(
                signal="kubernetes:gpu-resource",
                description="Model-serving container requests or limits an NVIDIA GPU",
                weight=0.45,
            )
        )


class KubernetesConnector(BaseConnector):
    # No live API: reads a manifest or API dump someone else exported.
    live_collection: ClassVar[bool] = False
    name = "cloud.kubernetes"
    surface = Surface.CLOUD
    provider = "kubernetes"
    description = "Analyze Kubernetes workload and control-plane inventory exports."
    offline_formats = "kubectl get -o json List envelope / JSONL / YAML export"
    config_keys: ClassVar[dict[str, str]] = {
        "cluster": "Required stable cluster label for offline resource identities.",
        "input": "Offline kubectl JSON / JSONL / YAML inventory export.",
    }

    def __init__(self, ctx: ConnectorContext) -> None:
        super().__init__(ctx)
        self.cluster = ctx.get("cluster")

    @staticmethod
    def _offline_pagination_issue(data: dict[str, Any]) -> str | None:
        return BaseConnector._offline_pagination_issue(data) or _list_pagination_issue(data)

    @classmethod
    def _unwrap(cls, data: Any, on_error: Callable[[str], None] | None = None) -> Iterator[dict[str, Any]]:
        # The shared loader unwraps a top-level List, so its kind must reach the items first.
        return super()._unwrap(_with_list_item_kinds(data), on_error)

    def collect(self) -> Iterable[dict[str, Any]]:
        raise ConnectorError(
            "cloud.kubernetes: live API collection is unavailable; provide an offline kubectl export"
        )

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        cluster = self.cluster
        if not isinstance(cluster, str) or not cluster.strip():
            raise ConnectorError("cloud.kubernetes: cluster is required for offline resource identity")
        accepted = self._accept_objects(records)
        egress_policies = _egress_policy_namespaces(accepted)
        for obj in accepted:
            finding = self._analyze_object(obj, cluster, egress_policies)
            if finding is not None:
                yield finding

    def _accept_objects(self, records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
        """Every object of the export, in order, up to the object limit.

        List envelopes give their items; an item that is not an object is skipped with a
        warning. The first object past the limit stops reading the export, with a warning.
        """
        accepted: list[dict[str, Any]] = []
        for record in records:
            items = self._record_items(record)
            if items is None:
                continue
            for item in items:
                # Reaching the cap is complete only if no further object is
                # present, including objects in a subsequent List envelope.
                if len(accepted) >= _MAX_OBJECTS:
                    self.ctx.warn(f"{self.name}: object limit reached")
                    return accepted
                if not isinstance(item, dict):
                    self.ctx.warn(f"{self.name}: malformed object")
                    continue
                accepted.append(item)
        return accepted

    def _record_items(self, record: dict[str, Any]) -> list[Any] | None:
        """The objects a loaded record holds: a List envelope's items, or the record itself.

        None (after a warning) for an envelope whose items are not a list.
        """
        if "items" not in record:
            return [record]
        record = _with_list_item_kinds(record)
        # A List envelope inside a JSON array is not unwrapped by the
        # shared loader, so check its continuation here. Observed
        # items are still analyzed.
        pagination_issue = self._offline_pagination_issue(record)
        if pagination_issue:
            self.ctx.warn(f"{self.name}: {pagination_issue}")
        items = record["items"]
        if not isinstance(items, list):
            self.ctx.warn(f"{self.name}: malformed object list")
            return None
        return items

    def _analyze_object(self, obj: dict[str, Any], cluster: str, egress_policies: set[str]) -> Finding | None:
        """The finding for one accepted object; None when it is skipped or carries no signal."""
        identity = self._object_identity(obj)
        if identity is None:
            return None
        kind, resource_name, namespace = identity
        workload_spec = self._workload_spec(obj, kind)
        if workload_spec is None:
            return None
        selected = _ai_images(_workload_images(workload_spec))
        tags: list[str] = []
        capabilities: list[str] = []
        if selected:
            tags.append("ai-workload")
        pod_spec = self._pod_spec(kind, workload_spec)
        if pod_spec is None:
            return None
        pod_signals = self._inspect_pod(pod_spec, tags)
        if pod_signals is None:
            return None
        model_argument, gpu_workload = pod_signals
        # A model argument corroborates an AI image or AI resource kind. It
        # never makes a workload AI by itself: GPU training and computer
        # vision jobs take ``--model org/name`` too.
        serving = model_argument and bool(selected or kind in _AI_RESOURCE_KINDS)
        if serving:
            tags.append("self-hosted-model-serving")
        if kind in {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod"} and selected:
            if namespace not in egress_policies:
                tags.append("no-egress-policy")
        tags.extend(_exposure_tags(obj, kind, resource_name, workload_spec))
        if kind in {"Agent", "ToolServer"}:
            capabilities.append("tool-use")
        if not tags and not selected and kind not in _AI_RESOURCE_KINDS:
            self.ctx.examined()
            return None
        if len(selected) > 20:
            self.ctx.warn(f"{self.name}: reported image limit reached")
        finding = self._new_finding(cluster, namespace, kind, resource_name, selected, tags, capabilities)
        _add_serving_evidence(finding, model_argument, serving, gpu_workload)
        self.ctx.examined()
        return finalize(finding, self.index)

    def _object_identity(self, obj: dict[str, Any]) -> tuple[str, str, str] | None:
        """An object's kind, name and namespace, or None when it is not analyzed.

        An unrecognized kind is skipped silently, a malformed identity with a warning.
        """
        kind = _kind(obj)
        if not kind:
            # Without a kind the object cannot be analyzed or ignored as
            # another kind: it could be any workload.
            self.ctx.warn(
                f"{self.name}: object has malformed kind"
                if "kind" in obj
                else f"{self.name}: object without kind outside a typed List"
            )
            return None
        if kind not in _RECOGNIZED | (_OPENSHIFT if self.name == "cloud.openshift" else set()):
            return None
        metadata_value = obj.get("metadata")
        if not isinstance(metadata_value, dict):
            self.ctx.warn(f"{self.name}: object has malformed metadata")
            return None
        resource_name = _name(obj)
        if not resource_name:
            self.ctx.warn(f"{self.name}: object without metadata.name")
            return None
        if len(resource_name) > 253:
            self.ctx.warn(f"{self.name}: object has oversized metadata.name")
            return None
        namespace = _namespace(obj)
        if namespace is None:
            self.ctx.warn(f"{self.name}: object has malformed metadata.namespace")
            return None
        return kind, resource_name, namespace

    def _workload_spec(self, obj: dict[str, Any], kind: str) -> dict[str, Any] | None:
        """The spec that holds an object's pod template (a CronJob's Job spec), or None when malformed.

        An object without a spec has {}. A malformed spec, Job template or workload pod
        template is skipped with a warning.
        """
        spec_value = obj.get("spec")
        if spec_value is not None and not isinstance(spec_value, dict):
            self.ctx.warn(f"{self.name}: object has malformed spec")
            return None
        workload_spec = spec_value if isinstance(spec_value, dict) else {}
        if kind == "CronJob":
            job_template = workload_spec.get("jobTemplate")
            if not isinstance(job_template, dict):
                self.ctx.warn(f"{self.name}: workload has malformed job template")
                return None
            job_spec = job_template.get("spec")
            if not isinstance(job_spec, dict):
                self.ctx.warn(f"{self.name}: workload has malformed job spec")
                return None
            # Image detection and posture checks must inspect the same
            # nested Job template, never a top-level template lookalike.
            workload_spec = job_spec
        if kind in _WORKLOAD_KINDS and not isinstance(workload_spec.get("template"), dict):
            self.ctx.warn(f"{self.name}: workload has malformed pod template")
            return None
        if kind in _WORKLOAD_KINDS:
            pod_template = workload_spec["template"]
            if not isinstance(pod_template.get("spec"), dict):
                self.ctx.warn(f"{self.name}: workload has malformed pod spec")
                return None
        if kind == "Pod" and not isinstance(spec_value, dict):
            self.ctx.warn(f"{self.name}: pod has malformed spec")
            return None
        return workload_spec

    def _pod_spec(self, kind: str, workload_spec: dict[str, Any]) -> dict[str, Any] | None:
        """The pod spec whose posture and containers are read, or None when it is malformed.

        It is the pod template's spec, a Pod's own spec, or {} for any other object. Malformed
        container fields or image pull secrets are skipped with a warning.
        """
        template = workload_spec.get("template")
        pod_spec_value = (
            template.get("spec", {}) if isinstance(template, dict) else workload_spec if kind == "Pod" else {}
        )
        pod_spec = pod_spec_value if isinstance(pod_spec_value, dict) else {}
        if _malformed_container_fields(pod_spec):
            self.ctx.warn(f"{self.name}: workload has malformed containers")
            return None
        if "imagePullSecrets" in pod_spec and not isinstance(pod_spec["imagePullSecrets"], list):
            self.ctx.warn(f"{self.name}: workload has malformed image pull secrets")
            return None
        return pod_spec

    def _inspect_pod(self, pod_spec: dict[str, Any], tags: list[str]) -> tuple[bool, bool] | None:
        """Read a pod spec's posture, containers and volumes, adding the tags they carry.

        Returns whether a container passes a model argument and whether one requests or
        limits an NVIDIA GPU; None (after a warning) when the volumes are malformed.
        """
        if pod_spec.get("hostNetwork") is True:
            tags.append("privileged-pod")
        pod_security = pod_spec.get("securityContext")
        if isinstance(pod_security, dict) and pod_security.get("privileged") is True:
            tags.append("privileged-pod")
        model_argument, gpu_workload = self._inspect_containers(pod_spec, tags)
        volumes = pod_spec.get("volumes", [])
        if not isinstance(volumes, list):
            self.ctx.warn(f"{self.name}: workload has malformed volumes")
            return None
        if len(volumes) > 100:
            self.ctx.warn(f"{self.name}: volume limit reached")
        if any(isinstance(volume, dict) and "hostPath" in volume for volume in volumes[:100]):
            tags.append("privileged-pod")
        return model_argument, gpu_workload

    def _inspect_containers(self, pod_spec: dict[str, Any], tags: list[str]) -> tuple[bool, bool]:
        """Read each container of a pod spec in turn, adding the tags it carries.

        Returns whether a container passes a model argument and whether one requests or
        limits an NVIDIA GPU.
        """
        containers = _pod_containers(pod_spec)
        model_argument = False
        gpu_workload = False
        if isinstance(containers, list):
            total = sum(len(pod_spec[f]) for f in _CONTAINER_FIELDS if isinstance(pod_spec.get(f), list))
            if total > 100:
                self.ctx.warn(f"{self.name}: container limit reached")
            for container in containers:
                if not isinstance(container, dict):
                    self.ctx.warn(f"{self.name}: malformed container")
                    continue
                if "image" in container and not isinstance(container["image"], str):
                    self.ctx.warn(f"{self.name}: container has malformed image")
                model_argument = self._container_model_argument(container, model_argument)
                security = container.get("securityContext")
                if isinstance(security, dict) and security.get("privileged") is True:
                    tags.append("privileged-pod")
                if not self._container_environment(container, tags):
                    continue
                if self._container_gpu(container):
                    tags.append("gpu-workload")
                    gpu_workload = True
        return model_argument, gpu_workload

    def _container_model_argument(self, container: dict[str, Any], seen: bool) -> bool:
        """Whether a model argument is ``seen`` already or is in this container's command or args.

        A malformed command or args field is reported and not read.
        """
        for field in ("command", "args"):
            arguments = container.get(field)
            # kubectl and serializers emit an unset field as null.
            if arguments is None:
                continue
            if not isinstance(arguments, list) or not all(isinstance(a, str) for a in arguments):
                self.ctx.warn(f"{self.name}: workload has malformed container {field}")
                continue
            seen = seen or bool(_MODEL_ARGUMENT.search(" ".join(arguments)))
        return seen

    def _container_environment(self, container: dict[str, Any], tags: list[str]) -> bool:
        """Tag the provider configuration a container's environment names.

        False (after a warning) when the environment is not a list: the container's
        resources are then not read either.
        """
        envs = container.get("env", [])
        if not isinstance(envs, list):
            self.ctx.warn(f"{self.name}: workload has malformed environment")
            return False
        if len(envs) > 1000:
            self.ctx.warn(f"{self.name}: environment limit reached")
        for env in envs[:1000]:
            if not isinstance(env, dict):
                self.ctx.warn(f"{self.name}: workload has malformed environment entry")
                continue
            key = env.get("name")
            if isinstance(key, str) and any(marker in key.upper() for marker in _ENV_MARKERS):
                tags.append("provider-config-present")
        return True

    def _container_gpu(self, container: dict[str, Any]) -> bool:
        """Whether a container requests or limits a positive NVIDIA GPU count.

        A malformed count is reported with a warning.
        """
        resources = container.get("resources")
        requests = resources.get("requests") if isinstance(resources, dict) else {}
        limits = resources.get("limits") if isinstance(resources, dict) else {}
        # A GPU can be set in limits alone (Kubernetes then copies it to requests).
        gpus = [
            _positive_quantity(r.get("nvidia.com/gpu")) for r in (requests, limits) if isinstance(r, dict)
        ]
        if None in gpus:
            self.ctx.warn(f"{self.name}: container has malformed GPU quantity")
        return True in gpus

    def _new_finding(
        self,
        cluster: str,
        namespace: str,
        kind: str,
        resource_name: str,
        selected: list[str],
        tags: list[str],
        capabilities: list[str],
    ) -> Finding:
        """The finding for a reported object, with its resource evidence and image matches."""
        resource = f"k8s:{cluster}/{namespace}/{kind}/{resource_name}"
        finding = Finding(
            surface=Surface.CLOUD,
            connector=self.name,
            kind=Kind.AGENT if selected or kind in _AI_RESOURCE_KINDS else Kind.CLOUD_RESOURCE,
            title=f"Kubernetes {kind} {resource_name}",
            resource=resource,
            resource_type=f"kubernetes/{kind}",
            provider="kubernetes",
            account=sanitize_text(cluster)[:160],
            confidence=0.8 if selected else 0.65,
            tags=list(dict.fromkeys(tags)),
            capabilities=capabilities,
            metadata={"namespace": namespace, "images": selected[:20]},
        )
        finding.add_evidence(
            Evidence(
                signal=f"kubernetes:{kind}",
                description=f"Exported Kubernetes {kind} resource",
                weight=0.75,
            )
        )
        image_matches = [match for image in selected for match in self.index.match_image(image)]
        apply_matches(finding, image_matches, weight_scale=0.75)
        return finding


class OpenShiftConnector(KubernetesConnector):
    name = "cloud.openshift"
    provider = "openshift"
    description = "Analyze Kubernetes, OpenShift, and OpenShift AI inventory exports."
