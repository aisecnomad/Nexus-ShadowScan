"""Pure helpers of the Kubernetes connector: AI images, egress policies and exposure tags."""

from __future__ import annotations

import pytest

from shadowscan.connectors.cloud.kubernetes import _ai_images, _egress_policy_namespaces, _exposure_tags


def test_ai_images_keep_vendor_and_serving_engine_images_in_order():
    images = [
        "nginx:1.25",
        "registry.example/ml/vllm-serving:1.4",
        "ollama/ollama:0.3",
        "ghcr.io/acme/ollama-exporter:1.0",
        "nvcr.io/nvidia/tritonserver:24.01-py3",
    ]
    assert _ai_images(images) == ["registry.example/ml/vllm-serving:1.4", "ollama/ollama:0.3"]


def _policy(namespace, spec):
    metadata = {"name": "policy"} if namespace is None else {"name": "policy", "namespace": namespace}
    return {"kind": "NetworkPolicy", "metadata": metadata, "spec": spec}


def test_egress_policy_namespaces_need_an_egress_type_or_rules_and_a_valid_namespace():
    objects = [
        _policy("typed", {"policyTypes": ["Ingress", "Egress"]}),
        _policy("rules", {"egress": []}),
        _policy(None, {"policyTypes": ["Egress"]}),
        _policy("ingress-only", {"policyTypes": ["Ingress"]}),
        _policy("types-not-a-list", {"policyTypes": "Egress"}),
        _policy("Bad_Namespace", {"policyTypes": ["Egress"]}),
        _policy("spec-not-a-mapping", "Egress"),
        {"kind": "Deployment", "metadata": {"name": "web", "namespace": "workload"}, "spec": {"egress": []}},
    ]
    assert _egress_policy_namespaces(objects) == {"typed", "rules", "default"}


@pytest.mark.parametrize(
    ("kind", "name", "spec", "tags"),
    [
        ("Service", "llm-api", {"type": "LoadBalancer"}, ["exposed-llm-server"]),
        ("Service", "api", {"type": "NodePort", "selector": {"app": "ollama"}}, ["exposed-llm-server"]),
        ("Service", "llm-api", {"type": "ClusterIP"}, []),
        ("Service", "web", {"type": "LoadBalancer", "selector": {"app": "web"}}, []),
        ("Ingress", "model-gateway", {}, ["exposed-llm-server"]),
        ("Ingress", "gateway", {"backend": {"service": {"name": "vllm"}}}, ["exposed-llm-server"]),
        ("Route", "gateway", {"to": {"kind": "Service", "name": "inference"}}, ["exposed-llm-server"]),
        ("Deployment", "llm-api", {"backend": "llm"}, []),
    ],
)
def test_exposure_tags_mark_ai_servers_reachable_from_outside_the_cluster(kind, name, spec, tags):
    obj = {"kind": kind, "metadata": {"name": name, "namespace": "ml"}, "spec": spec}
    assert _exposure_tags(obj, kind, name, spec) == tags


@pytest.mark.parametrize(
    ("role", "subjects", "tags"),
    [
        (
            "cluster-admin",
            [{"kind": "User", "name": "u"}, {"kind": "ServiceAccount", "name": "agent"}],
            ["cluster-admin"],
        ),
        ("cluster-admin", [{"kind": "User", "name": "u"}], []),
        ("view", [{"kind": "ServiceAccount", "name": "agent"}], []),
        ("cluster-admin", {"kind": "ServiceAccount", "name": "agent"}, []),
    ],
)
@pytest.mark.parametrize("kind", ["RoleBinding", "ClusterRoleBinding"])
def test_exposure_tags_mark_service_accounts_bound_to_cluster_admin(kind, role, subjects, tags):
    obj = {"kind": kind, "metadata": {"name": "binding"}, "roleRef": {"name": role}, "subjects": subjects}
    assert _exposure_tags(obj, kind, "binding", {}) == tags
