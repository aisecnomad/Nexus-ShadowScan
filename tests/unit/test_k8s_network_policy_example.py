"""The Kubernetes example requires an operator-approved live egress path."""

from __future__ import annotations

from pathlib import Path

import yaml

EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "k8s-network-policy.yaml"
NAME = {"app.kubernetes.io/name": "shadowscan"}


def _policies() -> dict[str, dict]:
    docs = [doc for doc in yaml.safe_load_all(EXAMPLE.read_text(encoding="utf-8")) if doc]
    assert all(doc["kind"] == "NetworkPolicy" for doc in docs)
    return {doc["metadata"]["name"]: doc["spec"] for doc in docs}


def test_every_shadowscan_pod_is_denied_egress_by_default():
    spec = _policies()["shadowscan-default-deny-egress"]
    assert spec["podSelector"] == {"matchLabels": NAME}
    assert spec["policyTypes"] == ["Egress"] and spec["egress"] == []


def test_live_egress_applies_only_to_labelled_shadowscan_pods():
    live = _policies()["shadowscan-live-egress"]
    labels = live["podSelector"]["matchLabels"]
    assert labels.items() >= NAME.items() and labels.get("shadowscan-mode") == "live"
    assert live["policyTypes"] == ["Egress"]


def test_live_baseline_only_allows_dns_to_selected_cluster_dns_pods():
    # In particular, neither arbitrary public HTTPS nor an internal HTTPS
    # endpoint in non-RFC1918 or global-unicast space is allowed out of the
    # box. A site's separately deployed policies can still widen this policy.
    [dns] = _policies()["shadowscan-live-egress"]["egress"]
    assert set(dns) == {"to", "ports"}
    assert dns["to"] == [
        {
            "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}},
            "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
        }
    ]
    assert dns["ports"] == [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}]
