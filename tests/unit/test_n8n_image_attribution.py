"""An n8n container image identifies its product, not its orchestrator."""

from __future__ import annotations

import pytest

from shadowscan.models import Kind


@pytest.mark.parametrize("image", ["n8nio/n8n:1.70.0", "docker.n8n.io/n8nio/n8n:1.70.0"])
def test_n8n_image_is_attributed_to_its_product(index, image):
    # The raw matcher may also name the Kubernetes workload signature; the
    # filesystem scanner withholds it unless the image sits inside a parsed
    # workload PodSpec, so Compose and Dockerfile images keep the product
    # signature only (the connector-level tests below and the container
    # fixture test pin that behavior).
    ids = {match.signature_id for match in index.match_image(image)}
    assert "platform.n8n" in ids


@pytest.mark.parametrize(
    "name, source",
    [
        ("compose.yaml", "services:\n  n8n:\n    image: n8nio/n8n:1.70.0\n"),
        ("Dockerfile", "FROM n8nio/n8n:1.70.0\n"),
    ],
)
def test_n8n_container_retains_infrastructure_without_kubernetes(tmp_path, run_connector, name, source):
    (tmp_path / name).write_text(source)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=False)
    assert not ctx.stats.incomplete, ctx.stats.errors
    infra = [finding for finding in findings if finding.kind == Kind.INFRA]
    assert len(infra) == 1
    assert infra[0].frameworks == ["platform.n8n"]
    assert all("cloud.kubernetes-agent-workloads" not in finding.frameworks for finding in findings)


def test_kubernetes_specific_images_remain_recognized(index):
    assert "cloud.kubernetes-agent-workloads" in {
        match.signature_id for match in index.match_image("ghcr.io/kagent-dev/kagent:latest")
    }
