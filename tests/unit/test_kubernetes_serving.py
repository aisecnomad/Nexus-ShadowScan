"""Kubernetes self-hosted model serving: image tokens, GPU limits and model arguments."""

from __future__ import annotations

import json

import pytest

from shadowscan.models import Kind

RESOURCE = "k8s:test/{namespace}/{kind}/{name}"


@pytest.fixture
def serving(run_connector, fixtures):
    findings, ctx = run_connector(
        "cloud.kubernetes", input=str(fixtures / "kubernetes/serving.json"), cluster="test"
    )
    assert not ctx.stats.incomplete and not ctx.stats.warnings
    return {finding.resource: finding for finding in findings}


def _get(findings, name, kind="Deployment", namespace="ml"):
    return findings.get(RESOURCE.format(namespace=namespace, kind=kind, name=name))


def test_private_registry_engine_image_with_model_argument_and_gpu_limit_is_serving(serving):
    finding = _get(serving, "chat-serving")
    assert finding.kind == Kind.AGENT
    assert {"ai-workload", "gpu-workload", "self-hosted-model-serving"} <= set(finding.tags)
    signals = {ev.signal: ev.weight for ev in finding.evidence}
    assert signals["kubernetes:model-argument"] == 0.7
    assert signals["kubernetes:gpu-resource"] == 0.45
    # Only the argument's presence is recorded, never the model identifier.
    assert "example-org/chat-7b" not in json.dumps(finding.to_dict())


@pytest.mark.parametrize(
    "name,kind",
    [("opaque-server", "Deployment"), ("finetune-forecast", "Job")],
)
def test_model_argument_and_gpu_without_an_ai_image_are_not_an_agent(serving, name, kind):
    finding = _get(serving, name, kind)
    assert finding.kind == Kind.CLOUD_RESOURCE
    assert "self-hosted-model-serving" not in finding.tags and "ai-workload" not in finding.tags
    assert finding.confidence == 0.75
    assert {ev.signal: ev.weight for ev in finding.evidence}["kubernetes:model-argument"] == 0.0
    assert "kubernetes:gpu-resource" not in {ev.signal for ev in finding.evidence}


def test_model_argument_without_gpu_or_ai_image_is_not_reported(serving):
    assert _get(serving, "image-classifier") is None


def test_gpu_set_only_in_limits_is_a_gpu_workload(serving):
    finding = _get(serving, "render-batch", "Job", "media")
    assert finding.kind == Kind.CLOUD_RESOURCE and "gpu-workload" in finding.tags


@pytest.mark.parametrize(
    "name,provider",
    [
        ("local-ai", "provider.localai"),
        ("llama-server", "provider.llama-cpp"),
        ("tgi", "provider.huggingface"),
    ],
)
def test_existing_engine_images_stay_agents(serving, name, provider):
    finding = _get(serving, name)
    assert finding.kind == Kind.AGENT and provider in finding.model_providers


def test_agent_named_environment_and_model_mounts_are_not_ai_evidence(serving):
    assert _get(serving, "web", namespace="web") is None


def _single_container(tmp_path, run_connector, container):
    source = tmp_path / "workloads.json"
    source.write_text(
        json.dumps(
            {
                "kind": "List",
                "items": [
                    {
                        "kind": "Deployment",
                        "metadata": {"name": "chat", "namespace": "ml"},
                        "spec": {"template": {"spec": {"containers": [container]}}},
                    }
                ],
            }
        )
    )
    return run_connector("cloud.kubernetes", input=str(source), cluster="test")


@pytest.mark.parametrize("field", ["args", "command"])
@pytest.mark.parametrize("value", ["--model example-org/chat-7b", ["--model", 7]])
def test_malformed_container_arguments_mark_the_scan_incomplete(tmp_path, run_connector, field, value):
    container = {"image": "registry.example/ml/vllm-serving:1.4", field: value}
    findings, ctx = _single_container(tmp_path, run_connector, container)
    assert ctx.stats.incomplete
    assert any(f"malformed container {field}" in warning for warning in ctx.stats.warnings)
    # The workload is still reported from its image; the argument is not read.
    assert len(findings) == 1 and "self-hosted-model-serving" not in findings[0].tags


@pytest.mark.parametrize("field", ["args", "command"])
def test_null_container_arguments_are_unset_not_malformed(tmp_path, run_connector, field):
    container = {"image": "registry.example/ml/vllm-serving:1.4", field: None}
    findings, ctx = _single_container(tmp_path, run_connector, container)
    assert not ctx.stats.incomplete and not ctx.stats.warnings
    assert len(findings) == 1 and findings[0].kind == Kind.AGENT
