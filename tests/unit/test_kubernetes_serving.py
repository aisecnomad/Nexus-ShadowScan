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


@pytest.mark.parametrize(
    "resources",
    [
        {"limits": {"nvidia.com/gpu": "0"}},
        {"requests": {"nvidia.com/gpu": 0}, "limits": {"nvidia.com/gpu": "0"}},
        {"requests": {"nvidia.com/gpu": "0.0"}},
        {"limits": {"nvidia.com/gpu": None}},
    ],
)
def test_zero_gpu_quantity_is_not_a_gpu_workload(tmp_path, run_connector, resources):
    """Regression (F19): a GPU count of 0 requests no GPU."""
    container = {"image": "registry.example/ml/vllm-serving:1.4", "resources": resources}
    findings, ctx = _single_container(tmp_path, run_connector, container)
    assert not ctx.stats.incomplete, ctx.stats.warnings
    assert len(findings) == 1 and "gpu-workload" not in findings[0].tags
    assert "kubernetes:gpu-resource" not in {ev.signal for ev in findings[0].evidence}


@pytest.mark.parametrize("quantity", [1, "1", "2", 4.0])
def test_positive_gpu_quantity_is_a_gpu_workload(tmp_path, run_connector, quantity):
    container = {"image": "nginx:1.25", "resources": {"limits": {"nvidia.com/gpu": quantity}}}
    findings, ctx = _single_container(tmp_path, run_connector, container)
    assert not ctx.stats.incomplete, ctx.stats.warnings
    assert len(findings) == 1 and "gpu-workload" in findings[0].tags


@pytest.mark.parametrize("quantity", ["lots", -1, "-1", True, {"count": 1}])
def test_malformed_gpu_quantity_marks_the_scan_incomplete(tmp_path, run_connector, quantity):
    container = {
        "image": "registry.example/ml/vllm-serving:1.4",
        "resources": {"limits": {"nvidia.com/gpu": quantity}},
    }
    findings, ctx = _single_container(tmp_path, run_connector, container)
    assert ctx.stats.incomplete
    assert any("malformed GPU quantity" in warning for warning in ctx.stats.warnings)
    assert len(findings) == 1 and "gpu-workload" not in findings[0].tags


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


@pytest.mark.parametrize(
    "image",
    [
        "registry.example/ml/ollama:0.3",
        "registry.example/ml/sglang",
        "registry.example/ml/llama-cpp-server:b3000",
        "registry.example/ml/vllm@sha256:" + "a" * 64,
        "registry.example:5000/vllm:0.5",
        # Triton with an LLM backend.
        "nvcr.io/nvidia/tritonserver:24.05-trtllm-python-py3",
        "nvcr.io/nvidia/tritonserver:24.05-vllm-python-py3",
    ],
)
def test_serving_engine_image_names_are_agents(tmp_path, run_connector, image):
    findings, ctx = _single_container(tmp_path, run_connector, {"image": image})
    assert not ctx.stats.incomplete
    assert len(findings) == 1 and findings[0].kind == Kind.AGENT and "ai-workload" in findings[0].tags


@pytest.mark.parametrize(
    "image",
    [
        # Triton also serves vision and tabular models.
        "nvcr.io/nvidia/tritonserver:24.01-py3",
        # Sidecars and controllers named after an engine.
        "ghcr.io/acme/ollama-exporter:1.0",
        "registry.example/ml/vllm-operator:0.2",
        # An engine name that does not start the image name.
        "registry.example/vllm/server:1",
        "registry.example/ml/serving-vllm",
    ],
)
def test_engine_tokens_elsewhere_in_an_image_are_not_serving(tmp_path, run_connector, image):
    findings, ctx = _single_container(tmp_path, run_connector, {"image": image})
    assert findings == [] and not ctx.stats.incomplete


def _pod(tmp_path, run_connector, pod_spec):
    source = tmp_path / "workloads.json"
    source.write_text(
        json.dumps(
            {
                "kind": "List",
                "items": [
                    {
                        "kind": "Deployment",
                        "metadata": {"name": "chat", "namespace": "ml"},
                        "spec": {"template": {"spec": pod_spec}},
                    }
                ],
            }
        )
    )
    return run_connector("cloud.kubernetes", input=str(source), cluster="test")


def test_native_sidecar_init_container_is_inspected(tmp_path, run_connector):
    """Regression (October 15 review): initContainers were ignored, so a native sidecar model
    server (restartPolicy: Always) produced no finding on a complete scan."""
    pod = {
        "containers": [{"image": "nginx:1.25"}],
        "initContainers": [
            {
                "name": "ollama",
                "image": "ollama/ollama:0.4",
                "restartPolicy": "Always",
                "resources": {"limits": {"nvidia.com/gpu": "1"}},
            }
        ],
    }
    findings, ctx = _pod(tmp_path, run_connector, pod)
    assert not ctx.stats.incomplete, ctx.stats.warnings
    assert any("gpu-workload" in f.tags for f in findings)
    assert any("ollama" in json.dumps(f.to_dict()) for f in findings)


def test_ephemeral_container_model_image_is_inspected(tmp_path, run_connector):
    pod = {
        "containers": [{"image": "nginx:1.25"}],
        "ephemeralContainers": [{"name": "debug", "image": "registry.example/ml/vllm-serving:1.4"}],
    }
    findings, ctx = _pod(tmp_path, run_connector, pod)
    assert not ctx.stats.incomplete, ctx.stats.warnings
    assert any("vllm-serving" in json.dumps(f.to_dict()) for f in findings)


def test_malformed_init_containers_are_reported(tmp_path, run_connector):
    findings, ctx = _pod(tmp_path, run_connector, {"containers": [], "initContainers": "nope"})
    assert ctx.stats.incomplete


_VLLM_GPU = {
    "name": "vllm",
    "image": "vllm/vllm-openai:v0.6.0",
    "resources": {"limits": {"nvidia.com/gpu": "1"}},
}


@pytest.mark.parametrize("field", ["initContainers", "ephemeralContainers"])
def test_a_null_optional_container_field_is_absent(tmp_path, run_connector, field):
    """Regression: a null initContainers/ephemeralContainers (an empty field as Helm renders it)
    was read as malformed, so the whole workload, here a vLLM GPU deployment, was skipped and
    the scan marked incomplete."""
    findings, ctx = _pod(tmp_path, run_connector, {field: None, "containers": [_VLLM_GPU]})
    assert not ctx.stats.incomplete, ctx.stats.warnings
    assert any("gpu-workload" in f.tags and "vllm" in json.dumps(f.to_dict()) for f in findings)


def test_a_helm_rendered_empty_init_containers_field_keeps_the_workload(tmp_path, run_connector):
    source = tmp_path / "rendered.yaml"
    source.write_text(
        "apiVersion: v1\n"
        "kind: List\n"
        "items:\n"
        "  - apiVersion: apps/v1\n"
        "    kind: Deployment\n"
        "    metadata: {name: chat, namespace: ml}\n"
        "    spec:\n"
        "      template:\n"
        "        spec:\n"
        "          initContainers:\n"
        "          containers:\n"
        "            - name: vllm\n"
        "              image: vllm/vllm-openai:v0.6.0\n"
        '              resources: {limits: {nvidia.com/gpu: "1"}}\n'
    )
    findings, ctx = run_connector("cloud.kubernetes", input=str(source), cluster="test")
    assert not ctx.stats.incomplete, ctx.stats.warnings
    assert any("gpu-workload" in f.tags for f in findings)


def test_a_null_containers_field_is_still_malformed(tmp_path, run_connector):
    # Every pod has containers: null there is not an absent optional field.
    findings, ctx = _pod(tmp_path, run_connector, {"containers": None, "initContainers": [_VLLM_GPU]})
    assert findings == [] and ctx.stats.incomplete
    assert ctx.stats.warnings == ["cloud.kubernetes: workload has malformed containers"]


def test_a_privileged_init_container_marks_the_ai_workload_privileged(tmp_path, run_connector):
    # Init containers are read like regular ones, so a privileged one (a GPU driver installer,
    # say) tags the workload as a privileged regular container does.
    pod = {
        "initContainers": [
            {"name": "setup", "image": "busybox:1.36", "securityContext": {"privileged": True}}
        ],
        "containers": [_VLLM_GPU],
    }
    findings, ctx = _pod(tmp_path, run_connector, pod)
    assert not ctx.stats.incomplete, ctx.stats.warnings
    assert any("privileged-pod" in f.tags and "gpu-workload" in f.tags for f in findings)
