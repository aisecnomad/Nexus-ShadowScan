"""Structural Kubernetes context for container image attribution.

An image name alone identifies a product, not the orchestrator deploying it.
Only recognized built-in workload PodSpecs confer Kubernetes context. YAML is
never rendered or executed; strict loader budgets cover the complete stream.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import cast

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

from shadowscan.connectors.code.semantic_config import has_template_markers
from shadowscan.utils.safe_yaml import (
    StrictBoundedConfigLoader,
    YAMLIntegrityError,
    YAMLResourceLimitError,
)

_POD_SPEC_PATHS: dict[tuple[str, str], tuple[str, ...]] = {
    ("v1", "Pod"): ("spec",),
    ("v1", "ReplicationController"): ("spec", "template", "spec"),
    ("apps/v1", "Deployment"): ("spec", "template", "spec"),
    ("apps/v1", "StatefulSet"): ("spec", "template", "spec"),
    ("apps/v1", "DaemonSet"): ("spec", "template", "spec"),
    ("apps/v1", "ReplicaSet"): ("spec", "template", "spec"),
    ("batch/v1", "Job"): ("spec", "template", "spec"),
    ("batch/v1", "CronJob"): ("spec", "jobTemplate", "spec", "template", "spec"),
}
_CONTAINERS = ("containers", "initContainers", "ephemeralContainers")


def _field(node: Node | None, key: str) -> Node | None:
    if isinstance(node, MappingNode):
        # PyYAML prepends merged fields before explicit fields. Construction
        # therefore takes the last occurrence, including explicit overrides.
        for name, value in reversed(node.value):
            if isinstance(name, ScalarNode) and name.value == key:
                return cast(Node, value)
    return None


def _template_integrity_failure(node: MappingNode, text: str) -> bool:
    """Recognize template ambiguity only at the mapping that actually failed."""
    values: dict[tuple[str, str], Node] = {}
    for key, value in node.value:
        if not isinstance(key, ScalarNode):
            # ``image: {{ .Values.image }}`` parses as a mapping-valued key.
            start = max(node.start_mark.index, key.start_mark.index - 1)
            end = min(node.end_mark.index, key.end_mark.index + 1)
            return has_template_markers(text[start:end])
        if key.tag != "tag:yaml.org,2002:str":
            return False
        identity = (key.tag, key.value)
        previous = values.get(identity)
        if previous is not None:
            return any(
                has_template_markers(text[item.start_mark.index : item.end_mark.index])
                for item in (previous, value)
            )
        values[identity] = value
    return False


class _TemplateIntegrityError(yaml.YAMLError):
    """A conditional template repeats a field or uses an unrendered mapping key."""


class _ContextLoader(StrictBoundedConfigLoader):
    def __init__(self, text: str) -> None:
        self._context_text = text
        super().__init__(text)

    def flatten_mapping(self, node: MappingNode) -> None:
        try:
            super().flatten_mapping(node)
        except YAMLIntegrityError:
            if _template_integrity_failure(node, self._context_text):
                raise _TemplateIntegrityError from None
            raise


def _string(node: Node | None) -> str:
    return node.value if isinstance(node, ScalarNode) and node.tag == "tag:yaml.org,2002:str" else ""


def _pod_specs(root: Node) -> Iterator[Node]:
    pending = [root]
    while pending:
        resource = pending.pop()
        api_version = _string(_field(resource, "apiVersion"))
        kind = _string(_field(resource, "kind"))
        if (api_version, kind) == ("v1", "List"):
            items = _field(resource, "items")
            if isinstance(items, SequenceNode):
                pending.extend(items.value)
            continue
        path = _POD_SPEC_PATHS.get((api_version, kind))
        if path is None:
            continue
        spec: Node | None = resource
        for component in path:
            spec = _field(spec, component)
        if isinstance(spec, MappingNode):
            yield spec


def _images(root: Node) -> Iterator[tuple[str, int]]:
    for spec in _pod_specs(root):
        for key in _CONTAINERS:
            containers = _field(spec, key)
            if not isinstance(containers, SequenceNode):
                continue
            for container in containers.value:
                image = _field(container, "image")
                value = _string(image)
                if value and not any(character.isspace() for character in value):
                    assert image is not None
                    yield value, image.start_mark.line + 1


def kubernetes_images(text: str) -> set[tuple[str, int]]:
    """Return image values and source lines inside supported Kubernetes PodSpecs.

    Construction checks duplicate keys and scalar types before nodes are read.
    Unparsed documents (including unrendered templates) confer no context, and
    preceding valid documents retain theirs. Integrity and resource failures
    propagate except for an unrendered template at the failing mapping itself.
    Nothing from one YAML document authorizes another one.
    """
    # A recognized resource requires the apiVersion key. Plain, folded and
    # alias-backed spellings contain it literally; escaped quoted spellings
    # contain a backslash and must still be parsed. This avoids constructing
    # ordinary Compose/CI/values documents that cannot confer this context.
    if "apiVersion" not in text and "\\" not in text:
        return set()
    loader = _ContextLoader(text)
    images: set[tuple[str, int]] = set()
    try:
        while loader.check_data():
            root = loader.get_node()
            assert root is not None
            loader.construct_document(root)
            images.update(_images(root))
    except (YAMLIntegrityError, YAMLResourceLimitError):
        raise
    except yaml.YAMLError:
        return images
    finally:
        loader.dispose()
    return images
