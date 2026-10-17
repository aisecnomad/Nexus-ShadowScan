"""Offline-first endpoint and runtime inventory connectors.

``endpoint.mcp`` also fetches A2A Agent Cards, but only from URLs the operator
lists in ``agent_card_urls`` (see :mod:`shadowscan.connectors.endpoint.a2a`).
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from collections.abc import Callable, Iterable, Iterator
from dataclasses import replace
from itertools import islice
from typing import Any, ClassVar
from urllib.parse import urlsplit

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError
from shadowscan.connectors.cloud.gcp import AI_SERVICES as GCP_AI_SERVICES
from shadowscan.connectors.code.instruction_content import inspect_instruction_text
from shadowscan.connectors.code.semantic_config import (
    a2a_card_metadata,
    a2a_card_tags,
    a2a_signature_state,
    a2a_unsupported_protocol_version,
    validate_agent_manifest,
)
from shadowscan.connectors.code.skill_audit import MAX_TEXT_BYTES, audit_skill_text
from shadowscan.connectors.common import apply_matches, failure_summary, finalize, name_matches
from shadowscan.connectors.endpoint import a2a
from shadowscan.connectors.endpoint.catalog import (
    AMBIGUOUS_PRODUCT_CONTEXTS,
    AMBIGUOUS_PRODUCT_NAMES,
    LOCAL_RUNTIME_NAMES,
    MODEL_FILE_SUFFIXES,
    MODEL_STORES,
    SHELL_TOOLS,
)
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.signatures import SignatureIndex
from shadowscan.utils.http import diagnostic_url
from shadowscan.utils.jcs import CanonicalizationError
from shadowscan.utils.jwks import fetch_jwks
from shadowscan.utils.redaction import REDACTED, SanitizationLimitError, sanitize, sanitize_text

_MAX_LABEL = 160
_MAX_TOOLS = 500
_MAX_OTEL_SPANS = 100_000
# Base tool-poisoning rules. They match anywhere in a description, so they
# also tag documentation URLs, tool references and quoted or prohibited
# wording; the sentence audit below is additional, zero-weight signal and
# never removes this tag.
_POISONING = re.compile(
    r"<\s*IMPORTANT\s*>|ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|"
    r"(?:exfiltrat|send|forward)\w*\s+(?:the\s+)?(?:data|secret|credential|prompt)|https?://",
    re.IGNORECASE,
)
# Invisible and bidirectional control characters, the set skill_audit treats
# as invisible: zero-width and directional marks, embeddings and overrides,
# word joiner and invisible operators, isolates, BOM and tag characters.
_ZERO_WIDTH = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000e0000-\U000e007f]")
_TOOL_REF = re.compile(r"\b(?:use|call|invoke)\s+the\s+[`\"']?([A-Za-z][\w.-]{0,63})", re.IGNORECASE)
# A model provider API host: any OpenAI or Anthropic host, and the Google AI services
# the GCP connector counts as AI (gcp.AI_SERVICES: Vertex AI, the Gemini API,
# Dialogflow, Discovery Engine, Document AI, Speech, Contact Center AI, ...), which
# include every googleapis.com host the bundled signatures name. Each is matched with
# its regional prefix (``us-central1-aiplatform``, ``eu-documentai``) and as the
# mutual-TLS endpoint Google client libraries use with a client certificate
# (``aiplatform.mtls.googleapis.com``). Other googleapis.com hosts (fonts, storage,
# www, ...) are not AI services, and Google front-end addresses carry many of them,
# so a flow's destination names must not match them. A Google host is matched from
# the start of its label only, so a hostile run of hyphenated words is scanned once,
# not once per word against every service name.
_GOOGLE_AI_SERVICES = "|".join(
    sorted(re.escape(host.removesuffix(".googleapis.com")) for host in GCP_AI_SERVICES)
)
_HOST = re.compile(
    r"(?:https?://)?(?:[a-z0-9-]{1,63}\.(?:openai\.com|anthropic\.com)"
    rf"|(?<![\w-])(?:[a-z0-9-]{{1,63}}-)?(?:{_GOOGLE_AI_SERVICES})(?:\.mtls)?\.googleapis\.com)\b",
    re.IGNORECASE,
)


def _bounded_text(value: object, limit: int = _MAX_LABEL) -> str:
    """A record value as sanitized text cut to ``limit`` ("" for anything but text).

    Raises SanitizationLimitError for a value past the sanitizer's safety limits; connectors
    read record values through ``_EndpointConnector._text``, which withholds such a value.
    """
    if not isinstance(value, str):
        return ""
    return sanitize_text(value)[:limit]


def _sensitive_attribute(key: str) -> bool:
    normalized = key.casefold()
    return (
        normalized.startswith(("gen_ai.prompt", "gen_ai.completion", "llm.input", "llm.output"))
        or normalized.endswith(".content")
        or ".content." in normalized
    )


def _attrs(value: object, warn: Callable[[str], None] | None = None) -> dict[str, Any]:
    """Convert OTLP attribute arrays or mappings into a small scalar mapping."""
    if isinstance(value, dict):
        if len(value) > 1000 and warn is not None:
            warn("gateway.otel: attribute limit reached")
        mapping_out: dict[str, Any] = {}
        for key, item in islice(value.items(), 1000):
            if not isinstance(key, str):
                if warn is not None:
                    warn("gateway.otel: malformed attribute key")
                continue
            if not _sensitive_attribute(key):
                mapping_out[key] = item
        return mapping_out
    if isinstance(value, list):
        list_out: dict[str, Any] = {}
        if len(value) > 1000 and warn is not None:
            warn("gateway.otel: attribute limit reached")
        for item in value[:1000]:
            if not isinstance(item, dict) or not isinstance(item.get("key"), str):
                if warn is not None:
                    warn("gateway.otel: malformed attribute")
                continue
            if _sensitive_attribute(item["key"]):
                continue
            raw = item.get("value")
            if isinstance(raw, dict):
                raw = next(iter(raw.values()), None)
            list_out[item["key"]] = raw
        return list_out
    if value is not None and warn is not None:
        warn("gateway.otel: malformed attributes")
    return {}


def _records(
    records: Iterable[dict[str, Any]], warn: Callable[[str], None] | None = None
) -> Iterator[dict[str, Any]]:
    """Yield bounded-enough dict records from standard nested telemetry envelopes."""
    span_count = 0
    for record in records:
        yield record
        spans = record.get("resourceSpans")
        if "resourceSpans" not in record:
            continue
        if not isinstance(spans, list):
            if warn is not None:
                warn("gateway.otel: malformed resource spans")
            continue
        if len(spans) > 1000 and warn is not None:
            warn("gateway.otel: resource span limit reached")
        for resource_span in spans[:1000]:
            if not isinstance(resource_span, dict):
                if warn is not None:
                    warn("gateway.otel: malformed resource span")
                continue
            raw_resource = resource_span.get("resource")
            if not isinstance(raw_resource, dict):
                if "resource" in resource_span and warn is not None:
                    warn("gateway.otel: malformed resource attributes")
                raw_resource = {}
            resource = _attrs(raw_resource.get("attributes"), warn)
            scopes = resource_span.get("scopeSpans")
            if not isinstance(scopes, list):
                if warn is not None:
                    warn("gateway.otel: malformed scope spans")
                continue
            if len(scopes) > 1000 and warn is not None:
                warn("gateway.otel: scope span limit reached")
            for scope in scopes[:1000]:
                if not isinstance(scope, dict) or not isinstance(scope.get("spans"), list):
                    if warn is not None:
                        warn("gateway.otel: malformed span collection")
                    continue
                if len(scope["spans"]) > 1000 and warn is not None:
                    warn("gateway.otel: span limit reached")
                for span in scope["spans"][:1000]:
                    if not isinstance(span, dict):
                        if warn is not None:
                            warn("gateway.otel: malformed span")
                        continue
                    if span_count >= _MAX_OTEL_SPANS:
                        if warn is not None:
                            warn("gateway.otel: aggregate span limit reached")
                        return
                    span_count += 1
                    # ``analyze`` reads ``resource["attributes"]``, the shape a raw
                    # OTLP span record carries. Yielding the flattened mapping
                    # directly dropped every resource attribute, so nested exports
                    # lost ``service.name`` and distinct callers merged into
                    # ``unknown-service``.
                    yield {"resource": {"attributes": resource}, **span}


class _EndpointConnector(BaseConnector):
    # No live API: reads an endpoint inventory collected on the host.
    live_collection: ClassVar[bool] = False
    surface: ClassVar[Surface] = Surface.ENDPOINT
    offline_formats: ClassVar[str] = "JSON / JSONL / YAML export"
    # Whether a value past the sanitizer's limits was withheld (see ``_text``).
    _withheld_values = False

    def collect(self) -> Iterable[dict[str, Any]]:
        raise NotImplementedError("endpoint inventory requires offline input")

    def _text(self, value: object, limit: int = _MAX_LABEL) -> str:
        """A record value as sanitized text cut to ``limit`` ("" for anything but text).

        One hostile record (a value past the sanitizer's safety limits) must not abort the
        whole connector and drop its other findings: that value is withheld and the rest is
        read. What was withheld was not analyzed, so the scan is incomplete, with one
        fixed-text warning however many values are withheld.
        """
        try:
            return _bounded_text(value, limit)
        except SanitizationLimitError:
            if not self._withheld_values:
                self._withheld_values = True
                self.ctx.warn(f"{self.name}: record value withheld: sanitization safety limit exceeded")
            return REDACTED

    def _finding(
        self,
        resource: str,
        resource_type: str,
        title: str,
        *,
        kind: Kind = Kind.AGENT,
        provider: str | None = None,
        tags: Iterable[str] = (),
        capabilities: Iterable[str] = (),
        metadata: dict[str, Any] | None = None,
        weight: float = 0.7,
    ) -> Finding:
        finding = Finding(
            surface=self.surface,
            connector=self.name,
            kind=kind,
            title=self._text(title) or resource_type,
            resource=self._text(resource) or "unknown",
            resource_type=resource_type,
            provider=provider,
            confidence=weight,
            capabilities=list(dict.fromkeys(capabilities)),
            tags=list(dict.fromkeys(tags)),
            metadata=metadata or {},
        )
        finding.add_evidence(
            Evidence(
                signal=f"{resource_type}:inventory",
                description=self._text(title) or resource_type,
                weight=weight,
            )
        )
        self.ctx.examined()
        return finalize(finding, self.index)


# Collector-declared categories that mark a host inventory row as AI-related.
# Tokens, not substrings: "local-llm-runtime" qualifies, "email-client" and a
# fleet-management "agent" product name do not reach this check at all.
_AI_CATEGORY_TOKENS = frozenset(
    {"ai", "agent", "agents", "assistant", "copilot", "genai", "llm", "mcp", "model", "models"}
)
_CATEGORY_TOKEN = re.compile(r"[a-z0-9]+")


def _ai_category(category: str) -> bool:
    return not _AI_CATEGORY_TOKENS.isdisjoint(_CATEGORY_TOKEN.findall(category.casefold()))


# Signature categories whose products a host installs or runs: model providers
# (Ollama, LM Studio, vLLM, llama.cpp, LocalAI), coding agents, and platforms
# (self-hosted chat UIs such as Open WebUI and AnythingLLM, LiteLLM, Dify,
# Flowise). A product name that is also a common word or another program's
# name needs its own product's context, by name, not by category
# (catalog.AMBIGUOUS_PRODUCT_CONTEXTS): "Make (Integromat)" is also GNU make.
_HOST_PRODUCT_CATEGORIES = frozenset({"provider", "coding-agent", "platform"})
# The products a signature groups, listed in its display name:
# "Self-hosted chat UIs (Open WebUI, LibreChat, AnythingLLM, ...)".
_LISTED_PRODUCTS = re.compile(r"\(([^()/]*,[^()/]*)\)")
_APP_SUFFIX = re.compile(r"\.(?:app|exe)$", re.IGNORECASE)
# "Ollama version 0.5.7", "LM Studio 0.3.14", "Jan v0.5.17": Windows program names
# carry the version. A bare number is part of the name ("Codex 3", "Jan 2024"). A
# match starts only where a whitespace run starts: tried from inside a run as well,
# ``\s+`` rescanned the rest of the run from each of its spaces, quadratic in its length.
_TRAILING_VERSION = re.compile(r"(?<!\s)\s+(?:version\s+v?\d|v\d|\d+\.\d)[\w.+-]*$", re.IGNORECASE)
_NON_ALNUM = re.compile(r"[^0-9a-z]+")
_PATH_SEPARATOR = re.compile(r"[\\/]")
# Host inventory paths are read this far, so a long path keeps its file name. Each
# name or path component is compared with product names only up to _MAX_LABEL
# characters: no product name is longer, so a longer one names none.
_MAX_HOST_PATH = 1024
# The catalog's model stores as case-folded path components below a home directory
# (``.ollama/models``), each with its layout.
_MODEL_STORE_ROOTS = tuple((tuple(store.root.casefold().split("/")), store.layout) for store in MODEL_STORES)
# A home directory as the case-folded components a path starts with, after any
# Windows drive: ``~`` (or ``~user``), a home variable or ``/root``, one component;
# ``/home/<user>``, ``/Users/<user>`` (``C:\Users\<user>``) and macOS's ``/var/root``, two.
_HOME_COMPONENTS = frozenset({"$home", "${home}", "%userprofile%", "root"})
_HOME_PARENTS = frozenset({"home", "users"})
_WINDOWS_DRIVE = re.compile(r"[a-z]:")
# The directories an Ollama store keeps its models in.
_OLLAMA_STORE_DIRECTORIES = frozenset({"manifests", "blobs"})
# The catalog's contexts for its ambiguous product names as case-folded path
# component runs (``goose.app``, ``.config/goose``), and the lengths of those runs.
_AMBIGUOUS_CONTEXTS = frozenset(
    tuple(context.casefold().split("/"))
    for contexts in AMBIGUOUS_PRODUCT_CONTEXTS.values()
    for context in contexts
)
_AMBIGUOUS_CONTEXT_LENGTHS = frozenset(map(len, _AMBIGUOUS_CONTEXTS))
_AMBIGUOUS_CONTEXT_HEADS = frozenset(run[0] for run in _AMBIGUOUS_CONTEXTS)


def _product_key(text: str) -> str:
    """``text`` as a product-name key: its last path component without an ``.app``/``.exe``
    suffix or a trailing version, letters and digits only, case-folded.

    ``/Applications/LM Studio.app``, ``lm-studio`` and ``LM Studio 0.3.14`` share one key.
    A component longer than _MAX_LABEL is no product name and has the empty key.
    """
    base = _PATH_SEPARATOR.split(text.rstrip("\\/"))[-1]
    if len(base) > _MAX_LABEL:
        return ""
    base = _TRAILING_VERSION.sub("", _APP_SUFFIX.sub("", base))
    return _NON_ALNUM.sub("", base.casefold())


def _signature_product_names(name: str) -> list[str]:
    """The product names in a signature's display name: the name before any ``/``
    alternative or parenthesis ("Gemini CLI / Jules" gives "Gemini CLI"), and each
    product a parenthesized list names. A parenthesis that is not a comma-separated
    list ("LiteLLM (SDK / Proxy)", "Make (Integromat)") qualifies the name and is not read.
    """
    names = [re.split(r"\s+/\s+|\s*\(", name)[0]]
    listed = _LISTED_PRODUCTS.search(name)
    if listed:
        names += listed.group(1).split(",")
    return names


def _host_product_keys(index: SignatureIndex) -> frozenset[str]:
    """Keys of the products whose whole name marks a host inventory row as AI-related.

    A signature contributes its product names (see ``_signature_product_names``). The
    endpoint catalog contributes its local model runtimes and AI command-line tools. A
    name the catalog lists as ambiguous is left out: it counts only in context (see
    ``_names_product``).
    """
    names = [
        product
        for signature in index.signatures.values()
        if signature.category in _HOST_PRODUCT_CATEGORIES
        for product in _signature_product_names(signature.name)
    ]
    names += [name for store in MODEL_STORES for name in (store.product, store.runtime)]
    names += [name for command, (product, _) in SHELL_TOOLS.items() for name in (command, product)]
    names += LOCAL_RUNTIME_NAMES
    ambiguous = _ambiguous_product_keys()
    return frozenset(key for key in map(_product_key, names) if key and key not in ambiguous)


def _ambiguous_product_keys() -> frozenset[str]:
    return frozenset(_product_key(name) for name in AMBIGUOUS_PRODUCT_NAMES)


def _names_bundle(part: str, keys: frozenset[str]) -> bool:
    """Whether the directory ``part`` is an application bundle or a dot-directory named
    after a product in ``keys``: ``Ollama.app``, ``~/.lmstudio``."""
    return bool(_APP_SUFFIX.search(part) or part.startswith(".")) and _product_key(part) in keys


def _path_parts(text: str) -> tuple[list[str], list[str]]:
    """The non-empty path components of ``text``, as written and case-folded."""
    parts = [part for part in _PATH_SEPARATOR.split(text) if part]
    return parts, [part.casefold() for part in parts]


def _in_ambiguous_context(folded: list[str]) -> bool:
    """Whether the case-folded path components ``folded`` hold, as a run, one of the
    contexts the catalog lists for an ambiguous product name (``Jan.exe``, ``Goose.app``,
    ``.continue``)."""
    return any(
        tuple(folded[start : start + length]) in _AMBIGUOUS_CONTEXTS
        for start, part in enumerate(folded)
        if part in _AMBIGUOUS_CONTEXT_HEADS
        for length in _AMBIGUOUS_CONTEXT_LENGTHS
    )


def _names_product(parts: list[str], folded: list[str], keys: frozenset[str]) -> bool:
    """Whether the name or path whose components are ``parts`` (``folded`` case-folded)
    names a known AI product as a whole.

    Its last component qualifies when it is a product name in ``keys`` (``ollama``,
    ``LM Studio.app``, ``Ollama version 0.5.7``), and a directory on the path when it is an
    application bundle or dot-directory named after one (``/Applications/Ollama.app/...``,
    ``~/.lmstudio/bin/lms``). A name the catalog lists as ambiguous is not in ``keys``: it
    qualifies only with its own product's context, a bundle, executable or directory the
    catalog lists for that product (``Jan.exe``, ``/Applications/Goose.app/Contents/MacOS/goose``,
    ``~/.continue``). An ``.app`` or ``.exe`` suffix or a dot-directory alone is no context
    (``make.exe``, ``Cohere.exe``, ``~/.make``), and a plain directory such as a home
    directory's user name or ``Cellar/goose`` names nothing.
    """
    if not parts:
        return False
    *parents, base = parts
    return (
        _product_key(base) in keys
        or any(_names_bundle(part, keys) for part in dict.fromkeys(parents))
        or _in_ambiguous_context(folded)
    )


def _below_home(parts: list[str]) -> list[str] | None:
    """The case-folded path components ``parts`` below the home directory they start
    at (see _HOME_COMPONENTS), or None when they start at none."""
    if parts and _WINDOWS_DRIVE.fullmatch(parts[0]):
        parts = parts[1:]
    if not parts:
        return None
    if parts[0].startswith("~") or parts[0] in _HOME_COMPONENTS:
        return parts[1:]
    if (parts[0] in _HOME_PARENTS and len(parts) > 1) or parts[:2] == ["var", "root"]:
        return parts[2:]
    return None


def _holds_store_layout(parts: list[str], root: tuple[str, ...], layout: str) -> bool:
    """Whether the case-folded path components ``parts`` hold the model store directory
    ``root`` with that store's own layout below it: Ollama's ``manifests`` or ``blobs``, a
    Hugging Face hub ``models--<org>--<name>`` directory, or for any other store a model
    file (MODEL_FILE_SUFFIXES)."""
    length, run = len(root), list(root)
    starts = [
        start for start, part in enumerate(parts) if part == run[0] and parts[start : start + length] == run
    ]
    if not starts:
        return False
    if layout == "files":
        # Whatever lies below a later run of ``root`` lies below the first one too.
        return any(part.endswith(MODEL_FILE_SUFFIXES) for part in parts[starts[0] + length :])
    following = {parts[start + length] for start in starts if start + length < len(parts)}
    if layout == "ollama":
        return not _OLLAMA_STORE_DIRECTORIES.isdisjoint(following)
    return any(name.startswith("models--") for name in following)


def _in_model_store(parts: list[str]) -> bool:
    """Whether the path whose case-folded components are ``parts`` is, or lies in, one
    of the catalog's model stores.

    A store counts at the place the catalog lists it, below a home directory
    (``~/.ollama/models``, ``/Users/u/.cache/lm-studio/models/...``,
    ``C:\\Users\\u\\.cache\\huggingface\\hub``, ``/home/u/jan/models``). Elsewhere on a
    path its directory counts only with the store's own layout below it
    (``/usr/share/ollama/.ollama/models/blobs/...``, a ``.gguf`` file in a ``jan/models``
    directory): an application's ``jan/models`` directory, or a user named jan with a
    ``models`` directory, is not a model store.
    """
    below_home = _below_home(parts) or []
    return any(
        tuple(below_home[: len(root)]) == root or _holds_store_layout(parts, root, layout)
        for root, layout in _MODEL_STORE_ROOTS
    )


class HostConnector(_EndpointConnector):
    name = "endpoint.host"
    provider = "host"
    description = "Offline host inventory of local AI agents, MCP clients, and model runtimes."
    config_keys = {
        "input": (
            "Offline host inventory JSON, JSONL, or YAML export; rows are reported when the "
            "name or path matches an AI product signature, the whole application or executable "
            "name is a known AI product, local model runtime or self-hosted AI platform (Ollama, "
            "LM Studio, GPT4All, llama.cpp, vLLM, LocalAI, Jan, Msty, Open WebUI, AnythingLLM, "
            "LiteLLM, ...), the path lies in a local model store (~/.ollama/models, ...), or the "
            "record's type/category names an AI category (ai, agent, assistant, copilot, llm, "
            "mcp, model)."
        )
    }
    # Whether rows without a recognized AI product were noted (one fixed-text note).
    _skipped_records = False
    # Keys of the AI products a row may name as a whole (see _host_product_keys).
    _product_keys: frozenset[str] | None = None

    def _names_ai_product(self, record: dict[str, Any]) -> bool:
        """Whether the row's name, path or process names, as a whole, a known AI product,
        or is a path in a local model store.

        osquery ``apps``/``programs`` and MDM rows carry an application or executable
        name (``LM Studio.app``, ``/usr/local/bin/ollama``, ``Ollama version 0.5.7``) and
        no category, and local runtime signatures have no display-name signal. Each value
        is read up to _MAX_HOST_PATH characters and split once, and only its components of
        up to _MAX_LABEL characters are keyed, so a row costs time linear in that bound.
        """
        if self._product_keys is None:
            self._product_keys = _host_product_keys(self.index)
        for key in ("name", "path", "process"):
            parts, folded = _path_parts(self._text(record.get(key), _MAX_HOST_PATH))
            if _names_product(parts, folded, self._product_keys) or _in_model_store(folded):
                return True
        return False

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        for record in records:
            name = self._text(record.get("name") or record.get("path") or record.get("process"))
            category = self._text(record.get("type") or record.get("category") or "host-runtime")
            if not name:
                self.ctx.warn("endpoint.host: record has no runtime or configuration name")
                continue
            # A general software inventory names every installed product; a row
            # becomes a finding only when something ties it to AI: a product
            # name or configuration path a signature recognizes, the whole name
            # of a known AI product or local runtime, or an AI category the
            # collector declared.
            relevant = (
                bool(name_matches(self.index, name))
                or _ai_category(category)
                or self._names_ai_product(record)
            )
            if not relevant:
                path = self._text(record.get("path") or record.get("name"))
                relevant = bool(self.index.match_file(path.lstrip("~"))) if path else False
            if not relevant:
                if not self._skipped_records:
                    self._skipped_records = True
                    self.ctx.warn(
                        "endpoint.host: inventory rows without a recognized AI product name, "
                        "path or category were not reported",
                        incomplete=False,
                    )
                self.ctx.examined()
                continue
            yield self._finding(
                name,
                category,
                f"Host AI runtime or client: {name}",
                provider=self._text(record.get("provider")) or None,
                tags=("host-runtime",),
                metadata={"source": self._text(record.get("source"))} if record.get("source") else {},
            )


class MCPInventoryConnector(_EndpointConnector):
    # Unlike its siblings this one does reach the network, probing the Agent
    # Card URLs it is given; without them it falls back to the inventory.
    live_collection: ClassVar[bool] = True
    name = "endpoint.mcp"
    provider = "mcp"
    description = (
        "MCP and A2A endpoint inventory: offline MCP tool-list exports and opt-in A2A Agent Card probes."
    )
    config_keys = {
        "input": "Offline MCP list-responses JSON / JSONL export, or A2A card records from --dump-records.",
        "agent_card_urls": (
            "opt-in live probe: list of HTTPS A2A Agent Card URLs or agent origins; an origin is probed at "
            "/.well-known/agent-card.json (then /.well-known/agent.json on 404); URLs inside a card are "
            "never fetched; refused together with input"
        ),
        "max_agent_cards": (
            "maximum number of agent_card_urls (default 100); a longer list is refused, never truncated"
        ),
        "agent_card_jwks_url": (
            "optional operator-trusted HTTPS JWKS endpoint that verifies Agent Card signatures; keys or key "
            "URLs named by a card are never used"
        ),
        "ca_bundle": (
            "optional PEM file trusted instead of the default CA store for Agent Card and JWKS endpoints "
            "(private CA)"
        ),
    }

    def __init__(self, ctx: ConnectorContext) -> None:
        super().__init__(ctx)
        self._card_urls = a2a.agent_card_urls(ctx.get("agent_card_urls"), ctx.get("max_agent_cards"))
        if self._card_urls and self.offline:
            # A replay never probes: the listed agents would silently go unchecked.
            raise ConnectorError(
                "endpoint.mcp: input replays an export and never probes agent_card_urls; set one or the other"
            )
        jwks_url = ctx.get("agent_card_jwks_url")
        self._card_jwks_url = None if jwks_url is None else a2a.https_url(jwks_url, "agent_card_jwks_url")
        # The operator's key set, fetched once per run on first use; False after a failed fetch.
        self._card_keys: dict[str, Any] | bool | None = None

    def collect(self) -> Iterable[dict[str, Any]]:
        if not self._card_urls:
            return super().collect()
        return self._probe_cards()

    def _probe_cards(self) -> Iterator[dict[str, Any]]:
        """Fetch each configured card; every failure is an error and the scan is incomplete."""
        ca_bundle = self.ctx.get("ca_bundle")
        for url in self._card_urls:
            self.ctx.check_deadline()
            origin = diagnostic_url(url)
            try:
                card_url, card = a2a.fetch_card(url, ca_bundle=ca_bundle)
            except Exception as exc:  # noqa: BLE001 - one unreachable agent must not stop the others
                self.ctx.error(
                    f"endpoint.mcp: A2A Agent Card fetch from {origin} failed ({failure_summary(exc)})"
                )
                continue
            if not isinstance(card, dict):
                self.ctx.error(f"endpoint.mcp: A2A Agent Card from {origin} is not a JSON object")
                continue
            yield {
                "record_type": a2a.RECORD_TYPE,
                "card_url": card_url,
                "card_path": urlsplit(card_url).path,
                "card": card,
            }

    def _export_record(self, record: dict[str, Any]) -> dict[str, Any]:
        if record.get("record_type") == a2a.RECORD_TYPE and isinstance(record.get("card"), dict):
            return {**record, "card": a2a.export_card(record["card"])}
        return record

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        names_by_server: dict[str, set[str]] = defaultdict(set)
        server_auth: dict[str, str] = {}
        server_tls: dict[str, bool] = {}
        staged: list[tuple[str, dict[str, Any]]] = []
        count = 0
        limit_hit = False
        for record in records:
            # Tool-list records have no discriminator; any record that names a
            # type is a card or unsupported, never read as an MCP server.
            if "record_type" in record:
                if record["record_type"] == a2a.RECORD_TYPE:
                    card_finding = self._card_finding(record)
                    if card_finding is not None:
                        yield card_finding
                else:
                    self.ctx.warn("endpoint.mcp: unsupported record_type")
                continue
            server = self._text(record.get("server") or record.get("name") or record.get("url"))
            if not server:
                self.ctx.warn("endpoint.mcp: record has no server identifier")
                continue
            auth = record.get("auth") or record.get("auth_mode")
            server_auth[server] = self._text(auth).casefold() if isinstance(auth, str) else ""
            endpoint = self._text(record.get("url") or server).lower()
            server_tls[server] = endpoint.startswith("https://")
            tools = record.get("tools", [])
            if not isinstance(tools, list):
                self.ctx.warn("endpoint.mcp: malformed tools list")
                continue
            if len(tools) > _MAX_TOOLS:
                self.ctx.warn("endpoint.mcp: tool limit reached")
                tools = tools[:_MAX_TOOLS]
            for tool in tools:
                if not isinstance(tool, dict):
                    self.ctx.warn("endpoint.mcp: malformed tool definition")
                    continue
                if count >= _MAX_TOOLS:
                    self.ctx.warn("endpoint.mcp: aggregate tool limit reached")
                    limit_hit = True
                    break
                count += 1
                name = self._text(tool.get("name"))
                if not name:
                    self.ctx.warn("endpoint.mcp: tool has no valid name")
                    continue
                if name:
                    names_by_server[server].add(name.casefold())
                staged.append((server, tool))
            if limit_hit:
                break

        for server, tool in staged:
            name = self._text(tool.get("name")) or "unnamed-tool"
            description = tool.get("description", "")
            malformed_description = not isinstance(description, str)
            if malformed_description:
                description = ""
            # A description is not a SKILL.md: a leading "---" is text, not front matter.
            audit = audit_skill_text(description, front_matter=False)
            if malformed_description:
                audit = replace(
                    audit, incomplete=True, limitations=(*audit.limitations, "Tool description is not text.")
                )
            if audit.incomplete:
                self.ctx.warn("endpoint.mcp: tool description instruction audit incomplete")
            content_hits = inspect_instruction_text(description)
            # Terminal control characters (ESC sequences, a lone carriage
            # return, C1 controls) can conceal or overwrite what an operator
            # reads. Line breaks and tabs are ordinary formatting.
            plain = description.replace("\r\n", "\n").replace("\n", "").replace("\t", "")
            terminal_escape = any(ord(ch) < 32 or 0x7F <= ord(ch) <= 0x9F for ch in plain)
            # Search the same window the instruction audit inspects, not a shorter prefix:
            # padding ahead of an <IMPORTANT> block, a URL or a tool reference must not hide
            # it. These patterns are linear, so a bounded window keeps the scan bounded; a
            # description past the window already makes ``audit`` incomplete above.
            desc = self._text(description, MAX_TEXT_BYTES)
            tags: list[str] = []
            if (
                _POISONING.search(desc)
                or _ZERO_WIDTH.search(desc)
                or _TOOL_REF.search(desc)
                or _HOST.search(desc)
                or audit.indicators
                or any(hit.rule != "invisible-characters" for hit in content_hits)
                or terminal_escape
            ):
                tags.append("tool-poisoning")
            for content_tag in dict.fromkeys(hit.tag for hit in content_hits):
                if content_tag not in tags:
                    tags.append(content_tag)
            if any(name.casefold() in tools for other, tools in names_by_server.items() if other != server):
                tags.append("tool-name-shadowing")
            auth = self._text(tool.get("auth") or tool.get("auth_mode")).casefold()
            auth = auth or server_auth.get(server, "")
            if auth in {"", "none", "unauthenticated"}:
                tags.append("unauthenticated-mcp")
            words = set(re.findall(r"[a-z]+", name.casefold()))
            capabilities = []
            if words & {"exec", "execute", "shell", "command", "terminal"}:
                capabilities.append("code-exec")
            if words & {"file", "read", "write", "directory", "filesystem"}:
                capabilities.append("data-access")
            if words & {"fetch", "http", "web", "search", "browser"}:
                capabilities.append("browsing")
            if words & {"slack", "email", "ticket", "issue", "send", "publish"}:
                capabilities.append("saas-actions")
            finding = self._finding(
                f"{server}/{name}",
                "mcp-tool",
                f"MCP tool {name} on {self._text(server)}",
                kind=Kind.MCP_SERVER,
                tags=tags,
                capabilities=capabilities,
                metadata={
                    "server": server,
                    "tool": name,
                    "tool_definition_sha256": hashlib.sha256(
                        json.dumps(tool, sort_keys=True, separators=(",", ":"), default=str).encode()
                    ).hexdigest(),
                    "tls": server_tls.get(
                        server, self._text(tool.get("url") or server).lower().startswith("https://")
                    ),
                    "static_instruction_audit": audit.to_metadata(),
                },
                weight=0.8 if tags else 0.65,
            )
            for indicator in audit.indicators:
                finding.add_evidence(
                    Evidence(
                        signal=f"instruction:{indicator.rule}",
                        description=indicator.description,
                        location=f"description:{indicator.line}",
                        weight=0.0,
                        attributes={"category": "static-instruction-audit", "rule": indicator.rule},
                    )
                )
            for hit in content_hits:
                finding.add_evidence(
                    Evidence(
                        signal=f"instruction:{hit.rule}",
                        description=hit.detail,
                        location=f"description:{hit.line}",
                        weight=0.0,
                        attributes={"category": "static-instruction-audit", "rule": hit.rule},
                    )
                )
            if terminal_escape:
                finding.add_evidence(
                    Evidence(
                        signal="instruction:terminal-escape",
                        description="Tool description holds terminal control or concealing characters",
                        location="description",
                        weight=0.0,
                        attributes={"category": "static-instruction-audit", "rule": "terminal-escape"},
                    )
                )
            yield finding

    # ------------------------------------------------------------ A2A cards
    def _card_finding(self, record: dict[str, Any]) -> Finding | None:
        """One finding per fetched or replayed card; the card is re-validated, never trusted."""
        url, card = record.get("card_url"), record.get("card")
        if not isinstance(card, dict):
            self.ctx.warn("endpoint.mcp: A2A card record has no card object")
            return None
        try:
            resource = a2a.card_resource(a2a.https_url(url, "card_url"))
        except ConnectorError:
            self.ctx.warn("endpoint.mcp: A2A card record has no valid HTTPS card_url")
            return None
        origin = diagnostic_url(resource)
        self.ctx.examined()
        validation = validate_agent_manifest(card, "a2a")
        if not validation.valid:
            state = "incomplete" if validation.incomplete else "invalid"
            self.ctx.error(
                f"endpoint.mcp: {state} A2A Agent Card at {origin}: {'; '.join(validation.errors)}"
            )
            if not validation.incomplete:
                return None
        signature, signed = self._card_signature(card)
        # A verified card is read as its signature covers it: the served card may carry empty
        # values the signer dropped (an empty securitySchemes entry), and they decide nothing.
        read = card if signed is None else signed
        try:
            # Whole-document context recognizes an opaque secret from its siblings.
            shown = sanitize(read)
        except (SanitizationLimitError, RecursionError):
            self.ctx.error(
                f"endpoint.mcp: A2A Agent Card at {origin} omitted: sanitization safety limit exceeded"
            )
            return None
        if a2a_unsupported_protocol_version(card):
            self.ctx.warn(
                f"endpoint.mcp: A2A Agent Card at {origin} declares a protocol version other than "
                "0.x or 1.x; its fields were read as A2A 0.3 and 1.0 fields"
            )
        agent_card = a2a_card_metadata(read, shown, signature)
        name = self._text(agent_card["name"]) or resource
        prefix = "Incomplete A2A Agent Card" if validation.incomplete else "A2A Agent Card"
        finding = Finding(
            surface=self.surface,
            connector=self.name,
            kind=Kind.AGENT,
            title=self._text(f"{prefix}: {name}", 300),
            resource=resource,
            resource_type="a2a-agent-card",
            provider="a2a",
            identity_discriminator="a2a-card",
            metadata={"agent_card": agent_card, "card_path": urlsplit(resource).path},
        )
        finding.add_framework("protocol.a2a")
        if validation.valid:
            finding.add_capability("multi-agent")
        finding.add_evidence(
            Evidence(
                signal="a2a:card-probe",
                description=f"A2A Agent Card served at {origin}",
                location=resource,
                weight=0.95 if validation.valid else 0.6,
                signature="protocol.a2a",
            )
        )
        finding.add_evidence(
            Evidence(
                signal="a2a:card-signature",
                description=_SIGNATURE_EVIDENCE[agent_card["signature"]],
                location=resource,
                weight=0.0,
            )
        )
        for interface in agent_card["interfaces"]:
            apply_matches(finding, self.index.match_domains_in_text(interface["url"]), location=resource)
        for tag in a2a_card_tags(read, agent_card["signature"]):
            finding.add_tag(tag)
        finalize(finding, self.index)
        if validation.incomplete:
            # Evidence of the protocol, never of an agent; its errors keep the scan incomplete.
            finding.kind = Kind.FRAMEWORK_USAGE
            finding.add_tag("incomplete-agent-card")
            finding.metadata["card_errors"] = list(validation.errors)
        else:
            finding.kind = Kind.AGENT
        return finding

    def _card_signature(self, card: dict[str, Any]) -> tuple[tuple[str, str | None], dict[str, Any] | None]:
        """The card's signature ``(state, reason)``, verified against the operator's key set when one
        is configured, and the form of the card a verified signature covers (None otherwise)."""
        state, reason = a2a_signature_state(card)
        if state != "present-unverified" or self._card_jwks_url is None:
            return (state, reason), None
        if self.offline and REDACTED in json.dumps(card, ensure_ascii=False, default=str):
            # --dump-records sanitized part of the card or its signatures, so the
            # replayed card is no longer what was signed.
            return ("present-unverified", "the export redacted part of the card; signature not checked"), None
        try:
            forms = a2a.signed_forms(card)
        except CanonicalizationError as exc:
            return ("invalid", str(exc)), None
        keys = self._trusted_card_keys()
        if keys is None:
            return ("present-unverified", "operator-trusted keys unavailable; signature not checked"), None
        state, reason, signed = a2a.verify_card(card, forms, keys)
        return (state, reason), signed

    def _trusted_card_keys(self) -> dict[str, Any] | None:
        """Fetch the operator's JWKS once per run; a failure is recorded once and the scan is incomplete."""
        if self._card_keys is None:
            try:
                self._card_keys = fetch_jwks(str(self._card_jwks_url), ca_bundle=self.ctx.get("ca_bundle"))
            except Exception as exc:  # noqa: BLE001 - remembered so every card reports the same outcome
                self.ctx.error(
                    f"endpoint.mcp: agent_card_jwks_url could not be read ({failure_summary(exc)}); "
                    "Agent Card signatures stay unverified"
                )
                self._card_keys = False
        return self._card_keys if isinstance(self._card_keys, dict) else None


_SIGNATURE_EVIDENCE = {
    "absent": "card is not signed",
    "present-unverified": "card signature present but NOT verified (no operator-trusted key set checked it)",
    "verified": "card signature verified against the operator-trusted key set (agent_card_jwks_url)",
    "invalid": "card signature is malformed or does not verify against the operator-trusted key set",
}


class OtelConnector(_EndpointConnector):
    name = "gateway.otel"
    surface = Surface.GATEWAY
    provider = "opentelemetry"
    description = "Aggregate OpenTelemetry GenAI span exports without retaining prompt content."
    config_keys = {"input": "Offline OTLP JSON / JSONL span export."}
    uses_run_identity_key = True

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        groups: dict[tuple[str, str, str], dict[str, Any]] = {}
        for record in _records(records, self.ctx.warn):
            attrs = _attrs(record.get("attributes"), self.ctx.warn)
            resource = record.get("resource")
            if isinstance(resource, dict):
                attrs = {**_attrs(resource.get("attributes"), self.ctx.warn), **attrs}
            service = self._text(attrs.get("service.name") or record.get("serviceName") or "unknown-service")
            agent = self._text(attrs.get("gen_ai.agent.name") or attrs.get("agent.name") or service)
            model = self._text(attrs.get("gen_ai.request.model") or attrs.get("llm.request.model"))
            system = self._text(attrs.get("gen_ai.system") or attrs.get("llm.provider"))
            if not (model or system or "gen_ai.operation.name" in attrs or "llm.operation.name" in attrs):
                continue
            key = (service, agent, system or "unknown")
            aggregate = groups.setdefault(key, {"models": set(), "operations": set(), "count": 0})
            if model:
                aggregate["models"].add(model)
            op = self._text(attrs.get("gen_ai.operation.name") or attrs.get("llm.operation.name"))
            if op:
                aggregate["operations"].add(op)
            aggregate["count"] += 1
            self.ctx.examined()
        for (service, agent, provider), aggregate in groups.items():
            models = sorted(aggregate["models"])[:100]
            yield self._finding(
                f"service:{service}/agent:{agent}",
                "gateway-caller",
                f"Observed GenAI caller {agent} ({service})",
                kind=Kind.GATEWAY_CALLER,
                provider=provider,
                metadata={"models": models, "span_count": aggregate["count"]},
                weight=0.75,
            )


class OllamaConnector(_EndpointConnector):
    name = "endpoint.ollama"
    provider = "ollama"
    description = "Inventory local LLM server and model exports."
    config_keys = {"input": "Offline /api/version, /api/tags, /api/ps JSON export."}

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        for record in records:
            models = record.get("models")
            if not isinstance(models, list):
                if "models" in record:
                    self.ctx.warn("endpoint.ollama: malformed model inventory")
                    continue
                if any(key in record for key in ("version", "processes")):
                    models = []
                else:
                    self.ctx.warn("endpoint.ollama: malformed model inventory")
                    continue
            if len(models) > 500:
                self.ctx.warn("endpoint.ollama: model limit reached")
            endpoint = self._text(record.get("endpoint") or record.get("url") or "local Ollama")
            tags = ["local-llm-runtime"]
            host = self._text(record.get("host") or record.get("endpoint") or record.get("url")).lower()
            if host and not any(x in host for x in ("localhost", "127.0.0.1", "::1")):
                tags.append("exposed-llm-server")
            for model in models[:500]:
                if not isinstance(model, dict):
                    self.ctx.warn("endpoint.ollama: malformed model entry")
                    continue
                model_name = self._text(model.get("name") or model.get("model"))
                if not model_name:
                    continue
                yield self._finding(
                    f"{endpoint}/model/{model_name}",
                    "local-model",
                    f"Local LLM model {model_name}",
                    provider="ollama",
                    tags=tags,
                    metadata={"size": model["size"]} if type(model.get("size")) is int else {},
                    weight=0.75,
                )
            self.ctx.examined()


class ModelArtifactConnector(_EndpointConnector):
    name = "endpoint.models"
    provider = "local-model"
    description = "Analyze bounded metadata exports for local model artifacts."
    config_keys = {
        "input": "Offline artifact metadata JSON / JSONL; only GGUF header metadata should be exported.",
    }

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        for record in records:
            raw_path = record.get("path") or record.get("name")
            path = sanitize_text(raw_path) if isinstance(raw_path, str) else ""
            if not path:
                self.ctx.warn("endpoint.models: artifact record has no path")
                continue
            extension = path.rsplit(".", 1)[-1].lower() if "." in path else ""
            tags = ["local-model-artifact"]
            if extension in {"pt", "bin", "pkl", "pickle"}:
                tags.append("unsafe-serialization")
            meta = record.get("metadata")
            metadata: dict[str, Any] = {"format": extension}
            if isinstance(meta, dict):
                metadata.update(
                    {
                        key: self._text(meta[key])
                        for key in ("general.architecture", "general.name", "general.license")
                        if isinstance(meta.get(key), str)
                    }
                )
            elif meta is not None:
                self.ctx.warn("endpoint.models: malformed artifact metadata")
            size = record.get("size")
            if type(size) is int and 0 <= size < 2**63:
                metadata["size"] = size
            elif size is not None:
                self.ctx.warn("endpoint.models: malformed artifact size")
            digest = record.get("sha256")
            if isinstance(digest, str) and re.fullmatch(r"[0-9a-fA-F]{64}", digest):
                metadata["sha256"] = digest.lower()
            elif digest is not None:
                self.ctx.warn("endpoint.models: malformed artifact digest")
            yield self._finding(
                path,
                "model-artifact",
                f"Local model artifact {path.rsplit('/', 1)[-1]}",
                tags=tags,
                metadata=metadata,
                weight=0.8,
            )


# endpoint.ebpf reads each producer's native export shape. A helper returns the
# flat record ``EbpfConnector.analyze`` scores, or ``None`` when the record is
# not that producer's format, and notes in ``defects`` the fields it could not
# read. Field names follow the producers' published schemas; where exporters
# differ, both snake_case and lowerCamelCase spellings are read. A record no
# reader recognizes is reported, not silently dropped: an export full of unread
# events must not look like a clean scan.

# The flat shape ``analyze`` scores, also accepted directly as an export format.
_EBPF_FLAT_KEYS = frozenset(
    {
        "destination",
        "remote_addr",
        "hostname",
        "server.address",
        "url",
        "binary",
        "process_name",
        "process",
        "port",
        "destination_port",
    }
)
# The flat fields that name where an event connected, scored for AI hosts.
_EBPF_DESTINATION_KEYS = ("destination", "remote_addr", "hostname", "server.address", "url")
# Tetragon wraps each event under its type (``tetra getevents -o json``).
_TETRAGON_EVENT_KEYS = (
    "process_kprobe",
    "processKprobe",
    "process_exec",
    "processExec",
    "process_exit",
    "processExit",
    "process_tracepoint",
    "processTracepoint",
    "process_lsm",
    "processLsm",
)
_EBPF_ARG_LIMIT = 100
# A port is a number or, in Tracee's sockaddr maps, its decimal text.
_EBPF_PORT = (int, str)
# Default ports of local model servers (Ollama, LM Studio, llama.cpp, vLLM), as text.
_LOCAL_MODEL_PORTS = frozenset({"11434", "1234", "8080", "8000"})
# What a reader could not read in a record it recognized: a field of the wrong
# type ("malformed"), or the entries of a list past _EBPF_ARG_LIMIT ("limit").
# Each is reported once per producer, the flat record shape included, and
# leaves the scan incomplete: a malformed or oversized export must not hide a
# connection on a scan that looks complete.
_EBPF_DEFECT_WARNINGS = {
    "malformed": "endpoint.ebpf: malformed {producer} event fields were not analyzed",
    "limit": "endpoint.ebpf: {producer} event list limit reached; entries past it were not analyzed",
}
# The incomplete_reasons category of each, named rather than read from the text.
_EBPF_DEFECT_REASONS = {"malformed": "unparsed-input", "limit": "analysis-limit"}


def _ebpf_field(
    container: dict[str, Any], keys: tuple[str, ...], kinds: type | tuple[type, ...], defects: set[str]
) -> Any:
    """The first non-empty value of ``keys`` in ``container`` that is of ``kinds``, or None.

    A value of another type, even an empty one, is not read: it is noted in
    ``defects`` as a malformed field. A JSON boolean is never of ``kinds``: no
    field is one, and ``bool`` subclasses ``int``, so ``true`` would pass as a port.
    An empty value of the right type carries nothing and is passed over.
    """
    for key in keys:
        value = container.get(key)
        if value is None:
            continue
        if not isinstance(value, kinds) or isinstance(value, bool):
            defects.add("malformed")
        elif value:
            return value
    return None


def _ebpf_list(container: dict[str, Any], key: str, defects: set[str]) -> list[Any]:
    """``container[key]`` cut to _EBPF_ARG_LIMIT entries; a malformed or cut list is noted in ``defects``."""
    value: list[Any] = _ebpf_field(container, (key,), list, defects) or []
    if len(value) > _EBPF_ARG_LIMIT:
        defects.add("limit")
    return value[:_EBPF_ARG_LIMIT]


def _tetragon_ebpf_record(record: dict[str, Any], defects: set[str]) -> dict[str, Any] | None:
    """Tetragon event: ``{"process_kprobe": {"process": {...}, "args": [...]}}``."""
    event = next(
        (record[key] for key in _TETRAGON_EVENT_KEYS if isinstance(record.get(key), dict)),
        None,
    )
    if event is None:
        return None
    process = _ebpf_field(event, ("process",), dict, defects) or {}
    pod = _ebpf_field(process, ("pod",), dict, defects) or {}
    destinations, ports = _tetragon_socket(_ebpf_list(event, "args", defects), defects)
    return {
        "process_name": _ebpf_field(process, ("binary",), str, defects) or "",
        "destination": destinations,
        "destination_port": ports,
        "namespace": _ebpf_field(pod, ("namespace",), str, defects) or "",
        "pod": _ebpf_field(pod, ("name",), str, defects) or "",
    }


# Tetragon's socket argument maps, and the destination address and port each carries.
_TETRAGON_SOCKETS = (
    (("sock_arg", "sockArg"), "daddr", "dport"),
    (("sockaddr_arg", "sockaddrArg"), "addr", "port"),
)


def _tetragon_socket(args: list[Any], defects: set[str]) -> tuple[tuple[str, ...], tuple[Any, ...]]:
    """Destination addresses and ports of every ``sock_arg`` and ``sockaddr_arg`` argument.

    A hook can take several, and the first need not hold the destination: the example
    TracingPolicy hooks ``tcp_v4_connect`` with ``[sock, sockaddr]``, and at kprobe entry
    the socket has no ``daddr`` or ``dport`` yet, while the ``sockaddr`` names the address
    being connected to.
    """
    addresses: list[str] = []
    ports: list[Any] = []
    for arg in args:
        if not isinstance(arg, dict):
            defects.add("malformed")
            continue
        for keys, address, port in _TETRAGON_SOCKETS:
            socket = _ebpf_field(arg, keys, dict, defects)
            if socket is not None:
                addresses.append(_ebpf_field(socket, (address,), str, defects))
                ports.append(_ebpf_field(socket, (port,), _EBPF_PORT, defects))
    return _present(addresses), _present(ports)


def _present(values: Iterable[Any]) -> tuple[Any, ...]:
    """The values that carry something (a reader's None and empty text drop out)."""
    return tuple(value for value in values if value)


def _each(value: Any) -> tuple[Any, ...]:
    """A reader's destination or port as the values to score: a reader passes several as a
    tuple, which no JSON or YAML export holds."""
    return value if isinstance(value, tuple) else (value,)


def _falco_ebpf_record(record: dict[str, Any], defects: set[str]) -> dict[str, Any] | None:
    """Falco JSON alert: dotted field names under ``output_fields``."""
    fields = record.get("output_fields")
    if not isinstance(fields, dict) or not ("rule" in record or "priority" in record):
        return None
    return {
        "process_name": _ebpf_field(fields, ("proc.name",), str, defects),
        "destination": _ebpf_field(fields, ("fd.sip.name", "fd.rip.name", "fd.sip", "fd.rip"), str, defects),
        "destination_port": _ebpf_field(fields, ("fd.sport", "fd.rport"), _EBPF_PORT, defects),
        "namespace": _ebpf_field(fields, ("k8s.ns.name",), str, defects),
        "pod": _ebpf_field(fields, ("k8s.pod.name",), str, defects),
    }


def _tracee_ebpf_record(record: dict[str, Any], defects: set[str]) -> dict[str, Any] | None:
    """Tracee event: ``eventName``/``processName`` with sockaddr maps in ``args``."""
    if not isinstance(record.get("eventName"), str):
        return None
    if "processName" not in record and "args" not in record:
        return None
    kubernetes = _ebpf_field(record, ("kubernetes",), dict, defects) or {}
    destinations, ports = _tracee_socket(_ebpf_list(record, "args", defects), defects)
    return {
        "process_name": _ebpf_field(record, ("processName",), str, defects),
        "destination": destinations,
        "destination_port": ports,
        "namespace": _ebpf_field(kubernetes, ("podNamespace",), str, defects)
        or _ebpf_field(record, ("podNamespace",), str, defects),
        "pod": _ebpf_field(kubernetes, ("podName",), str, defects)
        or _ebpf_field(record, ("podName",), str, defects),
    }


def _tracee_socket(args: list[Any], defects: set[str]) -> tuple[tuple[str, ...], tuple[Any, ...]]:
    """Destination addresses and ports of every sockaddr map among the event's arguments."""
    addresses: list[str] = []
    ports: list[Any] = []
    for arg in args:
        if not isinstance(arg, dict):
            defects.add("malformed")
            continue
        value = _tracee_sockaddr(arg, defects)
        if isinstance(value, dict) and ("sin_addr" in value or "sin6_addr" in value):
            addresses.append(_ebpf_field(value, ("sin_addr", "sin6_addr"), str, defects))
            ports.append(_ebpf_field(value, ("sin_port", "sin6_port"), _EBPF_PORT, defects))
    return _present(addresses), _present(ports)


def _tracee_sockaddr(arg: dict[str, Any], defects: set[str]) -> Any:
    """A Tracee argument's value when it may be a sockaddr map.

    An argument Tracee declares a socket address (``remote_addr``, or a
    ``struct sockaddr*`` type) whose value is not a map is malformed: its
    destination cannot be read. Any other argument is a sockaddr map only when its
    value is a map holding an address.
    """
    name = _ebpf_field(arg, ("name",), str, defects) or ""
    kind = _ebpf_field(arg, ("type",), str, defects) or ""
    if name == "remote_addr" or "sockaddr" in kind:
        return _ebpf_field(arg, ("value",), dict, defects)
    return arg.get("value")


def _hubble_ebpf_record(record: dict[str, Any], defects: set[str]) -> dict[str, Any] | None:
    """Hubble flow: the ``hubble observe -o json`` wrapper, or a bare flow."""
    flow = record.get("flow")
    if not isinstance(flow, dict):
        bare = isinstance(record.get("IP"), dict) or (
            isinstance(record.get("l4"), dict) and ("verdict" in record or "source" in record)
        )
        if not bare:
            return None
        flow = record
    ip = _ebpf_field(flow, ("IP",), dict, defects) or {}
    address = _ebpf_field(ip, ("destination",), str, defects) or ""
    names = _ebpf_list(flow, "destination_names", defects)
    if not all(isinstance(name, str) for name in names):
        defects.add("malformed")
    # Every name the destination address was resolved from: a CDN-fronted
    # address carries several, and the AI host need not come first. A tuple,
    # which no JSON or YAML export holds, has ``analyze`` read each name.
    destinations = tuple(name for name in names if isinstance(name, str) and name)
    l4 = _ebpf_field(flow, ("l4",), dict, defects) or {}
    entry = _ebpf_field(l4, ("TCP", "UDP", "tcp", "udp", "SCTP"), dict, defects) or {}
    source = _ebpf_field(flow, ("source",), dict, defects) or {}
    return {
        "process_name": "",
        "destination": destinations or address,
        "destination_port": _ebpf_field(entry, ("destination_port",), _EBPF_PORT, defects),
        "namespace": _ebpf_field(source, ("namespace",), str, defects),
        "pod": _ebpf_field(source, ("pod_name",), str, defects),
    }


# The native readers, by the producer name their warnings carry.
_EBPF_READERS: tuple[tuple[str, Callable[[dict[str, Any], set[str]], dict[str, Any] | None]], ...] = (
    ("Tetragon", _tetragon_ebpf_record),
    ("Falco", _falco_ebpf_record),
    ("Tracee", _tracee_ebpf_record),
    ("Hubble", _hubble_ebpf_record),
)


# The flat fields that name a port an event connected to; every one is scored.
_EBPF_PORT_KEYS = ("port", "destination_port")
# The flat fields that say where a record connected.
_EBPF_FLAT_DESTINATION_KEYS = frozenset({*_EBPF_DESTINATION_KEYS, *_EBPF_PORT_KEYS})
# Top-level keys of a producer's own events that the flat shape also names: a
# Falco alert's ``hostname`` is the sensor's host, and a bare Hubble flow's
# ``destination`` is the destination endpoint, neither of them a flat destination.
_EBPF_PRODUCER_KEYS = {"Falco": frozenset({"hostname"}), "Hubble": frozenset({"destination"})}


def _flat_ebpf_record(
    record: dict[str, Any], defects: set[str], own: frozenset[str] = frozenset()
) -> dict[str, Any]:
    """Flat record: the field names other collectors export (_EBPF_FLAT_KEYS), read with
    the type checks the native readers apply.

    The process is a ``process`` map's ``binary`` or ``name``, else ``binary`` or
    ``process_name``; every destination field and every port field is scored. ``own``
    names the top-level keys that belong to the native producer whose event this is
    (_EBPF_PRODUCER_KEYS): they are not flat fields and are not read.
    """
    process = _ebpf_field(record, ("process",), dict, defects) or {}
    destinations = (
        _ebpf_field(record, (key,), str, defects) for key in _EBPF_DESTINATION_KEYS if key not in own
    )
    ports = (_ebpf_field(record, (key,), _EBPF_PORT, defects) for key in _EBPF_PORT_KEYS if key not in own)
    return {
        "process_name": _ebpf_field(process, ("binary", "name"), str, defects)
        or _ebpf_field(record, ("binary", "process_name"), str, defects),
        "destination": _present(destinations),
        "destination_port": _present(ports),
        "namespace": _ebpf_field(record, ("namespace",), str, defects),
        "pod": _ebpf_field(record, ("pod", "pod_name"), str, defects),
    }


def _combined_ebpf_record(native: dict[str, Any], flat: dict[str, Any]) -> dict[str, Any]:
    """A record's native and flat readings as one record to score: every destination and
    port either reading found, and the flat process and workload, with gaps filled from
    the native reading."""
    combined = {key: value or native.get(key) for key, value in flat.items()}
    for key in ("destination", "destination_port"):
        combined[key] = _present((*_each(flat[key]), *_each(native.get(key))))
    return combined


# A record to score and, for each reader that read it, the producer and what it
# could not read (see _EBPF_DEFECT_WARNINGS).
_EbpfReading = tuple[dict[str, Any], list[tuple[str, set[str]]]]


def _normalize_ebpf_record(record: dict[str, Any]) -> _EbpfReading | None:
    """The record to score and what each reader that read it could not read, or None for
    a record no reader recognizes.

    A flat record can carry a key a native reader claims: a string ``eventName`` beside
    ``processName`` reads as Tracee, ``rule`` beside an ``output_fields`` map as Falco.
    When the record also has flat destination or port fields, it is read both ways and
    scored on every destination and port either reading finds, so a top-level ``url``
    or ``destination`` is not lost beside a native reading that found only a port or a
    non-AI address. The producer's own top-level keys (_EBPF_PRODUCER_KEYS) are never
    read as flat fields: a Falco alert's ``hostname`` is the sensor, not a destination.
    """
    for producer, reader in _EBPF_READERS:
        defects: set[str] = set()
        native = reader(record, defects)
        if native is None:
            continue
        own = _EBPF_PRODUCER_KEYS.get(producer, frozenset())
        if (_EBPF_FLAT_DESTINATION_KEYS - own).isdisjoint(record):
            return native, [(producer, defects)]
        flat_defects: set[str] = set()
        flat = _flat_ebpf_record(record, flat_defects, own)
        return _combined_ebpf_record(native, flat), [(producer, defects), ("flat", flat_defects)]
    if _EBPF_FLAT_KEYS.intersection(record):
        defects = set()
        return _flat_ebpf_record(record, defects), [("flat", defects)]
    return None


class EbpfConnector(_EndpointConnector):
    name = "endpoint.ebpf"
    provider = "runtime-telemetry"
    description = "Correlate offline eBPF runtime events with known AI hosts and local model ports."
    config_keys = {"input": "Offline Tetragon, Falco, Tracee, or Hubble JSON / JSONL export (native shapes)."}
    # Whether an unrecognized record was reported (one fixed-text warning).
    _unrecognized_records = False
    # The (producer, defect) pairs already reported (one fixed-text warning each).
    _reported_defects: frozenset[tuple[str, str]] = frozenset()

    def _report_defects(self, producer: str, defects: set[str]) -> None:
        """Warn once per producer and defect: what a reader could not read leaves the scan incomplete."""
        for defect in sorted(defects):
            if (producer, defect) not in self._reported_defects:
                self._reported_defects |= {(producer, defect)}
                self.ctx.warn(
                    _EBPF_DEFECT_WARNINGS[defect].format(producer=producer),
                    reason=_EBPF_DEFECT_REASONS[defect],
                )

    def _destination_text(self, record: dict[str, Any]) -> str:
        """The record's destinations as one text to score, each value cut to 512 characters.

        A reader passes several destinations as a tuple (Hubble's ``destination_names``, a
        flat record's destination fields); each is read on its own, so none is cut off by
        those before it.
        """
        return " ".join(self._text(item, 512) for item in _each(record.get("destination")))

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        for raw in records:
            normalized = _normalize_ebpf_record(raw)
            if normalized is None:
                # The record was not analyzed, so the scan is incomplete; one
                # fixed-text warning however many records are unrecognized.
                if not self._unrecognized_records:
                    self._unrecognized_records = True
                    self.ctx.warn(
                        "endpoint.ebpf: unrecognized event records were not analyzed; supported "
                        "exports are Tetragon, Falco, Tracee, Hubble and the flat record shape",
                        reason="unparsed-input",
                    )
                continue
            record, readings = normalized
            # The event is still scored on what was read.
            for producer, defects in readings:
                self._report_defects(producer, defects)
            binary = self._text(record.get("process_name"))
            serialized = self._destination_text(record) + " " + binary
            lower = serialized.lower()
            ports = {str(port) for port in _each(record.get("destination_port")) if port}
            tags = []
            if _HOST.search(serialized) or any(host in lower for host in ("openai", "anthropic", "ollama")):
                tags.append("llm-egress")
            if not _LOCAL_MODEL_PORTS.isdisjoint(ports):
                tags.append("local-llm-traffic")
            if not tags:
                self.ctx.examined()
                continue
            pod = self._text(record.get("pod"))
            ns = self._text(record.get("namespace"))
            binary = binary or "runtime-process"
            yield self._finding(
                f"{ns}/{pod}/{binary}".strip("/"),
                "runtime-process",
                f"Runtime process {binary} communicated with an AI service",
                tags=tags,
                metadata={"namespace": ns, "pod": pod} if pod or ns else {},
                weight=0.75,
            )
