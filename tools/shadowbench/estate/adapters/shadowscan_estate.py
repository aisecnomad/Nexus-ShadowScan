"""ShadowScan run against the whole estate: one scan, all nine surfaces."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tools.discovery_benchmark import taxonomy as code_taxonomy
from tools.discovery_benchmark.adapters.shadowscan import (
    _IAC_BY_SLUG,
    _LOWCODE,
    _sdk_backed_protocols,
    _slug_facts,
)
from tools.shadowbench.estate import taxonomy
from tools.shadowbench.estate.adapters import (
    Command,
    Normalized,
    Prediction,
    ToolConfig,
    ToolSpec,
    load_json,
    run_version,
)
from tools.shadowbench.estate.corpus import EstateCorpus

SPEC = ToolSpec(
    id="shadowscan",
    name="ShadowScan (Project Nexus)",
    vendor="aisecnomad",
    surfaces=frozenset(taxonomy.SURFACES),
    categories=frozenset(taxonomy.CATEGORIES),
    notes="one offline scan over the whole estate with the agent registry supplied",
)

_GENERIC_CSV_FIELDS = {
    "name": "App Name",
    "scopes": "Permissions",
    "users": "Users",
    "owner": "Installed By",
    "url": "Domain",
}

_CLIENT_SLUGS = {
    "claude-code": "claude-code",
    "claude-desktop": "claude-desktop",
    "cursor": "cursor",
    "windsurf": "windsurf",
    "codex": "codex",
    "gemini-cli": "gemini-cli",
    "continue": "continue",
    "cline": "cline",
    "goose": "goose",
    "amazon-q": "amazon-q",
    "kiro": "generic",
    "lm-studio": "lm-studio",
    "copilot-cli": "copilot",
    "openclaw": "generic",
    "aider": "generic",
    "vscode": "generic",
}

_EXTENSION_SLUGS = {
    "github.copilot": "copilot",
    "github.copilot-chat": "copilot",
    "saoudrizwan.claude-dev": "cline",
    "rooveterinaryinc.roo-cline": "generic",
    "anthropic.claude-code": "claude-code",
    "continue.continue": "continue",
    "openai.chatgpt": "generic",
    "amazonwebservices.amazon-q-vscode": "amazon-q",
    "google.geminicodeassist": "generic",
}

_NETWORK_SLUGS = {
    "provider.anthropic": "anthropic",
    "provider.openai": "openai",
    "identity-app.openai-chatgpt": "openai",
    "provider.google-gemini": "gemini",
    "provider.ollama": "ollama",
    "provider.openrouter": "openrouter",
    "coding-agent.cursor": "cursor",
    "provider.aws-bedrock": "bedrock",
    "cloud.aws-bedrock-agents": "bedrock",
    "provider.mistral": "mistral",
}

_PROCESS_SLUGS = {
    "claude-code": "claude-code",
    "claude": "claude-code",
    "codex": "codex",
    "aider": "aider",
    "goose": "generic",
    "openclaw": "openclaw",
    "cursor-agent": "generic",
    "ollama": "ollama",
    "vllm": "vllm",
    "litellm": "litellm",
    "lm-studio": "generic",
    "lms": "generic",
    "open-webui": "generic",
    "crewai": "generic",
    "langgraph": "generic",
    "llama-server": "generic",
}

_MODEL_STORES = {"ollama", "lm-studio", "huggingface", "gpt4all"}

_LOWCODE_PLATFORMS = (
    ("power-platform:bot", "copilot-studio"),
    ("power-platform:", "power-automate"),
    ("salesforce:", "agentforce"),
    ("servicenow:", "now-assist"),
    ("n8n:", "n8n"),
    ("make:", "make"),
    ("zapier:", "zapier"),
    ("workato:", "workato"),
)

_CLOUD_TYPES = (
    # agentcore before bedrock-agent: "bedrock-agentcore" ARNs contain both tokens
    ("agentcore", "cloud-ai:agentcore"),
    ("bedrock-agent", "cloud-ai:bedrock-agent"),
    ("cognitive-services", "cloud-ai:azure-openai"),
    ("foundry", "cloud-ai:ai-foundry-agent"),
    ("assistant", "cloud-ai:ai-foundry-agent"),
    ("botservice", "cloud-ai:bot-service"),
    ("bot-service", "cloud-ai:bot-service"),
    ("reasoning-engine", "cloud-ai:vertex-agent"),
    ("dialogflow", "cloud-ai:dialogflow"),
    ("kubernetes", "cloud-ai:k8s-ai-workload"),
)


def _gateway_connectors(estate: Path) -> list[dict[str, Any]]:
    gateway = estate / "gateway"
    entries: list[dict[str, Any]] = []
    names = ("litellm_spend.jsonl", "bedrock_invocations.jsonl", "azure_openai_diag.json", "egress_proxy.log")
    for name in names:
        path = gateway / name
        if path.exists():
            entries.append({"name": "gateway.logs", "label": name.split(".")[0], "input": str(path)})
    otel = gateway / "otel_spans.json"
    if otel.exists():
        entries.append({"name": "gateway.otel", "input": str(otel)})
    return entries


def build_config(estate: Path) -> dict[str, Any]:
    """The estate scan config: every surface's connectors plus the registry."""
    connectors: list[dict[str, Any]] = []
    code_root = estate / "code"
    if code_root.is_dir():
        for repo in sorted(code_root.iterdir()):
            if repo.is_dir():
                connectors.append({"name": "code.filesystem", "path": str(repo), "label": repo.name})
    identity = estate / "identity"
    identity_entries: list[dict[str, Any]] = [
        {
            "name": "identity.okta",
            "input": str(identity / "okta_apps.json"),
            "org_url": "https://vantor.okta.com",
        },
        {"name": "identity.entra", "input": str(identity / "entra_graph.json"), "tenant_id": "vantor-tenant"},
        {
            "name": "identity.google-workspace",
            "input": str(identity / "google_tokens.json"),
            "customer": "C0vantor99",
        },
        {
            "name": "identity.auth0",
            "input": str(identity / "auth0_clients.json"),
            "domain": "vantor.eu.auth0.com",
        },
        {"name": "identity.jwt", "input": str(identity / "tokens.txt")},
    ]
    lowcode = estate / "lowcode"
    lowcode_entries: list[dict[str, Any]] = [
        {"name": "lowcode.power-platform", "input": str(lowcode / "power_platform.json")},
        {
            "name": "lowcode.salesforce",
            "input": str(lowcode / "salesforce.json"),
            "instance_url": "https://vantor.my.salesforce.com",
        },
        {
            "name": "lowcode.servicenow",
            "input": str(lowcode / "servicenow.json"),
            "instance": "https://vantor.service-now.com",
        },
        {"name": "lowcode.n8n", "input": str(lowcode / "n8n_workflows.json")},
        {"name": "lowcode.make", "input": str(lowcode / "make_scenarios.json")},
        {"name": "lowcode.zapier", "input": str(lowcode / "zapier_zaps.csv")},
        {"name": "lowcode.workato", "input": str(lowcode / "workato_recipes.json")},
    ]
    saas = estate / "saas"
    saas_entries: list[dict[str, Any]] = [
        {"name": "saas.slack", "input": str(saas / "slack.json")},
        {
            "name": "saas.microsoft-teams",
            "input": str(saas / "teams_apps.json"),
            "tenant_id": "vantor-tenant",
        },
        {
            "name": "saas.github-apps",
            "input": str(saas / "github_installations.json"),
            "org": "vantor-logistics",
        },
        {
            "name": "saas.atlassian",
            "input": str(saas / "atlassian_plugins.json"),
            "site": "https://vantor.atlassian.net",
        },
        {"name": "saas.notion", "input": str(saas / "notion_users.json")},
        {"name": "saas.zoom", "input": str(saas / "zoom_apps.json")},
        {
            "name": "saas.generic",
            "input": str(saas / "generic_apps.csv"),
            "platform": "google-marketplace",
            "fields": dict(_GENERIC_CSV_FIELDS),
        },
    ]
    cloud = estate / "cloud"
    cloud_entries: list[dict[str, Any]] = [
        {"name": "cloud.aws", "input": str(cloud / "aws_records.jsonl")},
        {"name": "cloud.gcp", "input": str(cloud / "gcp_records.jsonl")},
        {"name": "cloud.azure", "input": str(cloud / "azure_records.jsonl")},
        {
            "name": "cloud.kubernetes",
            "cluster": "vantor-prod",
            "input": str(cloud / "kubernetes_workloads.json"),
        },
    ]
    endpoint_entries: list[dict[str, Any]] = []
    home_root = estate / "home"
    if home_root.is_dir():
        for device in sorted(home_root.iterdir()):
            if not device.is_dir():
                continue
            for user in sorted(device.iterdir()):
                if user.is_dir():
                    endpoint_entries.append(
                        {"name": "endpoint.inventory", "path": str(user), "label": device.name}
                    )
    exports = estate / "endpoint-exports"
    for connector, name in (
        ("endpoint.mcp", "mcp_tool_inventory.json"),
        ("endpoint.ollama", "ollama_models.json"),
        ("endpoint.ebpf", "ebpf_events.json"),
    ):
        path = exports / name
        if path.exists():
            endpoint_entries.append({"name": connector, "input": str(path)})
    network_entries: list[dict[str, Any]] = []
    zeek = estate / "network" / "zeek"
    if zeek.is_dir():
        network_entries.append({"name": "network.logs", "label": "vantor-zeek", "input": str(zeek)})
    generic_dns = estate / "network" / "generic_dns.csv"
    if generic_dns.exists():
        network_entries.append({"name": "network.logs", "label": "vantor-dns", "input": str(generic_dns)})
    runtime_entries: list[dict[str, Any]] = []
    processes = estate / "runtime" / "processes.jsonl"
    if processes.exists():
        runtime_entries.append({"name": "runtime.processes", "input": str(processes), "label": "fleet"})

    groups = (identity_entries, _gateway_connectors(estate), lowcode_entries, saas_entries, cloud_entries)
    for group in groups:
        connectors.extend(entry for entry in group if Path(str(entry.get("input", ""))).exists())
    connectors.extend(endpoint_entries)
    connectors.extend(network_entries)
    connectors.extend(runtime_entries)

    config: dict[str, Any] = {
        "options": {"min_confidence": 0.2, "parallel": 2, "connector_timeout_seconds": 600},
        "connectors": connectors,
    }
    registry = estate / "registry" / "agents.yaml"
    if registry.exists():
        config["inventory"] = [str(registry)]
    return config


def _code_facts(finding: dict[str, Any]) -> set[str]:
    """The code-surface mapping, identical in behavior to the code benchmark's adapter."""
    kind = str(finding.get("kind", ""))
    facts: set[str] = set()
    if kind in {"secret", "token"}:
        return facts
    locations = [str(e.get("location") or "") for e in finding.get("evidence") or [] if isinstance(e, dict)]
    resource = str(finding.get("resource", ""))
    signatures = [str(s) for s in finding.get("frameworks") or []]
    providers = [str(s) for s in finding.get("model_providers") or []]
    if kind == "infra":
        for sig in signatures + providers:
            family, _, slug = sig.partition(".")
            if family in {"cloud", "provider"} and slug in _IAC_BY_SLUG:
                facts.add(_IAC_BY_SLUG[slug])
            elif family == "provider" and slug in {"aws-bedrock", "bedrock"}:
                facts.add("iac:bedrock")
            elif family == "provider" and slug == "azure-openai":
                facts.add("iac:azure-openai")
            elif family == "provider" and slug in {"vertex-ai", "google-vertex", "gcp-vertex-ai"}:
                facts.add("iac:vertex-ai")
            elif family in {"provider", "framework", "platform"}:
                facts.update(_slug_facts(sig))
    elif kind == "mcp-server":
        for path in [resource, *locations]:
            facts.update(
                f for f in code_taxonomy.facts_for_config_path(path) if f.startswith("mcp-client-config:")
            )
        for sig in signatures:
            if not sig.startswith("protocol."):
                facts.update(_slug_facts(sig))
    elif kind == "agent-config":
        for path in [resource, *locations]:
            facts.update(
                f for f in code_taxonomy.facts_for_config_path(path) if f.startswith("agent-config:")
            )
        if not facts:
            facts.add("agent-config:generic")
    elif kind == "workflow":
        for sig in signatures:
            family, _, slug = sig.partition(".")
            if family == "platform" and slug in _LOWCODE:
                facts.add(_LOWCODE[slug])
            else:
                facts.update(_slug_facts(sig))
        for sig in providers:
            facts.update(_slug_facts(sig))
    else:
        sdk_backed = _sdk_backed_protocols(finding)
        capabilities = finding.get("capabilities") or []
        if isinstance(capabilities, list) and "mcp-server" in capabilities:
            facts.add("mcp:server")
        for sig in signatures:
            if sig == "protocol.a2a" and resource.endswith(".json"):
                facts.add("a2a:agent-card")
            elif sig.startswith("protocol.") and sig not in sdk_backed:
                continue
            else:
                facts.update(_slug_facts(sig))
        for sig in providers:
            facts.update(_slug_facts(sig))
    return facts


def _product(finding: dict[str, Any]) -> str:
    text = " ".join(str(finding.get(key, "")) for key in ("title", "resource"))
    return taxonomy.product_slug(text) or taxonomy.GENERIC


def _identity_facts(finding: dict[str, Any]) -> set[str]:
    kind = str(finding.get("kind", ""))
    tags = {str(t) for t in finding.get("tags") or []}
    if kind == "oauth-grant":
        return {f"oauth-app:{_product(finding)}"}
    if kind == "service-identity":
        return {f"service-identity:{_product(finding)}"}
    if kind == "token":
        metadata = finding.get("metadata") or {}
        identity = str(metadata.get("identity_type", "")) if isinstance(metadata, dict) else ""
        if identity in {"service", "workload", "delegated-agent"}:
            return {f"token:{identity}"}
        if "identity:delegated-agent" in tags or "agent-claims" in tags:
            return {"token:delegated-agent"}
        if "identity:workload" in tags:
            return {"token:workload"}
        if "identity:service" in tags:
            return {"token:service"}
        return {"token:generic"}
    return set()


def _gateway_facts(finding: dict[str, Any]) -> set[str]:
    if str(finding.get("kind", "")) != "gateway-caller":
        return set()
    tags = {str(t) for t in finding.get("tags") or []}
    resource = str(finding.get("resource", ""))
    agentic = (
        str(finding.get("title", "")).lower().startswith("agentic")
        or bool(tags & {"agent-loop", "agent-runtime-api", "mcp-client"})
        # an OTel caller whose resource names a gen_ai agent is an agent caller
        or (resource.startswith("service:") and "/agent:" in resource)
    )
    return {"gateway-caller:agentic" if agentic else "gateway-caller:llm"}


def _lowcode_facts(finding: dict[str, Any]) -> set[str]:
    resource = str(finding.get("resource", ""))
    for prefix, platform in _LOWCODE_PLATFORMS:
        if resource.startswith(prefix):
            return {f"lowcode-agent:{platform}"}
    return {f"lowcode-agent:{taxonomy.GENERIC}"}


def _saas_facts(finding: dict[str, Any]) -> set[str]:
    kind = str(finding.get("kind", ""))
    if kind == "bot-app":
        return {f"bot-app:{_product(finding)}"}
    if kind == "oauth-grant":
        return {f"oauth-app:{_product(finding)}"}
    if kind == "service-identity":
        return {f"service-identity:{_product(finding)}"}
    return set()


def _cloud_facts(finding: dict[str, Any]) -> set[str]:
    if str(finding.get("kind", "")) in {"secret", "iam-grant"}:
        return set()
    resource_type = str(finding.get("resource_type", "")).lower()
    resource = str(finding.get("resource", "")).lower()
    for token, fact in _CLOUD_TYPES:
        if token in resource_type or token in resource:
            return {fact}
    return {f"cloud-ai:{taxonomy.GENERIC}"}


def _endpoint_facts(finding: dict[str, Any]) -> set[str]:
    kind = str(finding.get("kind", ""))
    resource = str(finding.get("resource", ""))
    resource_type = str(finding.get("resource_type", ""))
    if kind == "mcp-server":
        return {"mcp:server"}
    if kind == "local-model" or resource_type == "local-model":
        metadata = finding.get("metadata") or {}
        runtime = str(metadata.get("runtime", "")) if isinstance(metadata, dict) else ""
        slug = runtime if runtime in _MODEL_STORES else None
        if slug is None:
            lowered = (resource + " " + str(finding.get("title", ""))).lower()
            slug = next((s for s in _MODEL_STORES if s.replace("-", " ") in lowered or s in lowered), None)
        return {f"model-store:{slug or taxonomy.GENERIC}"}
    if resource_type in {"model-artifact"}:
        return {f"model-store:{taxonomy.GENERIC}"}
    if resource_type in {"runtime-process"}:
        return {f"agent-process:{taxonomy.GENERIC}"}
    if ":agent-config:" in resource or ":cli-usage:" in resource:
        client = resource.rsplit(":", 1)[-1]
        return {f"ai-client:{_CLIENT_SLUGS.get(client, taxonomy.GENERIC)}"}
    if ":ide-extension:" in resource:
        ext = resource.rsplit(":", 1)[-1]
        return {f"ai-client:{_EXTENSION_SLUGS.get(ext, taxonomy.GENERIC)}"}
    if ":browser-extension:" in resource:
        return {f"ai-client:{taxonomy.GENERIC}"}
    if kind in {"agent", "ai-app"}:
        return {f"ai-client:{taxonomy.GENERIC}"}
    return set()


def _network_facts(finding: dict[str, Any]) -> set[str]:
    if str(finding.get("kind", "")) != "network-contact":
        return set()
    metadata = finding.get("metadata") or {}
    service = str(metadata.get("service", "")) if isinstance(metadata, dict) else ""
    slug = _NETWORK_SLUGS.get(service)
    if slug is None:
        tail = service.rsplit(".", 1)[-1] if service else ""
        slug = _NETWORK_SLUGS.get(f"provider.{tail}", taxonomy.product_slug(tail) or taxonomy.GENERIC)
        if f"ai-service-contact:{slug}" not in _KNOWN_NETWORK_FACTS:
            slug = taxonomy.GENERIC
    return {f"ai-service-contact:{slug}"}


_KNOWN_NETWORK_FACTS = frozenset(
    f"ai-service-contact:{slug}"
    for slug in (
        "openai",
        "anthropic",
        "gemini",
        "bedrock",
        "mistral",
        "ollama",
        "openrouter",
        "cursor",
        "generic",
    )
)


def _runtime_facts(finding: dict[str, Any]) -> set[str]:
    if str(finding.get("kind", "")) != "runtime-process":
        return set()
    metadata = finding.get("metadata") or {}
    tool = str(metadata.get("tool", "")) if isinstance(metadata, dict) else ""
    if tool.startswith("mcp:"):
        return {"agent-process:mcp-server"}
    return {f"agent-process:{_PROCESS_SLUGS.get(tool, taxonomy.GENERIC)}"}


_SURFACE_MAPPERS = {
    "identity": _identity_facts,
    "gateway": _gateway_facts,
    "lowcode": _lowcode_facts,
    "saas": _saas_facts,
    "cloud": _cloud_facts,
    "endpoint": _endpoint_facts,
    "network": _network_facts,
    "runtime": _runtime_facts,
}


def _prediction_text(finding: dict[str, Any]) -> str:
    parts = [str(finding.get("resource", "")), str(finding.get("title", ""))]
    for item in finding.get("evidence") or []:
        if isinstance(item, dict):
            parts.append(str(item.get("location") or ""))
    metadata = finding.get("metadata") or {}
    if isinstance(metadata, dict):
        for key in ("client", "tool", "service", "host", "user", "hosts", "models"):
            value = metadata.get(key)
            if isinstance(value, list):
                parts.extend(str(v) for v in value[:8])
            elif value is not None:
                parts.append(str(value))
    return " ".join(part for part in parts if part)


class ShadowScanEstateAdapter:
    spec = SPEC

    def unavailable_reason(self, cfg: ToolConfig) -> str | None:
        return None if cfg.binary("shadowscan") else "no 'bin' configured for shadowscan"

    def version(self, cfg: ToolConfig) -> str:
        return run_version(
            [cfg.binary("shadowscan") or "shadowscan", "--version"], pattern=r"(\d+\.\d+\.\d+\S*)"
        )

    def units(self, cfg: ToolConfig, estate: Path, corpus: EstateCorpus) -> list[str]:
        return ["estate"]

    def commands(self, cfg: ToolConfig, unit: str, estate: Path, out_dir: Path) -> list[Command]:
        config = build_config(estate)
        (out_dir / "estate-config.json").write_text(json.dumps(config, indent=1) + "\n", encoding="utf-8")
        argv = (
            cfg.binary("shadowscan") or "shadowscan",
            "scan",
            "-c",
            str(out_dir / "estate-config.json"),
            "--format",
            "json",
            "-o",
            str(out_dir / "report.json"),
        )
        return [Command(argv, ok_exit_codes=frozenset({0, 3}))]

    def normalize(self, unit: str, out_dir: Path) -> Normalized:
        data = load_json(out_dir / "report.json")
        if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
            return Normalized(error="report.json missing or malformed")
        result = Normalized(raw_count=len(data["findings"]))
        summary = data.get("summary") or {}
        result.incomplete = not bool(summary.get("complete", False)) if isinstance(summary, dict) else True
        result.detail["summary"] = summary if isinstance(summary, dict) else {}
        for finding in data["findings"]:
            if not isinstance(finding, dict):
                continue
            surface = str(finding.get("surface", ""))
            metadata = finding.get("metadata") or {}
            servers = metadata.get("servers") if isinstance(metadata, dict) else None
            if (
                surface == "endpoint"
                and str(finding.get("kind")) == "mcp-server"
                and isinstance(servers, list)
            ):
                # One prediction per configured server, carrying its own identifiers,
                # so multi-server configs attribute to each server entity.
                shadow = finding.get("shadow")
                base = _prediction_text(finding)
                for server in servers:
                    if not isinstance(server, dict):
                        continue
                    text = " ".join(
                        str(part)
                        for part in (
                            base,
                            server.get("name", ""),
                            server.get("command", ""),
                            " ".join(str(a) for a in server.get("args") or []),
                            server.get("url", ""),
                        )
                        if part
                    )
                    result.predictions.append(
                        Prediction(
                            fact="mcp:server",
                            text=text,
                            surface="endpoint",
                            shadow=shadow if isinstance(shadow, bool) else None,
                        )
                    )
                continue
            if surface == "code":
                facts = _code_facts(finding)
            else:
                mapper = _SURFACE_MAPPERS.get(surface)
                facts = mapper(finding) if mapper else set()
            if not facts:
                continue
            shadow = finding.get("shadow")
            text = _prediction_text(finding)
            for fact in sorted(facts):
                result.predictions.append(
                    Prediction(
                        fact=fact,
                        text=text,
                        surface=surface,
                        shadow=shadow if isinstance(shadow, bool) else None,
                    )
                )
        return result
