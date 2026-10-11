"""ShadowScan (Project Nexus) on every surface, through its offline connectors.

Exact invocation: ``<python> -m shadowscan.cli scan -c <config.json> -f json -o report.json``
with ``PYTHONPATH`` set to the checkout named in ``tools.json`` (``repo``). The
config lists one connector per case:

==========  ====================  ==================================================================
surface     modality              connector and input conversion
==========  ====================  ==================================================================
identity    okta-export           ``identity.okta`` on ``apps.json`` with each app's ``grants/`` and
                                  ``tokens/`` files embedded as ``_grants``/``_tokens`` (its offline shape)
identity    entra-export          ``identity.entra`` on the four Graph ``value`` arrays concatenated,
                                  plus a ``roleMap`` record naming the Graph app role ids
gateway     litellm-export        ``gateway.logs`` on ``spend_logs.jsonl`` unchanged
gateway     bedrock-export        ``gateway.logs`` on ``model_invocation_logs.jsonl`` unchanged
lowcode     powerplatform-export  ``lowcode.power-platform`` on the environment, flow, app, bot and
                                  botcomponent ``value`` arrays concatenated
lowcode     n8n-export            ``lowcode.n8n`` on ``workflows.json`` unchanged
saas        slack-export          ``saas.slack`` on team, approved apps, members and requests concatenated
saas        github-export         ``saas.github-apps`` on ``installations.json`` unchanged
cloud       aws-export            ``cloud.aws`` on a JSONL of the CLI outputs re-keyed into its dumped
                                  record kinds (account, bedrock-agent, agentcore-*, lambda,
                                  sagemaker-endpoint, bedrock-knowledge-base); IAM roles are not
                                  converted (its offline IAM record needs pre-analysed policy fields)
cloud       k8s-export            ``cloud.kubernetes`` on ``workloads.json`` unchanged
endpoint    home                  ``endpoint.inventory`` with ``path`` = the case home
network     passive               ``network.logs`` on the ``zeek/`` directory
runtime     snapshot              ``runtime.processes`` on ``osqueryd_results.jsonl``
runtime     live                  ``runtime.processes`` reading ``/proc`` (no input)
==========  ====================  ==================================================================

Mapping rule: each finding's resource or metadata names the entity (Okta app
id, Entra ``app_id``, gateway ``caller``, Power Platform bot or flow id, n8n
workflow id, Slack app id, GitHub ``app_slug``, ARN or ``k8s:`` path, endpoint
``files``, network ``client``, runtime ``pids``). A finding is ``agent`` when
its kind is ``agent``, ``mcp-server`` or ``agent-config`` or its metadata
carries a non-empty ``agent_indicators`` list; otherwise ``llm``. Findings
whose resource cannot be mapped are kept in the raw output and ignored. An
incomplete scan (exit 3) is still normalized and flagged ``incomplete``.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from tools.nine_surface.contract import (
    AdapterResult,
    Entity,
    Invocation,
    MaterializedCase,
    RunResult,
    ToolEnv,
    base_env,
    relative_artifact,
    tail,
)

AGENT_KINDS = frozenset({"agent", "mcp-server", "agent-config"})
ROLE_IDS = {
    "810c84a8-4a9e-49e6-bf7d-12d183f40d01": "Mail.Read",
    "e2a3a72e-5f79-4c64-b1b1-878b674ecb07": "Mail.ReadWrite",
    "b633e1c5-b582-4048-a93e-9f11b44c7e96": "Mail.Send",
    "75359482-048d-4d94-b6cb-4a7ba79f1c5e": "Files.ReadWrite.All",
    "01d4889c-1287-42c6-ac1f-5d1e02578ef6": "Files.Read.All",
    "7ab1d382-f21e-4acd-a863-ba3e13f7da61": "Directory.Read.All",
    "df021288-bdef-4463-88db-98f22de89214": "User.Read.All",
    "9492366f-7969-46a4-8d15-ed1a20078fff": "Sites.ReadWrite.All",
    "798ee544-9d2d-430c-a058-570e29e34338": "Calendars.Read",
}


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _values(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    data = _load(path)
    rows = data.get("value", []) if isinstance(data, dict) else data
    return [r for r in rows if isinstance(r, dict)]


def _dump(path: Path, value: Any) -> Path:
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
    return path


def _jsonl(path: Path, rows: list[dict[str, Any]]) -> Path:
    path.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
    return path


def convert_okta(inputs: Path, work: Path) -> Path:
    apps = _values(inputs / "okta" / "apps.json")
    for app in apps:
        for key, folder in (("_grants", "grants"), ("_tokens", "tokens")):
            extra = inputs / "okta" / folder / f"{app.get('id')}.json"
            if extra.exists():
                app[key] = _values(extra)
    return _dump(work / "okta.json", apps)


def convert_entra(inputs: Path, work: Path) -> Path:
    records: list[dict[str, Any]] = [{"_kind": "roleMap", "roles": ROLE_IDS}]
    for coll in ("servicePrincipals", "applications", "oauth2PermissionGrants", "appRoleAssignments"):
        records += _values(inputs / "entra" / f"{coll}.json")
    return _dump(work / "entra.json", records)


def convert_power_platform(inputs: Path, work: Path) -> Path:
    records: list[dict[str, Any]] = []
    for coll in ("environments", "flows", "apps", "bots", "botcomponents"):
        records += _values(inputs / "power-platform" / f"{coll}.json")
    return _dump(work / "power_platform.json", records)


def convert_slack(inputs: Path, work: Path) -> Path:
    base = inputs / "slack"
    records: list[dict[str, Any]] = []
    team = _load(base / "team.info.json").get("team") if (base / "team.info.json").exists() else None
    if isinstance(team, dict):
        records.append({**team, "_kind": "team"})
    for file, key, kind in (
        ("admin.apps.approved.list.json", "approved_apps", "approved_app"),
        ("users.list.json", "members", "bot_user"),
        ("admin.apps.requests.list.json", "app_requests", "app_request"),
    ):
        if (base / file).exists():
            for item in _load(base / file).get(key, []):
                if isinstance(item, dict):
                    records.append({**item, "_kind": kind})
    return _dump(work / "slack.json", records)


def _aws_json(inputs: Path, rel: str) -> Any:
    path = inputs / "aws" / rel
    return _load(path) if path.exists() else {}


def convert_aws(inputs: Path, work: Path) -> Path:
    region = "us-east-1"
    identity = _aws_json(inputs, "sts/get-caller-identity.json")
    account = str(identity.get("Account", "123456789012"))
    records: list[dict[str, Any]] = [{"_kind": "account", "account": account, "regions": [region]}]
    for summary in _aws_json(inputs, "bedrock-agent/list-agents.json").get("agentSummaries", []):
        agent_id = summary["agentId"]
        detail = _aws_json(inputs, f"bedrock-agent/get-agent.{agent_id}.json").get("agent", summary)
        groups = _aws_json(inputs, f"bedrock-agent/list-agent-action-groups.{agent_id}.json")
        aliases = _aws_json(inputs, f"bedrock-agent/list-agent-aliases.{agent_id}.json")
        kbs = _aws_json(inputs, f"bedrock-agent/list-agent-knowledge-bases.{agent_id}.json")
        records.append(
            {
                **detail,
                "_kind": "bedrock-agent",
                "_region": region,
                "_action_groups": groups.get("actionGroupSummaries", []),
                "_aliases": aliases.get("agentAliasSummaries", []),
                "_knowledge_bases": kbs.get("agentKnowledgeBaseSummaries", []),
            }
        )
    for kb in _aws_json(inputs, "bedrock-agent/list-knowledge-bases.json").get("knowledgeBaseSummaries", []):
        detail = _aws_json(inputs, f"bedrock-agent/get-knowledge-base.{kb['knowledgeBaseId']}.json").get(
            "knowledgeBase", kb
        )
        records.append({**detail, "_kind": "bedrock-knowledge-base", "_region": region})
    for rt in _aws_json(inputs, "bedrock-agentcore-control/list-agent-runtimes.json").get(
        "agentRuntimes", []
    ):
        detail = _aws_json(inputs, f"bedrock-agentcore-control/get-agent-runtime.{rt['agentRuntimeId']}.json")
        records.append({**rt, **detail, "_kind": "agentcore-runtime", "_region": region})
    for gw in _aws_json(inputs, "bedrock-agentcore-control/list-gateways.json").get("items", []):
        targets = _aws_json(inputs, f"bedrock-agentcore-control/list-gateway-targets.{gw['gatewayId']}.json")
        records.append(
            {**gw, "_kind": "agentcore-gateway", "_region": region, "_targets": targets.get("items", [])}
        )
    for fn in _aws_json(inputs, "lambda/list-functions.json").get("Functions", []):
        env = (fn.get("Environment") or {}).get("Variables") or {}
        records.append(
            {
                "_kind": "lambda",
                "_region": region,
                "FunctionName": fn.get("FunctionName"),
                "FunctionArn": fn.get("FunctionArn"),
                "Runtime": fn.get("Runtime"),
                "Role": fn.get("Role"),
                "Handler": fn.get("Handler"),
                "Environment": {str(k): str(v) for k, v in env.items()},
                "environment_coverage": "observed",
                "Layers": [layer.get("Arn") for layer in fn.get("Layers") or []],
                "LastModified": fn.get("LastModified"),
                "PackageType": fn.get("PackageType"),
                "Tags": {},
            }
        )
    for ep in _aws_json(inputs, "sagemaker/list-endpoints.json").get("Endpoints", []):
        cfg_name = ep.get("EndpointConfigName") or f"{ep['EndpointName']}-config"
        cfg = _aws_json(inputs, f"sagemaker/describe-endpoint-config.{cfg_name}.json")
        models = []
        for variant in cfg.get("ProductionVariants", []):
            model = _aws_json(inputs, f"sagemaker/describe-model.{variant.get('ModelName')}.json")
            container = model.get("PrimaryContainer") or {}
            models.append(
                {
                    "name": variant.get("ModelName"),
                    "instance": variant.get("InstanceType"),
                    "images": [container.get("Image")] if container.get("Image") else [],
                    "env": dict(container.get("Environment") or {}),
                    "model_data": [container.get("ModelDataUrl")] if container.get("ModelDataUrl") else [],
                }
            )
        records.append(
            {
                "_kind": "sagemaker-endpoint",
                "_region": region,
                "EndpointName": ep["EndpointName"],
                "EndpointArn": ep.get("EndpointArn"),
                "EndpointStatus": ep.get("EndpointStatus"),
                "CreationTime": str(ep.get("CreationTime")),
                "LastModifiedTime": str(ep.get("LastModifiedTime")),
                "models": models,
            }
        )
    return _jsonl(work / "aws_records.jsonl", records)


class ShadowScanAdapter:
    name = "shadowscan"
    display = "ShadowScan (Project Nexus)"
    surfaces: Mapping[str, frozenset[str]] = {
        "code": frozenset({"checkout"}),
        "identity": frozenset({"okta-export", "entra-export"}),
        "gateway": frozenset({"litellm-export", "bedrock-export"}),
        "lowcode": frozenset({"powerplatform-export", "n8n-export"}),
        "saas": frozenset({"slack-export", "github-export"}),
        "cloud": frozenset({"aws-export", "k8s-export"}),
        "endpoint": frozenset({"home"}),
        "network": frozenset({"passive"}),
        "runtime": frozenset({"snapshot", "live"}),
    }

    def unavailable_reason(self, env: ToolEnv) -> str | None:
        if not env.binary("shadowscan"):
            return "no 'bin' (python interpreter with ShadowScan's dependencies) configured for shadowscan"
        if not env.tool("shadowscan").get("repo"):
            return "no 'repo' (checkout to put on PYTHONPATH) configured for shadowscan"
        return None

    def version(self, env: ToolEnv) -> str:
        import subprocess

        repo = str(env.tool("shadowscan").get("repo"))
        try:
            out = subprocess.run(
                [env.binary("shadowscan") or "python", "-m", "shadowscan.cli", "--version"],
                capture_output=True,
                text=True,
                timeout=60,
                env={**base_env(Path(repo), Path(repo)), "PYTHONPATH": repo},
                check=False,
            )
            head = subprocess.run(
                ["git", "-C", repo, "rev-parse", "--short=12", "HEAD"],
                capture_output=True,
                text=True,
                check=False,
            )
            return f"{(out.stdout or out.stderr).strip().split()[-1]}+{head.stdout.strip()}"
        except (OSError, IndexError, subprocess.TimeoutExpired):
            return "unknown"

    def _connector(self, case: MaterializedCase, work: Path) -> dict[str, Any]:
        inputs = case.inputs
        s, m = case.surface, case.modality
        if (s, m) == ("code", "checkout"):
            return {"name": "code.filesystem", "path": str(inputs / "repo"), "use_git": False}
        if (s, m) == ("identity", "okta-export"):
            return {
                "name": "identity.okta",
                "input": str(convert_okta(inputs, work)),
                "org_url": "https://acme.okta.com",
            }
        if (s, m) == ("identity", "entra-export"):
            return {
                "name": "identity.entra",
                "input": str(convert_entra(inputs, work)),
                "tenant_id": "acme-tenant",
            }
        if (s, m) == ("gateway", "litellm-export"):
            return {
                "name": "gateway.logs",
                "input": str(inputs / "litellm" / "spend_logs.jsonl"),
                "label": "litellm",
            }
        if (s, m) == ("gateway", "bedrock-export"):
            return {
                "name": "gateway.logs",
                "input": str(inputs / "bedrock" / "model_invocation_logs.jsonl"),
                "label": "bedrock",
            }
        if (s, m) == ("lowcode", "powerplatform-export"):
            return {"name": "lowcode.power-platform", "input": str(convert_power_platform(inputs, work))}
        if (s, m) == ("lowcode", "n8n-export"):
            return {"name": "lowcode.n8n", "input": str(inputs / "n8n" / "workflows.json")}
        if (s, m) == ("saas", "slack-export"):
            return {"name": "saas.slack", "input": str(convert_slack(inputs, work))}
        if (s, m) == ("saas", "github-export"):
            return {
                "name": "saas.github-apps",
                "input": str(inputs / "github" / "installations.json"),
                "org": "acme",
            }
        if (s, m) == ("cloud", "aws-export"):
            return {
                "name": "cloud.aws",
                "input": str(convert_aws(inputs, work)),
                "account_id": "123456789012",
            }
        if (s, m) == ("cloud", "k8s-export"):
            return {
                "name": "cloud.kubernetes",
                "cluster": "bench",
                "input": str(inputs / "kubernetes" / "workloads.json"),
            }
        if (s, m) == ("endpoint", "home"):
            return {"name": "endpoint.inventory", "path": str(case.home), "label": "bench-host"}
        if (s, m) == ("network", "passive"):
            return {"name": "network.logs", "input": str(inputs / "zeek"), "label": "bench"}
        if (s, m) == ("runtime", "snapshot"):
            return {"name": "runtime.processes", "input": str(inputs / "osqueryd_results.jsonl")}
        if (s, m) == ("runtime", "live"):
            return {"name": "runtime.processes", "label": "bench-host"}
        raise ValueError(f"unsupported {s}/{m}")

    def invocations(self, case: MaterializedCase, env: ToolEnv, work: Path) -> list[Invocation]:
        cfg = work / "shadowscan.json"
        cfg.write_text(
            json.dumps({"connectors": [self._connector(case, work)], "options": {"parallel": 1}}),
            encoding="utf-8",
        )
        repo = str(env.tool("shadowscan").get("repo"))
        home = case.home if case.home is not None else work / "home"
        home.mkdir(exist_ok=True)
        return [
            Invocation(
                argv=(
                    env.binary("shadowscan") or "python",
                    "-m",
                    "shadowscan.cli",
                    "scan",
                    "-c",
                    str(cfg),
                    "-f",
                    "json",
                    "-o",
                    str(work / "report.json"),
                ),
                cwd=work,
                env={**base_env(home, work), "PYTHONPATH": repo, "PYTHONDONTWRITEBYTECODE": "1"},
                timeout=900,
                ok_codes=frozenset({0, 2, 3}),
            )
        ]

    def _keys(self, case: MaterializedCase, f: dict[str, Any]) -> list[str]:
        resource = str(f.get("resource") or "")
        meta = f.get("metadata") or {}
        s = case.surface
        if s == "identity":
            if resource.startswith("okta:app:"):
                return [f"app:{resource.split(':', 2)[2]}"]
            app_id = meta.get("app_id")
            return [f"app:{app_id}"] if app_id else []
        if s == "gateway":
            caller = meta.get("caller")
            return [f"caller:{caller}"] if caller else []
        if s == "lowcode":
            for prefix, kind in (
                ("power-platform:bot:", "bot"),
                ("power-platform:flow:", "flow"),
                ("n8n:workflow:", "workflow"),
            ):
                if resource.startswith(prefix):
                    return [f"{kind}:{resource[len(prefix) :]}"]
            return []
        if s == "saas":
            if resource.startswith("slack:app:"):
                return [f"app:{resource.split(':', 2)[2]}"]
            slug = meta.get("app_slug")
            return [f"app:{slug}"] if slug else []
        if s == "cloud":
            if resource.startswith("arn:"):
                return [f"resource:{resource}"]
            if resource.startswith("k8s:"):
                parts = resource.split("/", 1)
                return [f"k8s:{parts[1]}"] if len(parts) == 2 else []
            return []
        if s == "endpoint":
            home = case.home or case.inputs / "home"
            keys = []
            for path in [*(meta.get("files") or []), *(meta.get("locations") or [])]:
                key = relative_artifact(str(path), home)
                if key:
                    keys.append(key)
            return keys
        if s == "network":
            client = meta.get("client")
            return [f"client:{client}"] if client else []
        if s == "runtime":
            return [f"process:{pid}" for pid in meta.get("pids") or []]
        return []

    def _normalize_code(self, work: Path, run: RunResult) -> AdapterResult:
        """Map a code.filesystem report onto taxonomy facts with the code-surface benchmark's own adapter."""
        from tools.discovery_benchmark.adapters.shadowscan import ShadowScanAdapter as CodeAdapter

        normalized = CodeAdapter().normalize(work)
        if normalized.error:
            return AdapterResult("error", note=normalized.error)
        entities = [
            Entity("fact", fact, "llm" if fact.startswith("provider:") else "agent")
            for fact in sorted(normalized.facts)
        ]
        incomplete = bool(normalized.detail.get("incomplete")) or run.code == 3
        note = f"{normalized.raw_count} findings, {len(entities)} facts" + (
            "; incomplete scan" if incomplete else ""
        )
        return AdapterResult(
            "ok", entities, note=note, raw={"incomplete": incomplete, "stderr": tail(run.stderr, 2000)}
        )

    def normalize(self, case: MaterializedCase, work: Path, runs: list[RunResult]) -> AdapterResult:
        run = runs[0]
        report_path = work / "report.json"
        if not report_path.exists():
            return AdapterResult("error", note=f"exit {run.code}: {tail(run.stderr or run.stdout)}")
        if case.surface == "code":
            return self._normalize_code(work, run)
        report = _load(report_path)
        findings = report.get("findings", [])
        summary = report.get("summary", {})
        entities: dict[str, Entity] = {}
        unmapped = 0
        for f in findings:
            label = (
                "agent"
                if f.get("kind") in AGENT_KINDS or (f.get("metadata") or {}).get("agent_indicators")
                else "llm"
            )
            keys = self._keys(case, f)
            if not keys:
                unmapped += 1
            for key in keys:
                prior = entities.get(key)
                if prior is None or (label == "agent" and prior.label != "agent"):
                    entities[key] = Entity(
                        str(f.get("kind")), key, label, {"title": str(f.get("title", ""))[:120]}
                    )
        incomplete = run.code == 3 or not summary.get("complete", False)
        note = f"{len(findings)} findings, {unmapped} unmapped" + (
            "; incomplete scan (exit 3)" if incomplete else ""
        )
        return AdapterResult(
            "ok",
            list(entities.values()),
            note=note,
            raw={"report": report, "incomplete": incomplete, "stderr": tail(run.stderr, 2000)},
        )


ADAPTER = ShadowScanAdapter()
