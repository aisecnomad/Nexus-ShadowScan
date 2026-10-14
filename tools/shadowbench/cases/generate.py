"""Generate the seeded ShadowBench corpus.

``python -m tools.shadowbench.cases generate --seed 20261011 --per-surface 40 --output corpus.json``

Export surfaces (identity, gateway, lowcode, saas, cloud, runtime/snapshot)
compose several entity drafts into one platform-native export per case, so a
case holds a realistic mix of agents, plain AI use and decoys. Endpoint,
network and runtime/live cases hold one artifact, window or process set each.
Each (surface, modality) draws from its own random stream, seeded as the
recorded ``stream_scheme`` says (``stream_seed``). The same seed,
``--per-surface``, stream scheme and generator sources always produce the same
cases; only the ``created`` stamp in the header differs between runs. Code
cases come from ``benchmarks/shadow-ai-discovery/corpus.json``; without it the
generator refuses to build rather than write a corpus with no code surface.

``--stream-scheme legacy`` rebuilds the committed 2026-10-11 cases, whose seed
had no effect; never use it for a new corpus.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from tools.benchmark.common import Rand
from tools.shadowbench.cases.contract import TruthEntity
from tools.shadowbench.cases.corpus import (
    LEGACY_STREAMS,
    STREAM_SCHEMES,
    Case,
    Corpus,
    digest_files,
    dump_corpus,
    validate_case,
)
from tools.shadowbench.cases.families import (
    Draft,
    cloud,
    endpoint,
    gateway,
    identity,
    lowcode,
    network,
    runtime,
    saas,
)

DEFAULT_SEED = 20261011
CODE_CORPUS = Path(__file__).resolve().parents[3] / "benchmarks" / "shadow-ai-discovery" / "corpus.json"
# A stratified subset of the pinned code-surface corpus (benchmarks/shadow-ai-discovery): 16 positive,
# 4 control and 6 near-miss repositories, chosen before any tool ran and bounded in size.
CODE_REPOS: tuple[str, ...] = (
    "anthropics__claude-agent-sdk-python", "openai__openai-agents-python", "crewAIInc__crewAI-examples",
    "langchain-ai__react-agent", "modelcontextprotocol__servers", "github__github-mcp-server",
    "microsoft__playwright-mcp", "aws-ia__terraform-aws-bedrock", "n8n-io__self-hosted-ai-starter-kit",
    "google__adk-samples", "vercel__ai-chatbot", "jlowin__fastmcp", "huggingface__smolagents",
    "gitlab-org__gitlab-runner", "anthropics__skills", "awslabs__amazon-bedrock-agent-samples",
    "encode__httpx", "pallets__flask", "spf13__cobra", "terraform-aws-modules__terraform-aws-vpc",
    "autowp__arduino-mcp2515", "faisalman__ua-parser-js", "jenkinsci__docker-agent",
    "PrismarineJS__bedrock-protocol", "e2b-dev__awesome-ai-agents", "brianc__node-pg-cursor",
)  # fmt: skip
QUOTAS = (("agent", 0.45), ("llm", 0.15), ("none", 0.40))
Family = Callable[[Rand], Draft]
PLAN: tuple[tuple[str, str], ...] = (
    ("identity", "okta-export"),
    ("identity", "entra-export"),
    ("gateway", "litellm-export"),
    ("gateway", "bedrock-export"),
    ("lowcode", "powerplatform-export"),
    ("lowcode", "n8n-export"),
    ("saas", "slack-export"),
    ("saas", "github-export"),
    ("cloud", "aws-export"),
    ("cloud", "k8s-export"),
    ("endpoint", "home"),
    ("network", "passive"),
    ("network", "active"),
    ("runtime", "snapshot"),
    ("runtime", "live"),
)
"""The generated (surface, modality) pairs, in corpus order; code cases follow them."""
STREAM_SCHEME = "sha256"
"""The stream scheme every new corpus is generated with."""


def stream_seed(seed: int, surface: str, modality: str, scheme: str) -> int:
    """The seed of one (surface, modality) random stream under ``scheme``.

    ``sha256`` hashes the seed, surface and modality together, so every seed builds its own cases
    and no two modalities share a stream. ``legacy`` is how the committed 2026-10-11 corpus was
    built, kept only so that it still rebuilds: it reduced the big-endian key modulo 2**62, which
    keeps the key's last 62 bits. Those always fall inside the modality name, so the seed had no
    effect, and modalities whose keys end in the same 62 bits (``okta-export`` and
    ``entra-export``, among others) shared one stream (``shared_streams``).
    """
    key = f"{seed}:{surface}:{modality}".encode()
    if scheme == LEGACY_STREAMS:
        return int.from_bytes(key, "big") % (2**62)
    if scheme == "sha256":
        return int.from_bytes(hashlib.sha256(key).digest()[:8], "big")
    raise ValueError(f"unknown stream scheme {scheme!r} (expected one of {', '.join(STREAM_SCHEMES)})")


def shared_streams(seed: int, scheme: str) -> list[list[str]]:
    """Groups of ``surface/modality`` names that draw from one random stream under ``scheme``."""
    groups: dict[int, list[str]] = {}
    for surface, modality in PLAN:
        groups.setdefault(stream_seed(seed, surface, modality, scheme), []).append(f"{surface}/{modality}")
    return [group for group in groups.values() if len(group) > 1]


def _dump(value: Any) -> str:
    return json.dumps(value, indent=1, ensure_ascii=False) + "\n"


def _jsonl(rows: list[dict[str, Any]]) -> str:
    return "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows)


def _signature(d: Draft) -> str:
    if d.expected and not all(e.key.startswith("proc:") for e in d.expected):
        return "|".join(sorted(e.key for e in d.expected))
    return hashlib.sha256(json.dumps(d.records, sort_keys=True, default=str).encode()).hexdigest()


def _pick(rd: Rand, pools: dict[str, tuple[Family, ...]], label: str, seen: set[str]) -> Draft | None:
    """Draw a draft whose entities are not already in the case; ``None`` after too many collisions."""
    for _ in range(40):
        family: Family = rd.choice(pools[label])
        draft = family(rd)
        sig = _signature(draft)
        if sig not in seen:
            seen.add(sig)
            return draft
    return None


def _draw(rd: Rand, pools: dict[str, tuple[Family, ...]], labels: list[str]) -> list[Draft]:
    seen: set[str] = set()
    drafts = [_pick(rd, pools, lab, seen) for lab in labels]
    return [d for d in drafts if d is not None]


def _labels(rd: Rand, n: int) -> list[str]:
    """Entity labels for one export: at least one decoy, a mix otherwise."""
    labels = []
    for label, share in QUOTAS:
        labels += [label] * max(1 if label == "none" else 0, round(n * share))
    labels = labels[:n] if len(labels) >= n else labels + ["none"] * (n - len(labels))
    rd.shuffle(labels)
    return labels


def decoy_keys(records: dict[str, list[dict[str, Any]]]) -> list[str]:
    """Entity keys of the records a ``none`` draft added: the surface's true negatives."""
    keys: list[str] = []
    for coll, rows in records.items():
        for r in rows:
            if coll == "apps" and "signOnMode" in r:
                keys.append(f"app:{r['id']}")
            elif coll == "servicePrincipals":
                keys.append(f"app:{r['appId']}")
            elif coll == "flows":
                keys.append(f"flow:{r['name']}")
            elif coll == "bots":
                keys.append(f"bot:{r['botid']}")
            elif coll == "workflows":
                keys.append(f"workflow:{r['id']}")
            elif coll == "approved_apps":
                keys.append(f"app:{r['app']['id']}")
            elif coll == "installations":
                keys.append(f"app:{r['app_slug']}")
            elif coll == "lambda-functions":
                keys.append(f"resource:{r['FunctionArn']}")
            elif coll == "sagemaker-endpoints":
                keys.append(f"resource:{r['EndpointArn']}")
            elif coll == "iam-roles":
                keys.append(f"resource:{r['Arn']}")
            elif coll == "workloads":
                keys.append(f"k8s:{r['metadata']['namespace']}/{r['kind']}/{r['metadata']['name']}")
    return keys


def _merge(
    drafts: list[Draft],
) -> tuple[dict[str, list[dict[str, Any]]], list[TruthEntity], list[str], list[str], str]:
    records: dict[str, list[dict[str, Any]]] = {}
    expected: list[TruthEntity] = []
    tolerated: list[str] = []
    decoys: list[str] = []
    for d in drafts:
        for key, rows in d.records.items():
            records.setdefault(key, []).extend(rows)
        expected += d.expected
        tolerated += d.tolerated
        if d.label == "none":
            decoys += [k for k in decoy_keys(d.records) if k not in d.tolerated]
    family = "+".join(sorted({d.family for d in drafts}))
    return records, expected, tolerated, decoys, family


# --- export renderers -----------------------------------------------------------


def render_okta(records: dict[str, list[dict[str, Any]]]) -> dict[str, str]:
    files = {"okta/apps.json": _dump(records.get("apps", []))}
    for key, rows in records.items():
        if key.startswith("grants/"):
            files[f"okta/grants/{key.split('/', 1)[1]}.json"] = _dump(rows)
        elif key.startswith("tokens/"):
            files[f"okta/tokens/{key.split('/', 1)[1]}.json"] = _dump(rows)
    return files


def render_entra(records: dict[str, list[dict[str, Any]]]) -> dict[str, str]:
    out = {}
    for coll in ("servicePrincipals", "applications", "oauth2PermissionGrants", "appRoleAssignments"):
        out[f"entra/{coll}.json"] = _dump(
            {
                "@odata.context": f"https://graph.microsoft.com/v1.0/$metadata#{coll}",
                "value": records.get(coll, []),
            }
        )
    return out


def render_litellm(records: dict[str, list[dict[str, Any]]]) -> dict[str, str]:
    rows = sorted(records.get("rows", []), key=lambda r: str(r["startTime"]))
    return {"litellm/spend_logs.jsonl": _jsonl(rows)}


def render_bedrock_logs(records: dict[str, list[dict[str, Any]]]) -> dict[str, str]:
    rows = sorted(records.get("rows", []), key=lambda r: str(r["timestamp"]))
    return {"bedrock/model_invocation_logs.jsonl": _jsonl(rows)}


def render_power_platform(records: dict[str, list[dict[str, Any]]]) -> dict[str, str]:
    env = {
        "name": lowcode.ENV_NAME,
        "id": f"/providers/Microsoft.BusinessAppPlatform/environments/{lowcode.ENV_NAME}",
        "type": "Microsoft.BusinessAppPlatform/environments",
        "properties": {
            "displayName": lowcode.ENV_DISPLAY,
            "environmentSku": "Default",
            "linkedEnvironmentMetadata": {"instanceUrl": "https://acme.crm.dynamics.com/"},
        },
    }
    return {
        "power-platform/environments.json": _dump({"value": [env]}),
        "power-platform/flows.json": _dump({"value": records.get("flows", [])}),
        "power-platform/apps.json": _dump({"value": records.get("apps", [])}),
        "power-platform/bots.json": _dump({"value": records.get("bots", [])}),
        "power-platform/botcomponents.json": _dump({"value": records.get("botcomponents", [])}),
    }


def render_n8n(records: dict[str, list[dict[str, Any]]]) -> dict[str, str]:
    return {"n8n/workflows.json": _dump({"data": records.get("workflows", []), "nextCursor": None})}


def render_slack(records: dict[str, list[dict[str, Any]]]) -> dict[str, str]:
    return {
        "slack/team.info.json": _dump(
            {"ok": True, "team": {"id": "T0ACME0001", "name": "acme", "domain": "acme"}}
        ),
        "slack/admin.apps.approved.list.json": _dump(
            {"ok": True, "approved_apps": records.get("approved_apps", [])}
        ),
        "slack/admin.apps.requests.list.json": _dump(
            {"ok": True, "app_requests": records.get("requests", [])}
        ),
        "slack/users.list.json": _dump({"ok": True, "members": records.get("members", [])}),
    }


def render_github(records: dict[str, list[dict[str, Any]]]) -> dict[str, str]:
    inst = records.get("installations", [])
    return {"github/installations.json": _dump({"total_count": len(inst), "installations": inst})}


def render_aws(records: dict[str, list[dict[str, Any]]]) -> dict[str, str]:
    files: dict[str, str] = {
        "aws/sts/get-caller-identity.json": _dump(
            {
                "UserId": "AIDAEXAMPLE",
                "Account": cloud.ACCOUNT,
                "Arn": f"arn:aws:iam::{cloud.ACCOUNT}:user/auditor",
            }
        ),
        "aws/bedrock-agent/list-agents.json": _dump({"agentSummaries": records.get("bedrock-agents", [])}),
        "aws/bedrock-agent/list-knowledge-bases.json": _dump(
            {"knowledgeBaseSummaries": records.get("bedrock-knowledge-bases", [])}
        ),
        "aws/bedrock-agentcore-control/list-agent-runtimes.json": _dump(
            {"agentRuntimes": records.get("agentcore-runtimes", [])}
        ),
        "aws/bedrock-agentcore-control/list-gateways.json": _dump(
            {"items": records.get("agentcore-gateways", [])}
        ),
        "aws/lambda/list-functions.json": _dump({"Functions": records.get("lambda-functions", [])}),
        "aws/sagemaker/list-endpoints.json": _dump({"Endpoints": records.get("sagemaker-endpoints", [])}),
        "aws/iam/list-roles.json": _dump({"Roles": records.get("iam-roles", [])}),
    }
    for cfg in records.get("sagemaker-endpoint-configs", []):
        files[f"aws/sagemaker/describe-endpoint-config.{cfg['EndpointConfigName']}.json"] = _dump(cfg)
    for model in records.get("sagemaker-models", []):
        files[f"aws/sagemaker/describe-model.{model['ModelName']}.json"] = _dump(model)
    for extra in records.get("_files", []):
        files[str(extra["path"])] = _dump(extra["json"])
    return files


def render_k8s(records: dict[str, list[dict[str, Any]]]) -> dict[str, str]:
    items = records.get("workloads", [])
    return {
        "kubernetes/workloads.json": _dump(
            {"apiVersion": "v1", "kind": "List", "metadata": {"resourceVersion": ""}, "items": items}
        )
    }


def render_osquery(
    records: dict[str, list[dict[str, Any]]], rd: Rand, host: str
) -> tuple[dict[str, str], list[dict[str, Any]]]:
    """Snapshot rows (strings, as osquery prints them) and the pid each process got."""
    procs = records.get("processes", [])
    pids = sorted(rd.sample(range(300, 60000), len(procs)))
    rows = []
    results = []
    for p, pid in zip(procs, pids, strict=True):
        row = {
            "pid": str(pid),
            "name": p["name"],
            "path": p["path"],
            "cmdline": p["cmdline"],
            "cwd": f"/home/{p['username']}" if p["uid"] else "/",
            "uid": str(p["uid"]),
            "gid": str(p["uid"]),
            "username": p["username"],
            "parent": str(rd.randint(1, 299)),
            "start_time": str(p["start_time"]),
            "state": "S",
        }
        rows.append(row)
        results.append(
            {
                "name": "pack_endpoint_processes",
                "hostIdentifier": host,
                "calendarTime": "Mon Sep 29 08:05:00 2026 UTC",
                "unixTime": 1_759_133_100,
                "epoch": 0,
                "counter": 0,
                "numerics": False,
                "action": "snapshot",
                "columns": row,
            }
        )
    return {"osquery_processes.json": _dump(rows), "osqueryd_results.jsonl": _jsonl(results)}, [
        {**p, "pid": pid} for p, pid in zip(procs, pids, strict=True)
    ]


# --- surface builders -----------------------------------------------------------

EXPORTS: dict[
    tuple[str, str],
    tuple[
        dict[str, tuple[Family, ...]],
        Callable[[dict[str, list[dict[str, Any]]]], dict[str, str]],
        tuple[int, int],
    ],
] = {
    ("identity", "okta-export"): (
        {"agent": identity.OKTA_AGENT, "llm": identity.OKTA_LLM, "none": identity.OKTA_NONE},
        render_okta,
        (4, 9),
    ),
    ("identity", "entra-export"): (
        {"agent": identity.ENTRA_AGENT, "llm": identity.ENTRA_LLM, "none": identity.ENTRA_NONE},
        render_entra,
        (4, 9),
    ),
    ("gateway", "litellm-export"): (
        {"agent": gateway.LITELLM_AGENT, "llm": gateway.LITELLM_LLM, "none": gateway.LITELLM_NONE},
        render_litellm,
        (2, 5),
    ),
    ("gateway", "bedrock-export"): (
        {"agent": gateway.BEDROCK_AGENT, "llm": gateway.BEDROCK_LLM, "none": gateway.BEDROCK_NONE},
        render_bedrock_logs,
        (2, 4),
    ),
    ("lowcode", "powerplatform-export"): (
        {"agent": lowcode.PP_AGENT, "llm": lowcode.PP_LLM, "none": lowcode.PP_NONE},
        render_power_platform,
        (3, 7),
    ),
    ("lowcode", "n8n-export"): (
        {"agent": lowcode.N8N_AGENT, "llm": lowcode.N8N_LLM, "none": lowcode.N8N_NONE},
        render_n8n,
        (3, 7),
    ),
    ("saas", "slack-export"): (
        {"agent": saas.SLACK_AGENT, "llm": saas.SLACK_LLM, "none": saas.SLACK_NONE},
        render_slack,
        (4, 9),
    ),
    ("saas", "github-export"): (
        {"agent": saas.GITHUB_AGENT, "llm": saas.GITHUB_LLM, "none": saas.GITHUB_NONE},
        render_github,
        (3, 8),
    ),
    ("cloud", "aws-export"): (
        {"agent": cloud.AWS_AGENT, "llm": cloud.AWS_LLM, "none": cloud.AWS_NONE},
        render_aws,
        (3, 7),
    ),
    ("cloud", "k8s-export"): (
        {"agent": cloud.K8S_AGENT, "llm": cloud.K8S_LLM, "none": cloud.K8S_NONE},
        render_k8s,
        (3, 8),
    ),
}
RUNTIME_POOLS: dict[str, tuple[Family, ...]] = {
    "agent": runtime.RT_AGENT,
    "llm": runtime.RT_LLM,
    "none": runtime.RT_NONE,
}


def _export_case(rd: Rand, surface: str, modality: str, case_label: str, index: int) -> Case:
    pools, render, (lo, hi) = EXPORTS[(surface, modality)]
    n = rd.randint(lo, hi)
    labels = _labels(rd, n)
    if case_label == "none":
        labels = ["none"] * n
    elif case_label == "llm":
        labels = [("llm" if lab == "agent" else lab) for lab in labels]
        if "llm" not in labels:
            labels[0] = "llm"
    elif "agent" not in labels:
        labels[0] = "agent"
    if not pools["none"]:  # surfaces without natural negatives (gateway)
        labels = [("llm" if lab == "none" else lab) for lab in labels]
        if case_label == "none":
            case_label = "llm"
    drafts = _draw(rd, pools, labels)
    records, expected, tolerated, decoys, family = _merge(drafts)
    files = render(records)
    diff = "hard" if any(d.difficulty == "hard" for d in drafts) else "medium"
    rationale = "; ".join(f"{d.family}: {d.rationale}" for d in drafts)
    return Case(
        f"{surface}-{modality}-{index:03d}",
        surface,
        modality,
        family,
        diff,
        rationale,
        files=files,
        expected=expected,
        tolerated=sorted(set(tolerated)),
        decoys=sorted(set(decoys)),
    )


def _runtime_case(rd: Rand, modality: str, case_label: str, index: int) -> Case:
    n = rd.randint(4, 10)
    labels = _labels(rd, n)
    if case_label == "none":
        labels = ["none"] * n
    elif case_label == "llm":
        labels = [("llm" if lab == "agent" else lab) for lab in labels]
        if "llm" not in labels:
            labels[0] = "llm"
    elif "agent" not in labels:
        labels[0] = "agent"
    drafts = _draw(rd, RUNTIME_POOLS, labels)
    host = str(rd.choice(runtime.HOSTS))
    procs = [d.records["processes"][0] for d in drafts]
    expected: list[TruthEntity] = []
    rationale = "; ".join(f"{d.family}: {d.rationale}" for d in drafts)
    family = "+".join(sorted({d.family for d in drafts}))
    diff = "hard" if any(d.difficulty == "hard" for d in drafts) else "medium"
    decoys: list[str] = []
    if modality == "snapshot":
        files, with_pids = render_osquery({"processes": procs}, rd, host)
        for d, p in zip(drafts, with_pids, strict=True):
            for e in d.expected:
                expected.append(TruthEntity(e.kind, f"process:{p['pid']}", e.label, e.attributes, e.evidence))
            if d.label == "none":
                decoys.append(f"process:{p['pid']}")
        return Case(
            f"runtime-snapshot-{index:03d}",
            "runtime",
            "snapshot",
            family,
            diff,
            rationale,
            files=files,
            expected=expected,
            decoys=decoys,
        )
    for i, d in enumerate(drafts):
        for e in d.expected:
            expected.append(TruthEntity(e.kind, f"proc:{i}", e.label, e.attributes, e.evidence))
        if d.label == "none":
            decoys.append(f"proc:{i}")
    spawn = [
        {"index": i, "name": p["name"], "argv": p["argv"], "username": p["username"]}
        for i, p in enumerate(procs)
    ]
    return Case(
        f"runtime-live-{index:03d}",
        "runtime",
        "live",
        family,
        diff,
        rationale,
        processes=spawn,
        expected=expected,
        decoys=decoys,
    )


def _active_case(rd: Rand, case_label: str, index: int) -> Case:
    n = rd.randint(2, 6)
    labels = _labels(rd, n)
    if case_label == "none":
        labels = ["none"] * n
    elif case_label == "llm":
        labels = [("llm" if lab == "agent" else lab) for lab in labels]
        if "llm" not in labels:
            labels[0] = "llm"
    elif "agent" not in labels:
        labels[0] = "agent"
    drafts: list[Draft] = []
    ports: set[int] = set()
    for lab in labels:
        for _ in range(20):
            d = network.active_draft(rd, lab)
            port = int(d.services[0]["port"])
            if port not in ports:
                ports.add(port)
                drafts.append(d)
                break
    services = [d.services[0] for d in drafts]
    expected = [e for d in drafts for e in d.expected]
    decoys = [f"service:127.0.0.1:{d.services[0]['port']}" for d in drafts if d.label == "none"]
    rationale = "; ".join(d.rationale for d in drafts)
    family = "+".join(sorted({d.family for d in drafts}))
    diff = "hard" if any(d.difficulty == "hard" for d in drafts) else "easy"
    files = {"services.json": _dump(services)}
    return Case(
        f"network-active-{index:03d}",
        "network",
        "active",
        family,
        diff,
        rationale,
        files=files,
        services=services,
        expected=expected,
        decoys=decoys,
    )


def _require_code_corpus(corpus_path: Path) -> Path:
    """The code-surface corpus, or a clear error: a corpus without its code cases is not this benchmark."""
    if not corpus_path.is_file():
        raise FileNotFoundError(
            f"code-surface corpus {corpus_path} is missing; ShadowBench pins its code cases there, "
            "so the generator refuses to build or digest a corpus without them"
        )
    return corpus_path


def code_cases(corpus_path: Path = CODE_CORPUS, repo_ids: tuple[str, ...] = CODE_REPOS) -> list[Case]:
    """Code-surface cases: pinned public repositories with the discovery benchmark's fact-level truth.

    A ``provider:*`` fact is plain model use (``llm``); every other fact (framework, MCP, agent
    configuration, A2A, low-code export, agent IaC) is ``agent``. Tolerated facts are carried over.
    """
    data = json.loads(_require_code_corpus(corpus_path).read_text(encoding="utf-8"))
    repos = {r["id"]: r for r in data["repos"]}
    cases: list[Case] = []
    for i, rid in enumerate(repo_ids, 1):
        if rid not in repos:
            raise ValueError(f"{corpus_path}: pinned code repository {rid} is not in the code corpus")
        r = repos[rid]
        expected = [
            TruthEntity(
                "fact",
                str(e["fact"]),
                "llm" if str(e["fact"]).startswith("provider:") else "agent",
                {"class": r["class"]},
                "; ".join(str(x) for x in e.get("evidence", [])) or "corpus",
            )
            for e in r.get("expected", [])
        ]
        cases.append(
            Case(
                f"code-checkout-{i:03d}",
                "code",
                "checkout",
                f"{r['class']}:{rid}",
                "medium" if r["class"] == "positive" else "hard",
                f"{r['host']} {r['path']} at {r['commit'][:12]} ({r['class']})",
                expected=expected,
                tolerated=[str(t) for t in r.get("tolerated", [])],
                checkout={"id": rid, "host": r["host"], "path": r["path"], "commit": r["commit"]},
            )
        )
        validate_case(cases[-1])
    return cases


def _quota(n: int) -> list[str]:
    labels: list[str] = []
    for label, share in QUOTAS[:-1]:
        labels += [label] * round(n * share)
    labels += [QUOTAS[-1][0]] * (n - len(labels))
    return labels


def build(seed: int, per_surface: int, *, stream_scheme: str = STREAM_SCHEME) -> list[Case]:
    """The cases at ``seed``; a corpus that records no stream scheme was built with ``legacy``."""
    if per_surface < 0:
        raise ValueError(f"per_surface must be non-negative, not {per_surface}")
    if stream_scheme not in STREAM_SCHEMES:
        raise ValueError(f"unknown stream scheme {stream_scheme!r}")
    code_corpus = _require_code_corpus(CODE_CORPUS)
    cases: list[Case] = []
    per_modality = {s: per_surface // sum(1 for ss, _m in PLAN if ss == s) for s in {s for s, _m in PLAN}}
    for surface, modality in PLAN:
        n = per_modality[surface]
        rd = Rand(stream_seed(seed, surface, modality, stream_scheme))
        labels = _quota(n)
        rd.shuffle(labels)
        for i, label in enumerate(labels, 1):
            if (surface, modality) in EXPORTS:
                case = _export_case(rd, surface, modality, label, i)
            elif surface == "runtime":
                case = _runtime_case(rd, modality, label, i)
            elif surface == "network" and modality == "active":
                case = _active_case(rd, label, i)
            elif surface == "network":
                d = network.passive_draft(rd, label)
                case = Case(
                    f"network-passive-{i:03d}",
                    "network",
                    "passive",
                    d.family,
                    d.difficulty,
                    d.rationale,
                    files=d.files,
                    expected=d.expected,
                )
            else:
                d = endpoint.endpoint_draft(rd, label)
                case = Case(
                    f"endpoint-home-{i:03d}",
                    "endpoint",
                    "home",
                    d.family,
                    d.difficulty,
                    d.rationale,
                    files=d.files,
                    expected=d.expected,
                    tolerated=d.tolerated,
                )
            validate_case(case)
            cases.append(case)
    return cases + code_cases(code_corpus)


def generator_digest() -> str:
    """SHA-256 over every source the cases are built from, named by repository-relative path.

    That covers the generator, its families, the ``tools/benchmark`` families it reuses and the
    code-surface corpus the code cases are drawn from. Paths are part of the digest, so moving
    the sources changes it even when they still build the same cases (``verify`` says so).
    """
    here = Path(__file__).resolve().parent
    files = [
        here / "generate.py",
        here / "corpus.py",
        here / "contract.py",
        *sorted((here / "families").glob("*.py")),
    ]
    bench = here.parents[1] / "benchmark"
    files += [
        bench / "common.py",
        bench / "endpoint_cases.py",
        bench / "network_cases.py",
        bench / "repo_cases.py",
        _require_code_corpus(CODE_CORPUS),
    ]
    return digest_files(files, here.parents[2])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED)
    ap.add_argument(
        "--per-surface", type=int, default=40, help="cases per surface (split across its modalities)"
    )
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument(
        "--stream-scheme",
        choices=STREAM_SCHEMES,
        default=STREAM_SCHEME,
        help=f"how each modality's random stream is seeded (default {STREAM_SCHEME}); {LEGACY_STREAMS} "
        "only rebuilds the committed 2026-10-11 cases, and its seed has no effect",
    )
    args = ap.parse_args(argv)
    if args.per_surface < 0:
        ap.error("--per-surface must be non-negative")
    cases = build(args.seed, args.per_surface, stream_scheme=args.stream_scheme)
    corpus = Corpus(
        cases,
        args.seed,
        generator_digest(),
        datetime.now(UTC).replace(microsecond=0).isoformat(),
        per_surface=args.per_surface,
        stream_scheme=args.stream_scheme,
    )
    digest = dump_corpus(corpus, args.output)
    by_surface: dict[str, dict[str, int]] = {}
    for c in cases:
        by_surface.setdefault(c.surface, {}).setdefault(c.label, 0)
        by_surface[c.surface][c.label] += 1
    print(
        f"wrote {len(cases)} cases to {args.output}\ncorpus sha256 {digest}\n"
        f"generator digest {corpus.generator_digest}\nstream scheme {corpus.streams}"
    )
    if args.stream_scheme == LEGACY_STREAMS:
        print("warning: under the legacy stream scheme the seed has no effect on the cases")
    for group in shared_streams(args.seed, args.stream_scheme):
        print(f"warning: {' and '.join(group)} share one random stream")
    for s, counts in by_surface.items():
        entities = sum(len(c.expected) for c in cases if c.surface == s)
        print(f"  {s:9s} {counts}  expected entities={entities}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
