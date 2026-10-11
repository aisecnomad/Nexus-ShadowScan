"""Cloud-surface families: AWS CLI JSON outputs and Kubernetes workload lists.

Rubric. ``agent``: a managed agent resource (Bedrock agent, AgentCore runtime
or MCP gateway), a function or workload whose configuration binds it to an
agent (environment names such as BEDROCK_AGENT_ID, an agent framework in the
container command or environment, an MCP server image or command, an agent
builder or agent gateway image). ``llm``: model serving or plain model access
without agency (an LLM inference endpoint, a model-server image, a function
holding only a provider key name, a knowledge base). ``none``: no AI, including
non-LLM ML endpoints, monitoring agents, build agents, game servers and
resources whose names only sound like AI.
"""

from __future__ import annotations

from typing import Any

from tools.benchmark.common import Rand
from tools.shadowbench.contract import TruthEntity
from tools.shadowbench.families import Draft, iso

ACCOUNT = "123456789012"
REGION = "us-east-1"
BEDROCK_MODELS = (
    "anthropic.claude-3-5-sonnet-20241022-v2:0",
    "anthropic.claude-sonnet-4-20250514-v1:0",
    "amazon.nova-pro-v1:0",
)
TGI_IMAGE = (
    "763104351884.dkr.ecr.us-east-1.amazonaws.com/huggingface-pytorch-tgi-inference"
    ":2.4.0-tgi2.3.1-gpu-py311-cu124-ubuntu22.04"
)
XGB_IMAGE = "683313688378.dkr.ecr.us-east-1.amazonaws.com/sagemaker-xgboost:1.7-1"
SKLEARN_IMAGE = "683313688378.dkr.ecr.us-east-1.amazonaws.com/sagemaker-scikit-learn:1.2-1-cpu-py3"


def _arn(service: str, rest: str) -> str:
    return f"arn:aws:{service}:{REGION}:{ACCOUNT}:{rest}"


def _role(name: str) -> str:
    return f"arn:aws:iam::{ACCOUNT}:role/{name}"


def _lambda(
    rd: Rand, name: str, env: dict[str, str], role: str, layers: list[str] | None = None
) -> dict[str, Any]:
    return {
        "FunctionName": name,
        "FunctionArn": _arn("lambda", f"function:{name}"),
        "Runtime": rd.choice(("python3.12", "python3.13", "nodejs22.x")),
        "Role": _role(role),
        "Handler": "app.handler",
        "CodeSize": rd.randint(2_000, 40_000_000),
        "Description": "",
        "Timeout": rd.choice((30, 60, 300, 900)),
        "MemorySize": rd.choice((256, 512, 1024, 2048)),
        "LastModified": iso(rd),
        "Version": "$LATEST",
        "Environment": {"Variables": env},
        "Layers": [{"Arn": layer, "CodeSize": rd.randint(1_000_000, 60_000_000)} for layer in layers or []],
        "PackageType": "Zip",
        "Architectures": ["x86_64"],
    }


def _sagemaker(
    rd: Rand, name: str, image: str, env: dict[str, str], instance: str
) -> dict[str, dict[str, Any]]:
    cfg = f"{name}-config"
    model = f"{name}-model"
    return {
        "endpoint": {
            "EndpointName": name,
            "EndpointArn": _arn("sagemaker", f"endpoint/{name}"),
            "EndpointConfigName": cfg,
            "EndpointStatus": "InService",
            "CreationTime": iso(rd, 2025),
            "LastModifiedTime": iso(rd),
        },
        "endpoint_config": {
            "EndpointConfigName": cfg,
            "EndpointConfigArn": _arn("sagemaker", f"endpoint-config/{cfg}"),
            "ProductionVariants": [
                {
                    "VariantName": "AllTraffic",
                    "ModelName": model,
                    "InitialInstanceCount": 1,
                    "InstanceType": instance,
                }
            ],
        },
        "model": {
            "ModelName": model,
            "ModelArn": _arn("sagemaker", f"model/{model}"),
            "PrimaryContainer": {"Image": image, "Environment": env},
            "ExecutionRoleArn": _role("SageMakerExecutionRole"),
        },
    }


# --- AWS families ------------------------------------------------------------


def aws_bedrock_agent(rd: Rand) -> Draft:
    name = (
        rd.choice(("ops-provisioning", "finance-reconciler", "claims-triage", "kb-concierge"))
        + f"-{rd.hexid(2)}"
    )
    agent_id = "".join(rd.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(10))
    role = f"AmazonBedrockExecutionRoleForAgents_{rd.hexid(4)}"
    arn = _arn("bedrock", f"agent/{agent_id}")
    summary = {
        "agentId": agent_id,
        "agentName": name,
        "agentStatus": "PREPARED",
        "description": "",
        "latestAgentVersion": "1",
        "updatedAt": iso(rd),
    }
    detail = {
        "agent": {
            **summary,
            "agentArn": arn,
            "agentResourceRoleArn": _role(role),
            "foundationModel": rd.choice(BEDROCK_MODELS),
            "instruction": "You handle requests for the team. Use the tools when needed.",
            "idleSessionTTLInSeconds": 600,
            "createdAt": iso(rd, 2025),
            "preparedAt": iso(rd),
        }
    }
    groups = {
        "actionGroupSummaries": [
            {
                "actionGroupId": rd.hexid(10).upper(),
                "actionGroupName": rd.choice(("tickets", "terraform", "crm")),
                "actionGroupState": "ENABLED",
            }
        ]
    }
    if rd.chance(0.5):
        groups["actionGroupSummaries"].append(
            {"actionGroupId": rd.hexid(10).upper(), "actionGroupName": "code", "actionGroupState": "ENABLED"}
        )
    aliases = {
        "agentAliasSummaries": [
            {"agentAliasId": rd.hexid(10).upper(), "agentAliasName": "prod", "agentAliasStatus": "PREPARED"}
        ]
    }
    files = {
        f"aws/bedrock-agent/get-agent.{agent_id}.json": detail,
        f"aws/bedrock-agent/list-agent-action-groups.{agent_id}.json": groups,
        f"aws/bedrock-agent/list-agent-aliases.{agent_id}.json": aliases,
        f"aws/bedrock-agent/list-agent-knowledge-bases.{agent_id}.json": {"agentKnowledgeBaseSummaries": []},
    }
    return Draft(
        "aws-bedrock-agent",
        "agent",
        "easy",
        "Bedrock agent with an action group and an alias.",
        {"bedrock-agents": [summary], "_files": [{"path": k, "json": v} for k, v in files.items()]},
        expected=[
            TruthEntity(
                "resource",
                f"resource:{arn}",
                "agent",
                {"platform": "aws", "name": name},
                "bedrock-agent list-agents/get-agent: a managed agent with action groups",
            )
        ],
        tolerated=[f"resource:{_role(role)}"],
    )


def aws_agentcore_runtime(rd: Rand) -> Draft:
    name = (
        rd.choice(("strands_support_agent", "langgraph_research", "crewai_invoice_agent")) + f"_{rd.hexid(2)}"
    )
    rid = f"{name}-{rd.hexid(10)}"
    arn = _arn("bedrock-agentcore", f"runtime/{rid}")
    role = f"AgentCoreRuntimeRole-{rd.hexid(3)}"
    summary = {
        "agentRuntimeArn": arn,
        "agentRuntimeId": rid,
        "agentRuntimeName": name,
        "agentRuntimeVersion": "1",
        "status": "READY",
        "description": "",
        "lastUpdatedAt": iso(rd),
    }
    detail = {
        **summary,
        "roleArn": _role(role),
        "agentRuntimeArtifact": {
            "containerConfiguration": {
                "containerUri": f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/{name.replace('_', '-')}:latest"
            }
        },
        "networkConfiguration": {"networkMode": "PUBLIC"},
        "protocolConfiguration": {"serverProtocol": rd.choice(("HTTP", "MCP"))},
        "environmentVariables": {"MODEL_ID": rd.choice(BEDROCK_MODELS)},
    }
    return Draft(
        "aws-agentcore-runtime",
        "agent",
        "easy",
        "Bedrock AgentCore runtime hosting a containerised agent.",
        {
            "agentcore-runtimes": [summary],
            "_files": [
                {"path": f"aws/bedrock-agentcore-control/get-agent-runtime.{rid}.json", "json": detail}
            ],
        },
        expected=[
            TruthEntity(
                "resource",
                f"resource:{arn}",
                "agent",
                {"platform": "aws", "name": name},
                "bedrock-agentcore-control list-agent-runtimes: a managed agent runtime",
            )
        ],
        tolerated=[f"resource:{_role(role)}"],
    )


def aws_agentcore_gateway(rd: Rand) -> Draft:
    name = rd.choice(("tools-gateway", "crm-mcp-gateway", "ops-mcp")) + f"-{rd.hexid(2)}"
    gid = f"{name}-{rd.hexid(10)}"
    arn = _arn("bedrock-agentcore", f"gateway/{gid}")
    item = {
        "gatewayId": gid,
        "gatewayArn": arn,
        "name": name,
        "status": "READY",
        "gatewayUrl": f"https://{gid}.gateway.bedrock-agentcore.{REGION}.amazonaws.com/mcp",
        "protocolType": "MCP",
        "authorizerType": rd.choice(("CUSTOM_JWT", "AWS_IAM")),
        "createdAt": iso(rd, 2025),
        "updatedAt": iso(rd),
    }
    targets = {
        "items": [
            {
                "targetId": rd.hexid(10),
                "name": rd.choice(("jira", "crm", "runbooks")),
                "status": "READY",
                "targetConfiguration": {
                    "mcp": {"lambda": {"lambdaArn": _arn("lambda", "function:gw-tools")}}
                },
            }
        ]
    }
    return Draft(
        "aws-agentcore-gateway",
        "agent",
        "medium",
        "AgentCore gateway exposing tools over MCP.",
        {
            "agentcore-gateways": [item],
            "_files": [
                {"path": f"aws/bedrock-agentcore-control/list-gateway-targets.{gid}.json", "json": targets}
            ],
        },
        expected=[
            TruthEntity(
                "resource",
                f"resource:{arn}",
                "agent",
                {"platform": "aws", "name": name},
                "bedrock-agentcore-control list-gateways: protocolType MCP",
            )
        ],
    )


def aws_lambda_agent(rd: Rand) -> Draft:
    style = rd.choice(("bedrock-agent", "framework"))
    name = rd.choice(("ticket-router", "invoice-agent", "ops-assistant", "support-bot")) + f"-{rd.hexid(2)}"
    if style == "bedrock-agent":
        env = {
            "BEDROCK_AGENT_ID": rd.hexid(10).upper(),
            "BEDROCK_AGENT_ALIAS_ID": rd.hexid(10).upper(),
            "LOG_LEVEL": "INFO",
        }
        evidence = "environment variable names BEDROCK_AGENT_ID and BEDROCK_AGENT_ALIAS_ID"
        layers = []
    else:
        env = {
            "OPENAI_API_KEY": "redacted",
            "LANGCHAIN_TRACING_V2": "true",
            "LANGCHAIN_PROJECT": name,
            "CREWAI_TELEMETRY_OPT_OUT": "true",
        }
        evidence = (
            "environment names LANGCHAIN_TRACING_V2 and CREWAI_TELEMETRY_OPT_OUT beside a provider key name"
        )
        layers = [f"arn:aws:lambda:{REGION}:{ACCOUNT}:layer:langchain-deps:7"]
    fn = _lambda(rd, name, env, f"{name}-role", layers)
    return Draft(
        "aws-lambda-agent",
        "agent",
        "medium",
        "Lambda function bound to an agent by its configuration.",
        {"lambda-functions": [fn]},
        expected=[
            TruthEntity(
                "resource",
                f"resource:{fn['FunctionArn']}",
                "agent",
                {"platform": "aws", "name": name},
                evidence,
            )
        ],
    )


def aws_sagemaker_llm(rd: Rand) -> Draft:
    model_id = rd.choice(
        ("meta-llama/Llama-3.1-8B-Instruct", "mistralai/Mistral-7B-Instruct-v0.3", "Qwen/Qwen2.5-7B-Instruct")
    )
    name = rd.choice(("llm-chat", "huggingface-llm", "jumpstart-dft-llama")) + f"-{rd.hexid(3)}"
    recs = _sagemaker(
        rd,
        name,
        TGI_IMAGE,
        {"HF_MODEL_ID": model_id, "SM_NUM_GPUS": "1", "MAX_INPUT_LENGTH": "4096"},
        "ml.g5.2xlarge",
    )
    arn = recs["endpoint"]["EndpointArn"]
    return Draft(
        "aws-sagemaker-llm",
        "llm",
        "medium",
        "SageMaker endpoint serving an instruct LLM with the TGI container.",
        {
            "sagemaker-endpoints": [recs["endpoint"]],
            "sagemaker-endpoint-configs": [recs["endpoint_config"]],
            "sagemaker-models": [recs["model"]],
        },
        expected=[
            TruthEntity(
                "resource",
                f"resource:{arn}",
                "llm",
                {"platform": "aws", "name": name},
                f"TGI inference image with HF_MODEL_ID {model_id}",
            )
        ],
    )


def aws_lambda_llm(rd: Rand) -> Draft:
    name = rd.choice(("summarise-tickets", "translate-notes", "classify-feedback")) + f"-{rd.hexid(2)}"
    key = rd.choice(("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY"))
    fn = _lambda(rd, name, {key: "redacted", "MODEL": "gpt-4o-mini", "TABLE_NAME": "tickets"}, f"{name}-role")
    return Draft(
        "aws-lambda-llm",
        "llm",
        "medium",
        "Lambda holding a provider key name and a model name, no agent binding.",
        {"lambda-functions": [fn]},
        expected=[
            TruthEntity(
                "resource",
                f"resource:{fn['FunctionArn']}",
                "llm",
                {"platform": "aws", "name": name},
                f"environment name {key} and MODEL",
            )
        ],
    )


def aws_knowledge_base(rd: Rand) -> Draft:
    kb_id = rd.hexid(10).upper()
    arn = _arn("bedrock", f"knowledge-base/{kb_id}")
    kb = {
        "knowledgeBaseId": kb_id,
        "name": rd.choice(("policies-kb", "product-docs-kb", "runbooks-kb")),
        "status": "ACTIVE",
        "updatedAt": iso(rd),
        "description": "",
    }
    detail = {
        "knowledgeBase": {
            **kb,
            "knowledgeBaseArn": arn,
            "roleArn": _role("AmazonBedrockExecutionRoleForKnowledgeBase"),
            "knowledgeBaseConfiguration": {
                "type": "VECTOR",
                "vectorKnowledgeBaseConfiguration": {
                    "embeddingModelArn": (
                        f"arn:aws:bedrock:{REGION}::foundation-model/amazon.titan-embed-text-v2:0"
                    )
                },
            },
            "storageConfiguration": {"type": "OPENSEARCH_SERVERLESS"},
        }
    }
    return Draft(
        "aws-knowledge-base",
        "llm",
        "medium",
        "Bedrock knowledge base (RAG store) without an agent.",
        {
            "bedrock-knowledge-bases": [kb],
            "_files": [{"path": f"aws/bedrock-agent/get-knowledge-base.{kb_id}.json", "json": detail}],
        },
        expected=[
            TruthEntity(
                "resource",
                f"resource:{arn}",
                "llm",
                {"platform": "aws", "name": kb["name"]},
                "bedrock-agent list-knowledge-bases: vector store with an embedding model",
            )
        ],
    )


def aws_lambda_plain(rd: Rand) -> Draft:
    name = rd.choice(("image-resizer", "order-webhook", "nightly-report", "s3-indexer")) + f"-{rd.hexid(2)}"
    fn = _lambda(
        rd, name, {"TABLE_NAME": "orders", "BUCKET": "acme-uploads", "LOG_LEVEL": "INFO"}, f"{name}-role"
    )
    return Draft("aws-lambda-plain", "none", "easy", "Ordinary Lambda.", {"lambda-functions": [fn]})


def aws_lambda_decoy(rd: Rand) -> Draft:
    name, env = rd.choice(
        (
            (
                "field-agent-dispatcher",
                {"SQS_URL": "https://sqs.us-east-1.amazonaws.com/123456789012/dispatch", "REGION": REGION},
            ),
            (
                "bedrock-world-backup",
                {"S3_BUCKET": "acme-minecraft-backups", "WORLD_PATH": "/worlds/bedrock_level"},
            ),
            ("mcp-mapping-sync", {"MCP_VERSION": "9.42", "S3_BUCKET": "acme-mod-tools"}),
            ("copilot-seat-report", {"GITHUB_ORG": "acme", "TABLE_NAME": "seats"}),
            ("ssm-agent-rotator", {"SSM_PARAMETER": "/ops/agent/version"}),
        )
    )
    fn = _lambda(rd, name, env, f"{name}-role")
    return Draft(
        "aws-lambda-decoy",
        "none",
        "hard",
        "Lambda whose name sounds like AI; configuration holds none.",
        {"lambda-functions": [fn]},
    )


def aws_sagemaker_classic(rd: Rand) -> Draft:
    name = rd.choice(("churn-xgb", "fraud-score", "demand-forecast")) + f"-{rd.hexid(3)}"
    image, env = rd.choice(((XGB_IMAGE, {}), (SKLEARN_IMAGE, {"SAGEMAKER_PROGRAM": "inference.py"})))
    recs = _sagemaker(rd, name, image, env, "ml.m5.large")
    return Draft(
        "aws-sagemaker-classic",
        "none",
        "hard",
        "SageMaker endpoint serving a tabular model: ML, not an LLM.",
        {
            "sagemaker-endpoints": [recs["endpoint"]],
            "sagemaker-endpoint-configs": [recs["endpoint_config"]],
            "sagemaker-models": [recs["model"]],
        },
    )


def aws_iam_role_plain(rd: Rand) -> Draft:
    name = rd.choice(("datadog-agent-role", "jenkins-agent-role", "ssm-agent-instance-role", "eks-node-role"))
    role = {
        "RoleName": name,
        "Arn": _role(name),
        "Path": "/",
        "RoleId": "AROA" + rd.hexid(17).upper(),
        "CreateDate": iso(rd, 2024),
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        },
        "AttachedManagedPolicies": [
            {
                "PolicyName": "AmazonSSMManagedInstanceCore",
                "PolicyArn": "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
            }
        ],
    }
    return Draft(
        "aws-iam-role-plain",
        "none",
        "medium",
        "Instance role for an infrastructure agent.",
        {"iam-roles": [role]},
    )


AWS_AGENT = (aws_bedrock_agent, aws_agentcore_runtime, aws_agentcore_gateway, aws_lambda_agent)
AWS_LLM = (aws_sagemaker_llm, aws_lambda_llm, aws_knowledge_base)
AWS_NONE = (aws_lambda_plain, aws_lambda_decoy, aws_sagemaker_classic, aws_iam_role_plain)


# --- Kubernetes families -----------------------------------------------------


def _workload(
    rd: Rand,
    kind: str,
    name: str,
    namespace: str,
    image: str,
    *,
    args: list[str] | None = None,
    env: dict[str, str] | None = None,
    secret_env: list[str] | None = None,
    ports: list[int] | None = None,
    gpu: bool = False,
    labels: dict[str, str] | None = None,
) -> dict[str, Any]:
    container: dict[str, Any] = {"name": name.split("-")[0], "image": image}
    if args:
        container["args"] = args
    env_list: list[dict[str, Any]] = [{"name": k, "value": v} for k, v in (env or {}).items()]
    env_list += [
        {"name": k, "valueFrom": {"secretKeyRef": {"name": f"{name}-secrets", "key": k.lower()}}}
        for k in secret_env or []
    ]
    if env_list:
        container["env"] = env_list
    if ports:
        container["ports"] = [{"containerPort": p, "protocol": "TCP"} for p in ports]
    if gpu:
        container["resources"] = {"limits": {"nvidia.com/gpu": 1}}
    spec: dict[str, Any] = {
        "selector": {"matchLabels": {"app": name}},
        "template": {
            "metadata": {"labels": {"app": name, **(labels or {})}},
            "spec": {"containers": [container]},
        },
    }
    if kind != "DaemonSet":
        spec["replicas"] = rd.randint(1, 3)
    return {
        "apiVersion": "apps/v1",
        "kind": kind,
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {"app": name, **(labels or {})},
            "creationTimestamp": iso(rd, 2025),
        },
        "spec": spec,
    }


def _k8s_draft(
    family: str, label: str, difficulty: str, rationale: str, wl: dict[str, Any], evidence: str
) -> Draft:
    key = f"k8s:{wl['metadata']['namespace']}/{wl['kind']}/{wl['metadata']['name']}"
    expected = (
        [TruthEntity("workload", key, label, {"platform": "kubernetes"}, evidence)] if label != "none" else []
    )
    return Draft(family, label, difficulty, rationale, {"workloads": [wl]}, expected=expected)


def k8s_agent_deployment(rd: Rand) -> Draft:
    name = rd.choice(("research-agent", "ticket-triage-agent", "ops-crew")) + f"-{rd.hexid(2)}"
    framework = rd.choice(("crewai", "langgraph", "openai-agents"))
    if framework == "crewai":
        args, env = ["python", "-m", "crewai", "run"], {"CREWAI_TELEMETRY_OPT_OUT": "true"}
        evidence = "container args run crewai; secret env OPENAI_API_KEY"
    elif framework == "langgraph":
        args, env = ["langgraph", "up", "--host", "0.0.0.0"], {"LANGGRAPH_CONFIG": "/app/langgraph.json"}
        evidence = "container args run langgraph; LANGGRAPH_CONFIG env"
    else:
        args, env = (
            ["python", "agent_server.py"],
            {"OPENAI_AGENTS_DISABLE_TRACING": "1", "AGENT_MODEL": "gpt-4.1"},
        )
        evidence = "OPENAI_AGENTS_DISABLE_TRACING env beside a provider key name"
    wl = _workload(
        rd,
        "Deployment",
        name,
        rd.choice(("agents", "ai", "platform")),
        f"ghcr.io/acme/{name}:1.{rd.randint(0, 9)}",
        args=args,
        env=env,
        secret_env=["OPENAI_API_KEY"],
        ports=[8000],
    )
    return _k8s_draft(
        "k8s-agent-deployment", "agent", "medium", "Deployment running an agent framework.", wl, evidence
    )


def k8s_mcp_server(rd: Rand) -> Draft:
    choice = rd.choice(("github", "filesystem", "custom"))
    if choice == "github":
        name, image, args = "github-mcp", "ghcr.io/github/github-mcp-server:0.4.0", ["stdio"]
        evidence = "image ghcr.io/github/github-mcp-server"
    elif choice == "filesystem":
        name, image, args = (
            "mcp-filesystem",
            "node:22-alpine",
            ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"],
        )
        evidence = "args npx @modelcontextprotocol/server-filesystem"
    else:
        name, image, args = (
            "crm-mcp",
            f"ghcr.io/acme/crm-mcp:{rd.randint(1, 4)}.0",
            ["python", "-m", "crm_mcp.server", "--transport", "streamable-http", "--port", "8000"],
        )
        evidence = "args run an MCP server with streamable-http transport"
    wl = _workload(
        rd,
        "Deployment",
        f"{name}-{rd.hexid(2)}",
        rd.choice(("mcp", "tools", "ai")),
        image,
        args=args,
        ports=[8000],
        labels={"app.kubernetes.io/component": "mcp-server"},
    )
    return _k8s_draft("k8s-mcp-server", "agent", "medium", "MCP server deployment.", wl, evidence)


def k8s_agent_platform(rd: Rand) -> Draft:
    name, image, port, evidence = rd.choice(
        (
            ("langflow", "langflowai/langflow:1.5.0", 7860, "image langflowai/langflow: agent builder"),
            ("flowise", "flowiseai/flowise:3.0.1", 3000, "image flowiseai/flowise: agent builder"),
            (
                "openclaw-gateway",
                "ghcr.io/openclaw/openclaw:2026.9",
                18789,
                "image openclaw/openclaw: personal agent gateway",
            ),
            ("dify-api", "langgenius/dify-api:1.7.0", 5001, "image langgenius/dify-api: agent platform"),
        )
    )
    wl = _workload(rd, "Deployment", f"{name}-{rd.hexid(2)}", "ai", image, ports=[port])
    return _k8s_draft("k8s-agent-platform", "agent", "easy", "Agent platform deployment.", wl, evidence)


def k8s_model_server(rd: Rand) -> Draft:
    name, image, args, port, gpu, evidence = rd.choice(
        (
            (
                "vllm",
                "vllm/vllm-openai:v0.10.1",
                ["--model", "meta-llama/Llama-3.1-8B-Instruct", "--port", "8000"],
                8000,
                True,
                "image vllm/vllm-openai serving a model",
            ),
            ("ollama", "ollama/ollama:0.12.3", [], 11434, True, "image ollama/ollama"),
            (
                "tgi",
                "ghcr.io/huggingface/text-generation-inference:3.3.4",
                ["--model-id", "mistralai/Mistral-7B-Instruct-v0.3"],
                80,
                True,
                "image text-generation-inference",
            ),
            (
                "open-webui",
                "ghcr.io/open-webui/open-webui:v0.6.26",
                [],
                8080,
                False,
                "image open-webui/open-webui: chat UI",
            ),
            (
                "litellm",
                "ghcr.io/berriai/litellm:main-v1.77.3",
                ["--config", "/app/config.yaml"],
                4000,
                False,
                "image berriai/litellm: model gateway",
            ),
        )
    )
    wl = _workload(
        rd,
        "Deployment",
        f"{name}-{rd.hexid(2)}",
        rd.choice(("ai", "ml", "llm")),
        image,
        args=args or None,
        ports=[port],
        gpu=gpu,
    )
    return _k8s_draft("k8s-model-server", "llm", "easy", "Model serving or chat UI deployment.", wl, evidence)


def k8s_plain(rd: Rand) -> Draft:
    name, image, ports = rd.choice(
        (
            ("web", "nginx:1.27-alpine", [80]),
            ("api", "ghcr.io/acme/orders-api:3.2.1", [8080]),
            ("postgres", "postgres:16", [5432]),
            ("redis", "redis:7-alpine", [6379]),
            ("grafana", "grafana/grafana:11.2.0", [3000]),
        )
    )
    wl = _workload(
        rd,
        rd.choice(("Deployment", "StatefulSet")),
        f"{name}-{rd.hexid(2)}",
        rd.choice(("web", "data", "ops")),
        image,
        ports=ports,
    )
    return _k8s_draft("k8s-plain", "none", "easy", "Ordinary workload.", wl, "")


def k8s_decoy(rd: Rand) -> Draft:
    kind, name, image, args, ports = rd.choice(
        (
            ("DaemonSet", "datadog-agent", "gcr.io/datadoghq/agent:7.58.0", [], [8125]),
            (
                "Deployment",
                "jenkins-agent",
                "jenkins/inbound-agent:3273.v4cfe44cde7b_-1",
                ["-url", "http://jenkins:8080"],
                [],
            ),
            ("Deployment", "minecraft-bedrock", "itzg/minecraft-bedrock-server:latest", [], [19132]),
            ("Deployment", "agent-portal", "ghcr.io/acme/agent-portal:2.1.0", [], [3000]),
            ("DaemonSet", "elastic-agent", "docker.elastic.co/beats/elastic-agent:8.15.0", [], []),
            ("Deployment", "copilot-seat-sync", "ghcr.io/acme/copilot-seat-sync:0.3", ["--org", "acme"], []),
        )
    )
    wl = _workload(
        rd,
        kind,
        f"{name}-{rd.hexid(2)}",
        rd.choice(("monitoring", "ci", "games", "web")),
        image,
        args=args or None,
        ports=ports or None,
    )
    return _k8s_draft(
        "k8s-decoy", "none", "hard", "Workload whose name sounds like AI; image and config hold none.", wl, ""
    )


K8S_AGENT = (k8s_agent_deployment, k8s_mcp_server, k8s_agent_platform)
K8S_LLM = (k8s_model_server,)
K8S_NONE = (k8s_plain, k8s_decoy)
