"""ShadowScan: discover shadow AI agents across your organisation.

Surfaces covered:

* code repositories (local trees, GitHub, GitLab)
* identity providers (Okta, Microsoft Entra ID, Google Workspace, Auth0) and JWTs
* LLM inference gateway logs (LiteLLM, Portkey, Kong, Cloudflare, Helicone, Langfuse, Bedrock,
  Azure OpenAI, Vertex, provider usage exports, access logs) and OpenTelemetry GenAI spans
* low-code platforms & copilots (Power Platform/Copilot Studio, Salesforce Agentforce, ServiceNow,
  n8n, Make, Zapier, Workato)
* SaaS applications (Slack, Microsoft Teams, GitHub Apps, Atlassian, Notion, Zoom, generic app
  inventories)
* cloud accounts (AWS, GCP, Azure, Oracle Cloud) and Kubernetes/OpenShift workload exports
* endpoints (developer workstations, host, MCP, local model and eBPF inventories)
* network logs (DNS, TLS SNI and flow records)
* running processes

Detection is signature driven: see :mod:`shadowscan.signatures`. The scan pipeline is
:class:`shadowscan.engine.Engine`; ``docs/architecture.md`` describes the package layout.
"""

__version__ = "0.1.2"
__all__ = ["__version__"]
