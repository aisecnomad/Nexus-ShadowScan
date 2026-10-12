"""Tools in scope for the benchmark that cannot run against an offline corpus.

Each adapter here always reports an unavailable reason, so the run manifest
and the report carry the documented blocker instead of silently omitting the
tool. The evidence behind each reason (commands run, exact errors) is in the
benchmark README.
"""

from __future__ import annotations

from pathlib import Path

from tools.shadowbench.estate.adapters import (
    Command,
    Normalized,
    ToolConfig,
    ToolSpec,
    run_version,
)
from tools.shadowbench.estate.corpus import EstateCorpus


class _NotRunnableAdapter:
    spec: ToolSpec
    reason: str

    def unavailable_reason(self, cfg: ToolConfig) -> str | None:
        return self.reason

    def version(self, cfg: ToolConfig) -> str:
        binary = cfg.tool(self.spec.id).get("bin")
        if not binary:
            return "not installed"
        return run_version([str(binary), "--version"], pattern=r"(\d+\.\d+\.\d+\S*)")

    def units(self, cfg: ToolConfig, estate: Path, corpus: EstateCorpus) -> list[str]:
        return []

    def commands(self, cfg: ToolConfig, unit: str, estate: Path, out_dir: Path) -> list[Command]:
        return []

    def normalize(self, unit: str, out_dir: Path) -> Normalized:
        return Normalized(error=self.reason)


class PowerPwnAdapter(_NotRunnableAdapter):
    spec = ToolSpec(
        id="power_pwn",
        name="power-pwn",
        vendor="Zenity (mbrg)",
        surfaces=frozenset({"lowcode", "saas"}),
        categories=frozenset({"lowcode-agent", "bot-app"}),
        notes="live-tenant recon toolkit; no offline-export ingestion mode",
    )
    reason = (
        "not runnable by design: every discovery path (recon, dump, copilot-studio-hunter, "
        "llm-hound) requires a live Microsoft 365 / Power Platform tenant with interactive "
        "MSAL authentication or live internet scanning; there is no offline-export mode"
    )


class CartographyAdapter(_NotRunnableAdapter):
    spec = ToolSpec(
        id="cartography",
        name="Cartography",
        vendor="CNCF",
        surfaces=frozenset({"cloud", "identity"}),
        categories=frozenset({"cloud-ai", "service-identity"}),
        notes="live-estate graph syncer; AI modules pull live APIs into a running Neo4j",
    )
    reason = (
        "not runnable by design: AI-relevant modules (anthropic, openai, aws bedrock/sagemaker, "
        "gcp vertex) sync live APIs with admin credentials into a running Neo4j server; without "
        "Neo4j it exits 1 (ServiceUnavailable) and there is no offline-export ingestion mode"
    )
