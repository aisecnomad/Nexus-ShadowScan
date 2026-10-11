"""Tool-neutral fact taxonomy for the nine-surface estate benchmark.

Every expected or predicted item is a fact ``<category>:<value>``. The code
surface reuses the eight categories of the code-surface discovery benchmark
(`tools.discovery_benchmark.taxonomy`); the other surfaces add estate
categories for things that exist as tenant or infrastructure state rather
than as code. The vocabulary is shared by the ground-truth labels and by
every adapter, so no tool is scored against a vocabulary it cannot express,
and it is independent of every tool under test, including ShadowScan's
signature packs.
"""

from __future__ import annotations

import re

from tools.discovery_benchmark import taxonomy as code_taxonomy

SURFACES: tuple[str, ...] = (
    "code",
    "identity",
    "gateway",
    "lowcode",
    "saas",
    "cloud",
    "endpoint",
    "network",
    "runtime",
)

#: Categories reused verbatim from the code-surface benchmark. On the code
#: surface they mean what they mean there; `mcp-client-config`, `agent-config`
#: and `mcp` also appear on the endpoint surface for client configurations
#: found in home trees.
CODE_CATEGORIES: tuple[str, ...] = code_taxonomy.CATEGORIES

#: Estate categories. Values are product or platform slugs, or `generic` for
#: a custom instance that no product slug fits.
ESTATE_CATEGORIES: tuple[str, ...] = (
    # identity: OAuth apps / consent grants to AI SaaS, and machine identities
    # (service principals, M2M clients) that act as or serve agents.
    "oauth-app",
    "service-identity",
    # identity: classified bearer tokens from token exports.
    "token",
    # saas: bots and apps installed in collaboration platforms.
    "bot-app",
    # lowcode: agents and AI-powered automations on low-code platforms.
    "lowcode-agent",
    # cloud: managed AI resources and AI workloads in cloud accounts.
    "cloud-ai",
    # endpoint: AI desktop/CLI clients and coding agents installed on hosts,
    # and local model stores.
    "ai-client",
    "model-store",
    # gateway: callers reconstructed from gateway or egress logs.
    "gateway-caller",
    # network: AI services contacted, observed from network logs.
    "ai-service-contact",
    # runtime: AI tools and agents observed running as processes.
    "agent-process",
)

CATEGORIES: tuple[str, ...] = CODE_CATEGORIES + ESTATE_CATEGORIES

_FACT = re.compile(r"[a-z][a-z0-9-]*:[a-z0-9][a-z0-9.-]*\Z")


def is_fact(value: str) -> bool:
    """True when `value` is `<category>:<value>` with a known category."""
    if not _FACT.match(value):
        return False
    return value.split(":", 1)[0] in CATEGORIES


def category(fact: str) -> str:
    """The category of a well-formed fact."""
    return fact.split(":", 1)[0]


#: `<category>:generic` matches one expected fact of its category, exactly as
#: in the code-surface benchmark.
GENERIC = "generic"

# --- Product slugs -----------------------------------------------------------
#
# Canonical value slugs for AI products that appear as OAuth apps, SaaS bots,
# endpoint clients or processes. Adapters map vendor display names onto these
# slugs; the table is ordered so the most specific pattern wins.

_PRODUCT_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bchat\s?gpt\b|\bopenai\b(?!.*agents sdk)"), "openai"),
    (re.compile(r"\bclaude\b|\banthropic\b"), "claude"),
    (re.compile(r"\bgemini\b"), "gemini"),
    (re.compile(r"\bcopilot studio\b"), "copilot-studio"),
    (re.compile(r"\bgithub copilot\b|\bcopilot\b"), "copilot"),
    (re.compile(r"\bperplexity\b"), "perplexity"),
    (re.compile(r"\bfireflies\b"), "fireflies"),
    (re.compile(r"\botter\b"), "otter-ai"),
    (re.compile(r"\bread\.?ai\b"), "read-ai"),
    (re.compile(r"\bfathom\b"), "fathom"),
    (re.compile(r"\bgong\b"), "gong"),
    (re.compile(r"\bglean\b"), "glean"),
    (re.compile(r"\bmoveworks\b"), "moveworks"),
    (re.compile(r"\bcoderabbit"), "coderabbit"),
    (re.compile(r"\bcursor\b"), "cursor"),
    (re.compile(r"\bwindsurf\b"), "windsurf"),
    (re.compile(r"\bcline\b"), "cline"),
    (re.compile(r"\bcodex\b"), "codex"),
    (re.compile(r"\bgoose\b"), "goose"),
    (re.compile(r"\bollama\b"), "ollama"),
    (re.compile(r"\blm\s?studio\b"), "lm-studio"),
    (re.compile(r"\bhugging\s?face\b"), "huggingface"),
    (re.compile(r"\bmistral\b|\ble chat\b"), "mistral"),
    (re.compile(r"\bdeepseek\b"), "deepseek"),
    (re.compile(r"\bgrok\b|\bx\.?ai\b"), "xai"),
    (re.compile(r"\bzapier agents?\b"), "zapier-agents"),
    (re.compile(r"\bagentforce\b|\beinstein\b"), "agentforce"),
    (re.compile(r"\bnow assist\b"), "now-assist"),
)


def product_slug(text: str) -> str | None:
    """Canonical product slug for a display name, or None."""
    lowered = text.lower()
    for pattern, slug in _PRODUCT_RULES:
        if pattern.search(lowered):
            return slug
    return None
