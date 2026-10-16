"""Model-identifier literal recognition for the filesystem connector.

A quoted literal or a model-ish key's value is handed to the anchored
``model`` signatures only when it carries a vendor stem, and a stemmed
literal that names a tool, package or product is rejected
(``_model_lookalike``). The weights and caps here keep a project known only
from model identifiers below the strong confidence band (see the
``shadowscan.connectors.code.filesystem`` module docstring).
"""

from __future__ import annotations

import re

import regex

# A model identifier found as a literal is medium-weight evidence: it names a
# model the code may call, not an installed SDK (see _scan_model_literals).
MODEL_LITERAL_MAX_WEIGHT = 0.5
MODEL_IDS_ONLY_MAX_CONFIDENCE = 0.6
# Model-id candidates (literals with a vendor stem) the model-identifier pass
# reads per file before it stops; ordinary strings do not count.
MAX_MODEL_LITERALS_PER_FILE = 400
# Model matches kept per signature per file.
MAX_MODEL_MATCHES_PER_SIGNATURE = 3


# Model identifiers in source and configuration (see _scan_model_literals). A
# quoted literal of the id alphabet, closed by the quote that opened it; the
# run is possessive, so a quote that no matching quote follows costs one pass
# over at most 161 characters. Unquoted values follow a model-ish key in YAML,
# TOML, INI and dotenv files (``model: gpt-4o``, ``OPENAI_MODEL=gpt-4o``,
# ``deployment: my-gpt4``, ``spring.ai.openai.chat.options.model=gpt-4o``); the
# key search is anchored to a line start, the dotted prefix before ``model`` or
# ``deployment`` is bounded and lazy and the rest of the key possessive, so a
# line that is one long run of key characters costs a bounded number of
# attempts rather than a quadratic backtrack.
_MODEL_QUOTED_RE = regex.compile(r"""(["'`])([A-Za-z0-9][A-Za-z0-9._:/@-]{2,160}+)\1""")
_MODEL_KEY_VALUE_RE = regex.compile(
    r"""(?im)^[ \t]*+(?:-[ \t]*+)?["']?"""
    r"""(?:[A-Za-z0-9_.-]{0,80}?(?:model|deployment)[A-Za-z0-9_.-]*+|llm|engine)["']?"""
    r"""[ \t]*+[:=][ \t]*+["'`]?+([A-Za-z0-9][A-Za-z0-9._:/@-]{2,160}+)"""
)
# A literal that reaches the matcher through an open-ended family names a model
# only in the vendor's own shape. ``gpt-`` is followed by a version digit or
# the open-weight ``oss-`` family: ``gpt-j``, ``gpt-neox-20b`` (EleutherAI),
# ``gpt-tokenizer`` and ``gpt-engineer`` are not OpenAI models. The reasoning
# series carries a variant or a release date: ``o1-visa`` and ``o3-build`` do
# not. For every family (``grok-`` and ``qwen`` included) a segment that names
# a tool, package or product (``gpt-3-encoder``, ``gpt-4all``,
# ``grok-1-formatter``, ``qwen-agent``) is never a model id, whatever the stem.
_MODEL_FAMILY_SHAPES: tuple[tuple[str, regex.Pattern[str]], ...] = (
    ("gpt-", regex.compile(r"^gpt-(?:\d|oss-)")),
    ("o1-", regex.compile(r"^o1-(?:mini|preview|pro|\d{4}-\d{2}-\d{2})")),
    ("o3-", regex.compile(r"^o3-(?:mini|pro|deep-research|\d{4}-\d{2}-\d{2})")),
    ("o4-", regex.compile(r"^o4-(?:mini)")),
)
_MODEL_TOOLING_SEGMENTS = frozenset(
    {
        "4all",
        "academic",
        "agent",
        "agents",
        "app",
        "bench",
        "bot",
        "build",
        "cli",
        "client",
        "crawler",
        "encoder",
        "engineer",
        "formatter",
        "kit",
        "lib",
        "parser",
        "pattern",
        "patterns",
        "pilot",
        "plugin",
        "researcher",
        "sdk",
        "server",
        "tokenizer",
        "tools",
        "ui",
        "utils",
        "visa",
        "web",
    }
)
_MODEL_TOOLING_NAMES = frozenset({"qwen-code", "qwen-cli", "gpt4all", "gpt-4all", "gpt-3-encoder"})
_MODEL_SEGMENT_RE = regex.compile(r"[-_./:@]")


# A literal ending in a file extension names a file (``sonar-project.properties``,
# ``gpt-4-turbo-docs.md``), never a model id; ``gpt-4.1`` ends in a digit.
_MODEL_FILE_NAME_RE = re.compile(
    r"\.(?:properties|json|jsonc|ya?ml|toml|ini|cfg|conf|md|mdx|txt|rst|html?|xml|csv|lock|log"
    r"|py|[cm]?[jt]sx?|go|rs|java|kt|cs|rb|php|sh|ps1|bat)$"
)


def _model_lookalike(candidate: str) -> bool:
    """Whether a vendor-stemmed literal names a tool, package or product instead of a model.

    ``candidate`` is lower-cased. The ``gpt-`` and ``o1-``/``o3-``/``o4-``
    families, whose signature patterns are open-ended, are held to the vendor's
    id shape (``_MODEL_FAMILY_SHAPES``); a known tool name
    (``_MODEL_TOOLING_NAMES``) and any id whose segments name tooling
    (``_MODEL_TOOLING_SEGMENTS``) are rejected whatever the family.
    """
    if candidate in _MODEL_TOOLING_NAMES or _MODEL_FILE_NAME_RE.search(candidate):
        return True
    for stem, shape in _MODEL_FAMILY_SHAPES:
        if candidate.startswith(stem):
            if shape.match(candidate) is None:
                return True
            break
    return any(segment in _MODEL_TOOLING_SEGMENTS for segment in _MODEL_SEGMENT_RE.split(candidate))


# A literal is handed to the anchored ``model`` signatures only when it carries
# a vendor stem; everything else in a source file is an ordinary string. Where
# a signature's family prefix is open-ended (``gemini-``, ``mistral-``,
# ``grok-``, ``embed-``, ``rerank-``, ``sonar``) the stems name the vendor's id
# families, so ``gemini-python/1.8.2`` (an exchange client's user agent),
# ``grok-pattern`` and ``sonar-scanner`` never reach the matcher.
_MODEL_STEMS = (
    "claude",
    "gpt-",
    "o1-",
    "o3-",
    "o4-",
    "text-embedding",
    "gemini-1",
    "gemini-2",
    "gemini-3",
    "gemini-pro",
    "gemini-flash",
    "gemini-embedding",
    "gemini-exp",
    "gemini-live",
    "gemini/",
    "mistral-large",
    "mistral-medium",
    "mistral-small",
    "mistral-tiny",
    "mistral-embed",
    "mistral-nemo",
    "mistral-saba",
    "mistral-ocr",
    "mistral-moderation",
    "mistral-7b",
    "open-mistral",
    "mistral/",
    "mixtral-",
    "codestral",
    "ministral-",
    "pixtral-",
    "magistral",
    "devstral",
    "command-",
    "embed-english",
    "embed-multilingual",
    "embed-v",
    "rerank-english",
    "rerank-multilingual",
    "rerank-v",
    "grok-1",
    "grok-2",
    "grok-3",
    "grok-4",
    "grok-beta",
    "grok-vision",
    "grok-code",
    "deepseek",
    "titan",
    "nova-",
    "anthropic.",
    "amazon.",
    "meta.",
    "cohere.",
    "bedrock/",
    "vertex_ai/",
    "azure/",
    "openai/",
    "anthropic/",
    "ollama/",
    "ollama_chat/",
    "openrouter/",
    "together_ai/",
    "groq/",
    "huggingface/",
    "perplexity/",
    "sonar-pro",
    "sonar-reasoning",
    "sonar-deep",
    "sonar-small",
    "sonar-medium",
    "sonar-large",
    "cerebras/",
    "xai/",
    "voyage-",
    "llama",
    "qwen",
    "@cf/",
    "@hf/",
    "arn:aws:bedrock",
)
# A value under one of these prefixes is a route (``bedrock/anthropic.claude-...``,
# ``openrouter/anthropic/claude-3.5-sonnet``): its last path segment is the
# model id and is matched too. Any other ``/`` (``EleutherAI/gpt-neox-20b``, an
# npm scope, a URL path) is a namespace, and the value is read whole only.
_MODEL_ROUTE_PREFIXES = tuple(stem for stem in _MODEL_STEMS if stem.endswith("/")) + ("arn:aws:bedrock",)
# The stems as one alternation of plain strings: the per-literal test runs for
# every quoted string of a file inside the match iterator, where an ``any``
# over each stem costs several times more.
_MODEL_STEM_RE = re.compile("|".join(map(re.escape, _MODEL_STEMS)))


def _has_model_stem(value: str) -> bool:
    """Whether ``value`` carries a vendor stem, so it is a model-id candidate."""
    return _MODEL_STEM_RE.search(value.lower()) is not None


# Configuration formats whose literals the model-identifier pass reads. Prose
# (.md, .mdc, .mdx, .txt) is never read; dotenv files are recognised by name.
_MODEL_LITERAL_CONFIG_EXTENSIONS = frozenset(
    {
        ".yaml",
        ".yml",
        ".json",
        ".jsonc",
        ".json5",
        ".toml",
        ".tf",
        ".tfvars",
        ".hcl",
        ".bicep",
        ".env",
        ".cfg",
        ".ini",
        ".properties",
    }
)
