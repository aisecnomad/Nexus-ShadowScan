"""The placeholder vocabulary that the placeholder test and the credential judge share.

Documentation stands for a credential with placeholder words ('your_api_key',
'replace-me') and, translated, with a possessive and the credential's noun
('sua_chave_openai', 'votre-cle-api', 'deine_api_schluessel'). A passphrase a
person picks is also written as a possessive and words ('ton-jardin-secret',
'votre-jardin-secret', 'su-token-de-casa'), so a possessive phrase is a
template only when every word after its possessive is in the closed
vocabulary of templates (``TEMPLATE_WORDS``). ``possessive_phrase`` is that
one test: :func:`shadowscan.connectors.common.placeholder_reason` reads such a
template as a placeholder, and :mod:`shadowscan.signatures.matcher` reads it as
a label, so a value is a credential to both or to neither.
"""

from __future__ import annotations

import re

# Lowercase words that documentation uses where a real key would go.
PLACEHOLDER_WORDS: tuple[str, ...] = (
    "replaceme",
    "replace",
    "placeholder",
    "changeme",
    "example",
    "sample",
    "dummy",
    "fake",
    "test",
    "insert",
    "paste",
    "here",
    "todo",
    "your",
    "redacted",
    "mock",
    "demo",
)
# The same words in the languages documentation is commonly translated into.
# Every word has at least four letters, and each counts only as a whole word
# between separators (``sua_chave_aqui``), never across a case boundary or as
# the start or end of a longer run of letters as the English words do: random
# keys hold short runs such as ``hier`` or ``aqui`` often enough that matching
# them there doubled how often a real key was taken for a placeholder.
TRANSLATED_PLACEHOLDER_WORDS: frozenset[str] = frozenset(
    {
        # Portuguese
        "exemplo",
        "substitua",
        "insira",
        "aqui",
        # Spanish
        "ejemplo",
        "reemplazar",
        "reemplace",
        "inserte",
        # French
        "exemple",
        "remplacer",
        "remplacez",
        # German
        "beispiel",
        "ersetzen",
        "hier",
        # Italian
        "esempio",
        "sostituire",
        # Dutch
        "voorbeeld",
        # Indonesian and Turkish
        "contoh",
        "ornek",
    }
)
# The translated credential nouns and the longer possessives, read as whole
# words between separators the same way. They are words a passphrase is made
# of too ('sua-senha-forte-azul', 'votre-jardin-secret'): in a phrase of words
# they mark a placeholder only when every word of it is ``TEMPLATE_WORDS``.
TRANSLATED_CREDENTIAL_WORDS: frozenset[str] = frozenset(
    {
        "chave",
        "senha",
        "clave",
        "clef",
        "schluessel",
        "chiave",
        "sleutel",
        "kunci",
        "anahtar",
        "votre",
        "dein",
        "deine",
        "ihre",
        "jouw",
    }
)
# The closed vocabulary of a possessive template: what it stands for (the
# credential's noun and its qualifiers, in English and in each translation),
# whose it is (the provider), the placeholder words of every language, and
# the short words that join them ('su_clave_de_api').
TEMPLATE_WORDS: frozenset[str] = frozenset(
    {
        # The credential's noun.
        "api",
        "apikey",
        "auth",
        "credential",
        "credentials",
        "key",
        "keys",
        "pass",
        "passphrase",
        "passwd",
        "password",
        "passwords",
        "pwd",
        "secret",
        "secrets",
        "token",
        "tokens",
        # Translated nouns, and the forms too short for TRANSLATED_CREDENTIAL_WORDS.
        "chaves",
        "senhas",
        "claves",
        "contrasena",
        "cle",
        "cles",
        "clefs",
        "passe",
        "mot",
        "schlussel",
        "passwort",
        "kennwort",
        "sleutels",
        "wachtwoord",
        "chiavi",
        "sifre",
        "secreta",
        "secreto",
        # Its qualifiers.
        "access",
        "account",
        "app",
        "application",
        "bearer",
        "bot",
        "client",
        "integration",
        "license",
        "master",
        "org",
        "organization",
        "personal",
        "private",
        "project",
        "service",
        "session",
        "signing",
        "subscription",
        "webhook",
        "workspace",
        # Whose it is.
        "anthropic",
        "aws",
        "azure",
        "claude",
        "cloudflare",
        "cohere",
        "deepseek",
        "elevenlabs",
        "firebase",
        "firecrawl",
        "fireworks",
        "gcp",
        "gemini",
        "github",
        "gitlab",
        "google",
        "groq",
        "hf",
        "huggingface",
        "langchain",
        "langsmith",
        "litellm",
        "mistral",
        "notion",
        "openai",
        "openrouter",
        "perplexity",
        "pinecone",
        "replicate",
        "sendgrid",
        "serper",
        "slack",
        "stripe",
        "supabase",
        "tavily",
        "twilio",
        "vercel",
        "voyage",
        # Where it goes, in the languages above, and what it is.
        "aca",
        "ici",
        "id",
        "new",
        "own",
        "qui",
        "valeur",
        "valor",
        "value",
        "waarde",
        "wert",
        # The short words that join them.
        "da",
        "de",
        "del",
        "di",
        "do",
        "du",
        "for",
        "of",
    }
    | set(PLACEHOLDER_WORDS)
    | TRANSLATED_PLACEHOLDER_WORDS
    | TRANSLATED_CREDENTIAL_WORDS
)
# A value that is only a possessive and words (``your_api_key``,
# ``sua_chave_openai``, ``votre-cle-api``): a placeholder in any of the
# languages documentation is written in when the words are ``TEMPLATE_WORDS``;
# a token carries digits, which the word tail excludes. A separator must
# follow the possessive: without one, every letters-only token that begins
# with ``Su``, ``Ta``, ``Je`` or ``Ton`` would read as a possessive and a word.
POSSESSIVES = (
    "your|sua|seu|suas|seus|su|tu|tus|votre|vos|ton|ta|dein|deine|ihr|ihre|jouw|uw|je"
    "|tua|tuo|tuoi|vostra|vostro|anda|senin|sizin"
)
# Each word after the possessive is one case, as a written word is: a mixed-case
# run ('ta-QzWpLmNxVbRtYcDfGh') is a token's body, not a word.
_POSSESSIVE_PHRASE = re.compile(
    rf"(?P<possessive>(?i:{POSSESSIVES}))(?P<words>(?:[_-](?:[a-z]+|[A-Z][a-z]*|[A-Z]+))*)(?P<end>[_-]?)"
)
_WORD_SEPARATOR = re.compile(r"[_-]")
# A phrase of words: two or more one-case words between separators.
_WORD_PHRASE = re.compile(r"(?:[a-z]+|[A-Z][a-z]*|[A-Z]+)(?:[-_.](?:[a-z]+|[A-Z][a-z]*|[A-Z]+))+")


def possessive_phrase(value: str) -> bool | None:
    """Whether a possessive phrase is a template, or None when ``value`` is no possessive phrase.

    A phrase is a whole value of a possessive and one-case words after it,
    each after a separator. It is a template when every word is
    ``TEMPLATE_WORDS`` ('your_client_secret', 'tu_clave', 'SUA_CHAVE_AQUI',
    'sua_serper_api_key'), and a passphrase when any word is not
    ('ton-jardin-secret', 'votre-jardin-secret', 'su-token-de-casa',
    'je-suis-le-patron'), whichever word comes first or last. A possessive of
    three letters or more alone, or with a separator after it ('sua',
    'seu_token_'), is a template; a two-letter one alone ('su-') is neither.
    """
    match = _POSSESSIVE_PHRASE.fullmatch(value)
    if match is None:
        return None
    words = [word.lower() for word in _WORD_SEPARATOR.split(match["words"]) if word]
    if not words:
        return True if len(match["possessive"]) >= 3 else None
    return all(word in TEMPLATE_WORDS for word in words)


def word_phrase(value: str) -> bool:
    """Whether ``value`` is a phrase of two or more one-case words joined by '-', '_' or '.'."""
    return _WORD_PHRASE.fullmatch(value) is not None


def template_phrase(value: str) -> bool:
    """Whether every word of a phrase of words is ``TEMPLATE_WORDS`` ('chave_api', 'senha_aqui')."""
    return all(word.lower() in TEMPLATE_WORDS for word in re.split(r"[-_.]", value))
