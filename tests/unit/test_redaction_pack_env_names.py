"""Every credential-named environment variable the signature packs detect has its value withheld.

The packs and the redaction rules are maintained separately: a pack can add a
variable whose last word names no credential ('AWS_BEARER_TOKEN_BEDROCK',
'LOBE_ACCESS_CODE'), which the suffix rules then miss. This test reads the
names from the shipped packs, so a new pack variable cannot reach evidence
snippets with its value.
"""

from __future__ import annotations

import pytest

from shadowscan.signatures.loader import load_signatures
from shadowscan.utils.redaction import REDACTED, sanitize, sanitize_text

# Words that make a variable name a credential's wherever they stand in it.
_CREDENTIAL_WORDS = frozenset(
    {"KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "PWD", "PASS", "PASSPHRASE"}
    | {"CREDENTIAL", "CREDENTIALS", "APIKEY", "SECRETKEY", "BEARER"}
)
# Synthetic, opaque and built at runtime so repository secret scanners do not flag it.
VALUE = "Qx7v" + "Lm2Rt9Kp4Wz8Nb3Hs6Jd1Fc5Gy0"


def _credential_env_names() -> list[str]:
    names: set[str] = set()
    for signature in load_signatures():
        for signal in signature.signals:
            if signal.type == "env":
                names.update(signal.names or [])
    return sorted(
        name
        for name in names
        if _CREDENTIAL_WORDS & set(name.upper().split("_")) or "ACCESS_CODE" in name.upper()
    )


CREDENTIAL_ENV_NAMES = _credential_env_names()


def test_the_packs_name_credential_variables() -> None:
    # Guards the parametrization below against a loader or schema change that yields nothing.
    assert len(CREDENTIAL_ENV_NAMES) > 100
    assert {"AWS_BEARER_TOKEN_BEDROCK", "LOBE_ACCESS_CODE", "OPENAI_API_KEY"} <= set(CREDENTIAL_ENV_NAMES)


@pytest.mark.parametrize("name", CREDENTIAL_ENV_NAMES)
def test_credential_named_pack_variables_are_withheld_in_text(name: str) -> None:
    for line in (f"export {name}={VALUE}", f"{name}={VALUE}", f"set {name}={VALUE}", f'{name}: "{VALUE}"'):
        out = sanitize_text(line)
        assert VALUE not in out and REDACTED in out, line


@pytest.mark.parametrize("name", CREDENTIAL_ENV_NAMES)
def test_credential_named_pack_variables_are_withheld_in_records(name: str) -> None:
    assert sanitize({"environment": {name: VALUE}})["environment"][name] == REDACTED


@pytest.mark.parametrize(
    "line",
    [
        "set ZAPIER_MCP_URL=https://mcp.zapier.com/api/mcp/s/{value}/mcp",
        "export MODAL_TOKEN_ID=ak-{value}",
    ],
)
def test_credential_variables_without_a_credential_word_are_withheld(line: str) -> None:
    text = line.format(value=VALUE)
    assert VALUE not in sanitize_text(text)
