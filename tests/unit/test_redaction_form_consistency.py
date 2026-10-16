"""One decision about a name and its value, whatever syntax carries them.

Redaction runs as a sequence of passes, and each pass recognises the syntax it
owns: source assignments, YAML mappings, block scalars, command lines, call
arguments, markup. A pass that reads a narrower set of names than its
neighbours is not visible in its own tests — the value simply survives in the
one form that pass owns. That is how a bare ``key:`` over a YAML block scalar
kept an opaque credential while ``key: <opaque>`` on one line was withheld.

These tests pin the invariants rather than the implementation, so a new pass,
or a name added to one pass's list, has to hold all of them:

* a credential-bearing name withholds an opaque value in *every* form;
* a name that locates or labels keeps its value in every name-driven form;
* a name that always carries a credential withholds its block whatever the
  block holds, while one that carries a credential only when the value is
  opaque reads the block and keeps a path, a sentence or a placeholder.
"""

from __future__ import annotations

import pytest

from shadowscan.utils.redaction import sanitize_text

# Mixed case, digits and no separators: opaque by shape, with no provider
# prefix that a format pass could recognise instead of the name.
OPAQUE = "Ab3Cd4Ef5Gh6Ij7Kl8Mn9Op0Qr1St2Uv"

# Names that always carry a credential, whatever the value looks like.
ALWAYS_CREDENTIAL_NAMES = [
    "password",
    "api_key",
    "secret",
    "token",
    "client_secret",
    "credentials",
    "private_key",
]
# Carries a credential only when the value is opaque; 'key' also names the file
# holding one, a column in a table and a dictionary entry.
CONDITIONAL_CREDENTIAL_NAMES = ["key"]
CREDENTIAL_NAMES = ALWAYS_CREDENTIAL_NAMES + CONDITIONAL_CREDENTIAL_NAMES

# Names that locate, label or describe. An opaque-looking value under one of
# these is an identifier, not a credential.
PLAIN_NAMES = ["data", "name", "description", "model", "version", "region", "bucket"]

# Each form spells the same name/value pair the way a different pass reads it.
# All of these are decided by the name beside the value.
NAME_DRIVEN_FORMS = {
    "assignment": '{name} = "{value}"',
    "yaml-inline": "{name}: {value}",
    "yaml-block": "{name}: |\n  {value}\n",
    "yaml-folded": "{name}: >\n  {value}\n",
    "yaml-quoted": '{name}: "{value}"',
    "json": '{{"{name}": "{value}"}}',
    "environment": "{upper}={value}",
    "export": "export {upper}={value}",
    "cli-option": "tool --{name} {value}",
    "header": 'headers={{"{name}": "{value}"}}',
}
# Decided by the callee instead: an opaque literal handed to a client
# constructor is withheld whichever argument carries it, because the positional
# form ('Client("<secret>")') names nothing at all. Listed separately so the
# name-driven expectations above are not asserted of it.
CALLEE_DRIVEN_FORMS = {"call-argument": 'Client({name}="{value}")'}
ALL_FORMS = {**NAME_DRIVEN_FORMS, **CALLEE_DRIVEN_FORMS}

NOT_CREDENTIALS = ["/etc/ssl/private/server.pem", "see the runbook for this value", "CHANGEME"]


def _spell(forms: dict[str, str], form: str, name: str, value: str) -> str:
    return forms[form].format(name=name, upper=name.upper(), value=value)


@pytest.mark.parametrize("form", sorted(ALL_FORMS))
@pytest.mark.parametrize("name", CREDENTIAL_NAMES)
def test_an_opaque_value_is_withheld_in_every_form(form, name):
    text = _spell(ALL_FORMS, form, name, OPAQUE)
    clean = sanitize_text(text)
    assert OPAQUE not in clean, f"{form} kept an opaque credential named {name!r}"
    # Evidence is sanitized more than once, so a reading must settle.
    assert sanitize_text(clean) == clean


@pytest.mark.parametrize("form", sorted(NAME_DRIVEN_FORMS))
@pytest.mark.parametrize("name", PLAIN_NAMES)
def test_a_value_that_names_no_credential_is_kept_in_every_name_driven_form(form, name):
    text = _spell(NAME_DRIVEN_FORMS, form, name, OPAQUE)
    assert OPAQUE in sanitize_text(text), f"{form} withheld an ordinary value named {name!r}"


@pytest.mark.parametrize("body", NOT_CREDENTIALS)
@pytest.mark.parametrize("name", ALWAYS_CREDENTIAL_NAMES)
def test_an_always_credential_name_withholds_its_block_whatever_it_holds(name, body):
    clean = sanitize_text(f"{name}: |\n  {body}\n")
    assert body not in clean, f"{name}: | kept {body!r}"


@pytest.mark.parametrize("body", NOT_CREDENTIALS)
@pytest.mark.parametrize("name", CONDITIONAL_CREDENTIAL_NAMES)
def test_a_conditional_name_keeps_a_block_that_is_not_a_credential(name, body):
    clean = sanitize_text(f"{name}: |\n  {body}\n")
    assert body in clean, f"{name}: | withheld {body!r}"
