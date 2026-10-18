"""Regressions from the adversarial review of the round-5 credential rules.

Each input is synthetic and assembled by concatenation, so no credential-shaped
literal sits in this file.
"""

from __future__ import annotations

import json

import pytest


def _scan(run_connector, tmp_path, rel: str, text: str):
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.incomplete, ctx.stats.errors
    return findings


def _secret_lines(findings) -> list[int]:
    return sorted(
        int(evidence.location.rsplit(":", 1)[1])
        for finding in findings
        if finding.kind.value == "secret"
        for evidence in finding.evidence
        if evidence.location.rsplit(":", 1)[-1].isdigit()
    )


@pytest.mark.parametrize(
    "password",
    ["NowIs" + "TheTimeToCome", "ItIs" + "TimeToComeIn", "ComeWith" + "MeNowPlease", "ComeOn" + "InTheVault"],
)
def test_a_sentence_password_with_a_weak_verb_is_a_password_in_an_env_file(run_connector, tmp_path, password):
    # Regression: 'come', 'use' and 'set' made any closed-vocabulary sentence an
    # instruction, so these env-file passwords, which main reported, were dropped
    # as labels.
    findings = _scan(run_connector, tmp_path, ".env", f"DB_HOST=db.internal\nDB_PASSWORD={password}\n")
    assert _secret_lines(findings) == [2]


@pytest.mark.parametrize(
    "label", ["must-come-from-vault", "never-use-in-prod", "use-your-own", "change-me-please", "set-me-first"]
)
def test_an_instruction_is_still_a_label_in_an_env_file(run_connector, tmp_path, label):
    findings = _scan(run_connector, tmp_path, ".env", f"DB_HOST=db.internal\nDB_PASSWORD={label}\n")
    assert _secret_lines(findings) == []


def _snippets(findings) -> str:
    return json.dumps([finding.to_dict() for finding in findings])


@pytest.mark.parametrize("name", ["dbPassWord", "userPassWord"])
def test_a_password_fallback_under_a_split_password_name_is_withheld(run_connector, tmp_path, name):
    # Regression: the detector reads 'dbPassWord' as a password's name and reports
    # its fallback literal, but the redactor read its last word, 'Word', and showed
    # the password in the finding's own snippet.
    password = "Xk9#mQ2" + "$vL!pR7@wZ4%"
    text = (
        "export const settings = {\n"
        '  host: process.env.PGHOST ?? "localhost",\n'
        f'  {name}: process.env.DB_PASSWORD?.trim() || "{password}",\n'
        "};\n"
    )
    findings = _scan(run_connector, tmp_path, "src/db.ts", text)
    assert _secret_lines(findings) == [3]
    assert password not in _snippets(findings)


def test_a_uuid_key_given_as_a_settings_default_is_withheld(run_connector, tmp_path):
    # Regression: the detector reports a UUID-shaped default of an API key's
    # settings read, but its hyphens cut it into runs the opaque-key test does not
    # take, so the snippet showed the key.
    key = "9aea6429-b149-" + "4e24-b192-b70442594052"
    text = (
        "export class VectorConfig {\n"
        "  readonly options = {\n"
        f"    pineconeApiKey: this.configService.get<string>('PINECONE_API_KEY', '{key}'),\n"
        "  };\n"
        "}\n"
    )
    findings = _scan(run_connector, tmp_path, "src/vector.config.ts", text)
    assert key not in _snippets(findings)
