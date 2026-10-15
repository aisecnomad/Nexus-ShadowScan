"""Configuration diagnostics never quote an opaque token back, and read failures are typed."""

from __future__ import annotations

import os

import pytest

from shadowscan.config import ConfigValidationError, ScanConfig
from shadowscan.triage import TriageConfigError, TriageSettings

# Synthetic shapes of unprefixed credentials, built so no tracked file holds one.
OPAQUE_KEYS = [
    "00" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5bC7dE",  # Okta API token shape
    "".join("0123456789abcdef"[(n * 7) % 16] for n in range(40)),  # 40-hex key
    "Zq8" + "x" * 21,  # mixed case
    "k" + "7" * 30,  # many digits
]


@pytest.mark.parametrize("key", OPAQUE_KEYS)
def test_an_opaque_token_in_key_position_is_described_not_echoed(key):
    with pytest.raises(ConfigValidationError, match="does not accept an unsupported key") as failure:
        ScanConfig.from_dict({"connectors": [{"name": "identity.okta", key: "1"}]})
    assert key not in str(failure.value)


def test_a_misspelt_option_is_still_quoted_with_a_suggestion():
    with pytest.raises(ConfigValidationError, match="'fetch_tokenz'.*did you mean 'fetch_tokens'"):
        ScanConfig.from_dict({"connectors": [{"name": "identity.okta", "fetch_tokenz": True}]})


def test_an_oversized_configuration_file_gets_a_read_diagnostic(tmp_path):
    path = tmp_path / "shadowscan.yaml"
    path.write_bytes(b"#" * (8 * 1024 * 1024 + 1))
    with pytest.raises(ConfigValidationError, match="could not be read"):
        ScanConfig.from_yaml(path)


def test_a_configuration_file_that_is_not_utf8_gets_a_read_diagnostic_naming_the_encoding(tmp_path):
    path = tmp_path / "shadowscan.yaml"
    path.write_bytes("connectors: []  # caf\u00e9\n".encode("latin-1"))
    with pytest.raises(ConfigValidationError, match="could not be read: .*UTF-8") as failure:
        ScanConfig.from_yaml(path)
    assert "0xe9" not in str(failure.value)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="named pipes need POSIX")
def test_a_named_pipe_configuration_gets_a_read_diagnostic(tmp_path):
    path = tmp_path / "shadowscan.yaml"
    os.mkfifo(path)
    with pytest.raises(ConfigValidationError, match="could not be read"):
        ScanConfig.from_yaml(path)


@pytest.mark.parametrize("field", ["provider", "min_level"])
@pytest.mark.parametrize("value", [["anthropic"], {"x": 1}])
def test_unhashable_triage_values_raise_the_typed_error(field, value):
    with pytest.raises(TriageConfigError):
        TriageSettings.from_options({field: value})
    with pytest.raises(ConfigValidationError):
        ScanConfig.from_dict({"options": {"llm_triage": {field: value}}})
