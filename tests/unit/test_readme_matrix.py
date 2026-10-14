"""The generated README detection matrix stays derived from the shipped catalogs."""

from __future__ import annotations

import pytest

from shadowscan.connectors import builtin_connector_names
from shadowscan.signatures.loader import load_signatures
from tools.readme_matrix import BEGIN, END, FRAMEWORKS, main, render, replace_block


def test_every_listed_framework_is_a_shipped_framework_signature() -> None:
    frameworks = {signature.id for signature in load_signatures() if signature.category == "framework"}
    assert set(FRAMEWORKS) <= frameworks
    assert len(set(FRAMEWORKS)) == len(FRAMEWORKS)


def test_block_names_each_identity_gateway_lowcode_saas_and_network_connector() -> None:
    block = render()
    listed = [
        name
        for name in builtin_connector_names()
        if name.split(".", 1)[0] in {"identity", "gateway", "lowcode", "saas", "network"}
    ]
    assert listed and all(f"| `{name}` |" in block for name in listed)
    assert block.startswith(BEGIN) and block.endswith(END)


def test_replace_block_keeps_the_surrounding_text() -> None:
    text = f"intro\n{BEGIN}\nold\n{END}\noutro\n"
    assert replace_block(text, f"{BEGIN}\nnew\n{END}") == f"intro\n{BEGIN}\nnew\n{END}\noutro\n"


@pytest.mark.parametrize(
    "text",
    [
        "no markers\n",
        f"{BEGIN}\nonly the start\n",
        f"{END}\n{BEGIN}\n",
        f"{BEGIN}\n{END}\n{BEGIN}\n{END}\n",
    ],
    ids=["missing", "unterminated", "reversed", "repeated"],
)
def test_replace_block_refuses_missing_or_ambiguous_markers(text: str) -> None:
    with pytest.raises(ValueError, match="markers"):
        replace_block(text, f"{BEGIN}\n{END}")


def test_cli_rejects_unknown_arguments(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--write"]) == 2
    assert "usage" in capsys.readouterr().err
