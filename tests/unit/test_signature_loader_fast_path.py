"""The libyaml parse of the built-in packs is the bounded parse, and only built-in packs get it."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from shadowscan.signatures import loader
from shadowscan.signatures.loader import (
    SignaturePackError,
    builtin_signature_dir,
    load_signature_file,
    load_signatures,
)
from shadowscan.utils.files import read_policy_text

_BUILTIN_PACKS = sorted(loader._pack_files(builtin_signature_dir(), custom=False))


def _parse(path: Path, parser: type) -> list[object]:
    return list(yaml.load_all(read_policy_text(path), Loader=parser))


@pytest.mark.skipif(not getattr(yaml, "__with_libyaml__", False), reason="PyYAML built without libyaml")
@pytest.mark.parametrize("pack", _BUILTIN_PACKS, ids=lambda path: path.name)
def test_libyaml_parse_of_each_builtin_pack_equals_the_bounded_parse(pack: Path) -> None:
    assert loader._BuiltinPackLoader is not loader._UniqueKeyLoader
    assert _parse(pack, loader._BuiltinPackLoader) == _parse(pack, loader._UniqueKeyLoader)


def test_builtin_signatures_load_identically_through_either_parser() -> None:
    fast = load_signatures()
    bounded = load_signatures(libyaml_builtin=False)
    assert [repr(sig) for sig in fast] == [repr(sig) for sig in bounded]


def test_custom_packs_never_use_the_libyaml_loader(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pack = tmp_path / "custom.yaml"
    pack.write_text(
        "id: framework.custom-example\n"
        "name: Custom example\n"
        "category: framework\n"
        "signals:\n"
        "  - type: code\n"
        "    patterns: ['\\bCustomExampleAgent\\b']\n"
        "    weight: 0.8\n",
        encoding="utf-8",
    )
    used: list[type] = []
    real_load_all = yaml.load_all

    def spy(stream: str, Loader: type) -> object:
        used.append(Loader)
        return real_load_all(stream, Loader=Loader)

    monkeypatch.setattr(loader.yaml, "load_all", spy)
    signatures = load_signatures([tmp_path], include_builtin=False)
    assert [sig.id for sig in signatures] == ["framework.custom-example"]
    assert used == [loader._UniqueKeyLoader]


def test_duplicate_keys_are_rejected_by_the_builtin_parser_too(tmp_path: Path) -> None:
    pack = tmp_path / "dup.yaml"
    pack.write_text("id: framework.a\nid: framework.b\n", encoding="utf-8")
    for builtin in (False, True):
        with pytest.raises(SignaturePackError, match="duplicate YAML key 'id' at line 2, column 1"):
            load_signature_file(pack, builtin=builtin)
