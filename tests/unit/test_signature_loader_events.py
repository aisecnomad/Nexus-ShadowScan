"""Native signature tokenization must retain the bounded Python loader's contract."""

from __future__ import annotations

import io

import pytest
import yaml

from shadowscan.signatures import SignatureIndex
from shadowscan.signatures import loader as packs
from shadowscan.utils.safe_yaml import YAMLConstructionError


@pytest.fixture(params=["native", "python"])
def pack_loader(request, monkeypatch):
    native = getattr(yaml, "CSafeLoader", None)
    if request.param == "python":
        monkeypatch.setattr(yaml, "CSafeLoader", None, raising=False)
    elif native is None:
        pytest.skip("LibYAML event parser is unavailable")
    else:

        class EventOnlyLoader(native):
            def get_node(self):
                raise AssertionError("native composition must not bypass Python resource checks")

            def get_single_node(self):
                raise AssertionError("native composition must not bypass Python resource checks")

            def get_data(self):
                raise AssertionError("native construction must not run")

            def get_single_data(self):
                raise AssertionError("native construction must not run")

        monkeypatch.setattr(yaml, "CSafeLoader", EventOnlyLoader)
    return packs._UniqueKeyLoader


@pytest.mark.parametrize(
    ("limit", "maximum", "source", "reason"),
    [
        ("MAX_INPUT_SIZE", 8, "key: " + "x" * 20, "input size"),
        ("MAX_NODES", 3, "key: [one, two]", "node limit"),
        ("MAX_ALIASES", 1, "a: &a one\nb: *a\nc: *a", "alias limit"),
        ("MAX_DEPTH", 3, "key: [[[one]]]", "nesting limit"),
        ("MAX_EXPANDED_NODES", 10, "a: &a [one, two]\nb: [*a, *a, *a]", "expansion limit"),
        ("MAX_EXPANDED_CHARS", 8, "key: " + "x" * 20, "expansion limit"),
        ("MAX_NUMBER_CHARS", 3, "key: 1234", "number length"),
    ],
)
def test_event_parser_keeps_every_preconstruction_budget(
    pack_loader, monkeypatch, limit, maximum, source, reason
):
    monkeypatch.setattr(pack_loader, limit, maximum)
    with pytest.raises(yaml.YAMLError, match=reason):
        yaml.load(source, Loader=pack_loader)


@pytest.mark.parametrize(
    ("source", "error", "reason"),
    [
        ("key: one\nkey: two", packs.SignaturePackError, "duplicate YAML key"),
        ("key: &a [*a]", yaml.YAMLError, "cyclic alias"),
        ("!!python/object/apply:builtins.str [one]", yaml.YAMLError, "constructor"),
    ],
)
def test_event_parser_keeps_integrity_and_safe_construction(pack_loader, source, error, reason):
    with pytest.raises(error, match=reason):
        yaml.load(source, Loader=pack_loader)


def test_event_parser_keeps_multidocument_aliases_and_scalar_semantics(pack_loader):
    source = "a: &a [one, two]\nb: *a\n---\nnumber: 3\nflag: true\n"
    documents = list(yaml.load_all(source, Loader=pack_loader))
    assert documents == [{"a": ["one", "two"], "b": ["one", "two"]}, {"number": 3, "flag": True}]
    assert documents[0]["a"] is documents[0]["b"]
    assert list(yaml.load_all(io.StringIO(source), Loader=pack_loader)) == documents


def test_event_parser_keeps_scalar_failure_value_free(pack_loader):
    with pytest.raises(YAMLConstructionError) as error:
        yaml.load("key: !!bool synthetic_sensitive_value", Loader=pack_loader)
    assert "synthetic_sensitive_value" not in str(error.value)


def test_all_bundled_signatures_have_the_same_fingerprint_without_native_events(monkeypatch):
    if getattr(yaml, "CSafeLoader", None) is None:
        pytest.skip("LibYAML event parser is unavailable")
    native = SignatureIndex(packs.load_signatures())
    monkeypatch.setattr(yaml, "CSafeLoader", None)
    python = SignatureIndex(packs.load_signatures())
    assert native.fingerprint() == python.fingerprint()
    assert len(native.signatures) == len(python.signatures) >= 233
