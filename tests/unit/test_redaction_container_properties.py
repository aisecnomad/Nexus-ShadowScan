"""Property test: a sanitized container stays a container of its type.

The example-based regression tests are in test_redaction_container_types.py,
which runs without Hypothesis.
"""

from __future__ import annotations

import string
from typing import Any

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from shadowscan.utils.redaction import sanitize  # noqa: E402


def _is_plain(item: Any) -> bool:
    """Whether ``item`` holds only plain dicts, lists and tuples as containers."""
    if isinstance(item, dict):
        return type(item) is dict and all(_is_plain(child) for child in item.values())
    if isinstance(item, (list, tuple)):
        return all(_is_plain(child) for child in item)
    return True


# Keys that never change and keys after a scheme credential, which read alike
# once withheld in one reading or in both. Every value is synthetic.
_PLAIN_KEYS = ["keep", "tools", "notes", "meta", "items"]
_SCHEME_KEYS = [
    f"{scheme} {credential}{glued}"
    for scheme in ("Bearer", "Basic", "SSWS")
    for credential in ("a", "b", "abc123")
    for glued in ("", "--auth", "--cookie", "--token", "--password", "--x9", "=x9", "=password", "\n--x9")
]
_LEAVES = (
    st.text(alphabet=string.ascii_letters + string.digits + " -=:\n", max_size=30)
    | st.sampled_from(_SCHEME_KEYS)
    | st.integers()
    | st.none()
    | st.booleans()
)
_KEYS = st.sampled_from(_PLAIN_KEYS + _SCHEME_KEYS)
_VALUES = st.recursive(
    _LEAVES,
    lambda children: (
        st.lists(children, max_size=4)
        | st.tuples(children, children)
        | st.dictionaries(_KEYS, children, max_size=6)
    ),
    max_leaves=25,
)


def _assert_containers_kept(value: Any, cleaned: Any) -> None:
    """Each container reached through unchanging keys and positions is one of its type in ``cleaned``.

    A key that a short known value occurs in is withheld whole, as before;
    the value under it is then not looked for.
    """
    if isinstance(value, dict):
        assert type(cleaned) is dict
        for key, child in value.items():
            if key in _PLAIN_KEYS and key in cleaned:
                _assert_containers_kept(child, cleaned[key])
    elif isinstance(value, (list, tuple)):
        assert type(cleaned) is type(value) and len(cleaned) == len(value)
        for child, cleaned_child in zip(value, cleaned, strict=True):
            _assert_containers_kept(child, cleaned_child)


@given(value=st.dictionaries(_KEYS, _VALUES, max_size=8), short=st.booleans())
@settings(max_examples=300, deadline=None)
def test_sanitize_keeps_every_container_type(value: dict[str, Any], short: bool) -> None:
    cleaned = sanitize(value, redact_short_secrets=short)
    _assert_containers_kept(value, cleaned)
    assert _is_plain(cleaned)
    assert sanitize(cleaned, redact_short_secrets=short) == cleaned
