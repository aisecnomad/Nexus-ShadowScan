"""Capability interactions score above the sum of their parts.

A purely additive model cannot express that two capabilities are worse
together than apart. ``browsing`` plus ``code-exec`` is the
prompt-injection-to-execution path, and private data plus untrusted content
plus an outbound channel is one injection away from exfiltration; both scored
the same as any unrelated pair of the same weights.

The properties asserted here are that the interaction fires only on the full
set, that it is named in the breakdown rather than folded into a total, and
that adding it did not break the model's existing invariants.
"""

from __future__ import annotations

import itertools

import pytest

from shadowscan.models import Finding, Kind, Surface
from shadowscan.risk import COMBINATION_WEIGHTS, RiskPolicy, assess

ALL_CAPS = [
    "code-exec",
    "autonomous",
    "saas-actions",
    "data-access",
    "browsing",
    "memory",
    "multi-agent",
    "delegated-identity",
    "tool-use",
    "mcp-server",
    "rag",
]


def _finding(caps: list[str], confidence: float = 1.0) -> Finding:
    return Finding(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.AGENT,
        title="an agent",
        resource="services/agent",
        resource_type="repo",
        capabilities=list(caps),
        confidence=confidence,
    )


def _combos(caps: list[str], policy: RiskPolicy | None = None) -> list[str]:
    risk = assess(_finding(caps), policy=policy)
    return [f.id.removeprefix("combination:") for f in risk.factors if f.id.startswith("combination:")]


def _score(caps: list[str], policy: RiskPolicy | None = None) -> int:
    return assess(_finding(caps), policy=policy).score


class TestFiring:
    @pytest.mark.parametrize("cid", sorted(COMBINATION_WEIGHTS))
    def test_the_full_set_fires(self, cid: str) -> None:
        caps, _weight, _description = COMBINATION_WEIGHTS[cid]
        assert cid in _combos(sorted(caps))

    @pytest.mark.parametrize("cid", sorted(COMBINATION_WEIGHTS))
    def test_every_proper_subset_does_not(self, cid: str) -> None:
        caps, _weight, _description = COMBINATION_WEIGHTS[cid]
        for n in range(len(caps)):
            for subset in itertools.combinations(sorted(caps), n):
                assert cid not in _combos(list(subset)), f"{cid} fired on {subset}"

    def test_nothing_fires_without_capabilities(self) -> None:
        assert _combos([]) == []

    def test_an_unrelated_pair_fires_nothing(self) -> None:
        assert _combos(["rag", "tool-use"]) == []

    def test_the_lethal_trifecta_needs_all_three(self) -> None:
        pair = _score(["data-access", "browsing"])
        trio = _score(["data-access", "browsing", "saas-actions"])
        # The third capability contributes its own weight *and* the interaction.
        assert trio > pair + 10


class TestExplainability:
    def test_the_interaction_is_a_named_factor(self) -> None:
        risk = assess(_finding(["browsing", "code-exec"]))
        factor = next(f for f in risk.factors if f.id == "combination:injection-to-execution")
        assert "injected text" in factor.description
        assert factor.weight > 0

    @pytest.mark.parametrize("n", [0, 1, 2, 3, 4])
    def test_factors_still_sum_to_the_score(self, n: int) -> None:
        """The model's documented invariant: the breakdown reconstructs the total."""
        for caps in itertools.islice(itertools.combinations(ALL_CAPS, n), 40):
            risk = assess(_finding(list(caps), confidence=0.9))
            assert sum(f.weight for f in risk.factors) == risk.score

    @pytest.mark.parametrize("n", [1, 2, 3])
    def test_adding_a_capability_never_lowers_the_score(self, n: int) -> None:
        for caps in itertools.islice(itertools.combinations(ALL_CAPS, n), 30):
            base = _score(list(caps))
            for extra in ALL_CAPS:
                if extra not in caps:
                    assert _score([*caps, extra]) >= base


class TestPolicy:
    def test_an_operator_can_zero_an_interaction(self) -> None:
        policy = RiskPolicy.from_options({"combinations": {"injection-to-execution": 0}})
        assert _combos(["browsing", "code-exec"], policy) == []

    def test_an_operator_can_reweigh_an_interaction(self) -> None:
        policy = RiskPolicy.from_options({"combinations": {"injection-to-execution": 40}})
        risk = assess(_finding(["browsing", "code-exec"]), policy=policy)
        factor = next(f for f in risk.factors if f.id == "combination:injection-to-execution")
        assert factor.weight == 40

    def test_the_capability_set_is_not_redefinable(self) -> None:
        """An id must mean the same thing in every report, so only the weight is tunable."""
        policy = RiskPolicy.from_options({"combinations": {"injection-to-execution": 40}})
        caps, _weight, _description = policy.combinations["injection-to-execution"]
        assert caps == COMBINATION_WEIGHTS["injection-to-execution"][0]

    def test_an_unknown_combination_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="is not a capability combination"):
            RiskPolicy.from_options({"combinations": {"not-a-thing": 10}})

    def test_a_near_miss_gets_a_suggestion(self) -> None:
        with pytest.raises(ValueError, match="lethal-trifecta"):
            RiskPolicy.from_options({"combinations": {"lethal-trifcta": 10}})

    def test_defaults_are_unchanged_by_an_empty_override(self) -> None:
        policy = RiskPolicy.from_options({})
        assert dict(policy.combinations) == dict(COMBINATION_WEIGHTS)

    def test_an_interaction_fires_even_when_a_member_weight_is_zeroed(self) -> None:
        """The capability is still present; only its individual weight changed."""
        policy = RiskPolicy.from_options({"capabilities": {"browsing": 0}})
        assert "injection-to-execution" in _combos(["browsing", "code-exec"], policy)


class TestDefinitions:
    @pytest.mark.parametrize("cid", sorted(COMBINATION_WEIGHTS))
    def test_each_combination_is_well_formed(self, cid: str) -> None:
        caps, weight, description = COMBINATION_WEIGHTS[cid]
        assert len(caps) >= 2, "a combination of one capability is just a capability"
        assert 0 < weight <= 100
        assert description.strip() and "—" not in description

    @pytest.mark.parametrize("cid", sorted(COMBINATION_WEIGHTS))
    def test_members_are_real_capabilities(self, cid: str) -> None:
        from shadowscan.signatures.schema import CAPABILITIES

        caps, _weight, _description = COMBINATION_WEIGHTS[cid]
        assert caps <= set(CAPABILITIES), f"{cid} names capabilities outside the vocabulary"

    def test_no_combination_is_a_subset_of_another(self) -> None:
        """Nested sets would double-charge the inner one whenever the outer fires."""
        for a, b in itertools.permutations(sorted(COMBINATION_WEIGHTS), 2):
            caps_a = COMBINATION_WEIGHTS[a][0]
            caps_b = COMBINATION_WEIGHTS[b][0]
            assert not caps_a < caps_b, f"{a} is a subset of {b}"
