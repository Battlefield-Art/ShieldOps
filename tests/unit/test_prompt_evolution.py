"""Behavioral TDD tests for prompt_evolution.py.

Tests cover: registration, de-duplication, version hashing, mutation, A/B testing,
activation, rollback, lineage tracking, version limits, and singleton access.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest

from shieldops.utils.evolution.types import ABTestResult, MutationType, PromptStatus
from shieldops.utils.prompt_evolution import (
    AB_SIGNIFICANCE_THRESHOLD,
    MAX_VERSIONS_PER_PROMPT,
    MIN_AB_OBSERVATIONS,
    PromptEvolutionStore,
    get_prompt_store,
)


@pytest.fixture()  # type: ignore[misc]
def store() -> PromptEvolutionStore:  # type: ignore[misc]
    """Fresh store per test -- no cross-test state leakage."""
    return PromptEvolutionStore()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _expected_hash(agent_id: str, node_name: str, content: str, gen: int) -> str:
    raw = f"{agent_id}:{node_name}:{gen}:{content[:200]}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _register_and_mutate(
    store: PromptEvolutionStore,
    agent_id: str = "agent1",
    node_name: str = "investigate",
    original: str = "You are a security analyst.",
    mutated: str = "You are a senior security analyst.",
    auto_test: bool = True,
) -> tuple[Any, Any]:
    """Register an original prompt then mutate it. Returns (original_ver, mutated_ver)."""
    orig = store.register_prompt(agent_id, node_name, original, activate=True)
    mut = store.mutate(
        agent_id,
        node_name,
        mutated,
        MutationType.INSTRUCTION_REFINE,
        auto_test=auto_test,
    )
    return orig, mut  # type: ignore[return-value]


def _run_ab_test_to_conclusion(
    store: PromptEvolutionStore,
    agent_id: str,
    node_name: str,
    champion_id: str,
    challenger_id: str,
    champion_score: float,
    challenger_score: float,
    n: int | None = None,
) -> ABTestResult | None:
    """Feed n observations for each side and return the final result."""
    n = n or MIN_AB_OBSERVATIONS
    result = None
    for _ in range(n):
        store.record_ab_observation(agent_id, node_name, champion_id, champion_score)
        result = store.record_ab_observation(agent_id, node_name, challenger_id, challenger_score)
    return result


# ===================================================================
# TestRegisterPrompt
# ===================================================================


class TestRegisterPrompt:
    """Registering a prompt creates a version with correct status and metadata."""

    def test_register_with_activate_true_sets_active_status(
        self, store: PromptEvolutionStore
    ) -> None:
        v = store.register_prompt("a1", "node", "content", activate=True)
        assert v.status == PromptStatus.ACTIVE
        assert v.activated_at > 0.0

    def test_register_with_activate_false_sets_draft_status(
        self, store: PromptEvolutionStore
    ) -> None:
        v = store.register_prompt("a1", "node", "content", activate=False)
        assert v.status == PromptStatus.DRAFT
        assert v.activated_at == 0.0

    def test_register_sets_generation_zero(self, store: PromptEvolutionStore) -> None:
        v = store.register_prompt("a1", "node", "content")
        assert v.generation == 0

    def test_register_stores_agent_and_node(self, store: PromptEvolutionStore) -> None:
        v = store.register_prompt("agent-x", "investigate", "prompt text")
        assert v.agent_id == "agent-x"
        assert v.node_name == "investigate"

    def test_register_stores_content_verbatim(self, store: PromptEvolutionStore) -> None:
        content = "You are a security analyst.\nAnalyze threats carefully."
        v = store.register_prompt("a1", "n1", content)
        assert v.content == content

    def test_register_active_sets_active_map(self, store: PromptEvolutionStore) -> None:
        store.register_prompt("a1", "n1", "c1", activate=True)
        assert store.get_active_prompt("a1", "n1") == "c1"

    def test_register_draft_does_not_set_active_map(self, store: PromptEvolutionStore) -> None:
        store.register_prompt("a1", "n1", "c1", activate=False)
        assert store.get_active_prompt("a1", "n1") == ""

    def test_deduplication_returns_existing_version(self, store: PromptEvolutionStore) -> None:
        v1 = store.register_prompt("a1", "n1", "same content")
        v2 = store.register_prompt("a1", "n1", "same content")
        assert v1.version_id == v2.version_id

    def test_deduplication_does_not_add_second_entry(self, store: PromptEvolutionStore) -> None:
        store.register_prompt("a1", "n1", "same content")
        store.register_prompt("a1", "n1", "same content")
        lineage = store.get_lineage("a1", "n1")
        assert lineage.total_versions == 1

    def test_different_content_creates_separate_versions(self, store: PromptEvolutionStore) -> None:
        v1 = store.register_prompt("a1", "n1", "content A")
        v2 = store.register_prompt("a1", "n1", "content B")
        assert v1.version_id != v2.version_id


# ===================================================================
# TestVersionHashing
# ===================================================================


class TestVersionHashing:
    """version_id is a deterministic sha256 truncated to 16 chars."""

    def test_hash_is_deterministic(self, store: PromptEvolutionStore) -> None:
        v = store.register_prompt("a1", "n1", "content")
        expected = _expected_hash("a1", "n1", "content", 0)
        assert v.version_id == expected

    def test_hash_uses_first_200_chars_of_content(self, store: PromptEvolutionStore) -> None:
        long_content = "x" * 500
        v = store.register_prompt("a1", "n1", long_content)
        expected = _expected_hash("a1", "n1", long_content, 0)
        assert v.version_id == expected

    def test_hash_length_is_16(self, store: PromptEvolutionStore) -> None:
        v = store.register_prompt("a1", "n1", "content")
        assert len(v.version_id) == 16

    def test_different_agents_produce_different_hashes(self, store: PromptEvolutionStore) -> None:
        v1 = store.register_prompt("a1", "n1", "content")
        v2 = store.register_prompt("a2", "n1", "content")
        assert v1.version_id != v2.version_id

    def test_different_nodes_produce_different_hashes(self, store: PromptEvolutionStore) -> None:
        v1 = store.register_prompt("a1", "n1", "content")
        v2 = store.register_prompt("a1", "n2", "content")
        assert v1.version_id != v2.version_id


# ===================================================================
# TestMutate
# ===================================================================


class TestMutate:
    """Mutation creates a child version with correct lineage and state."""

    def test_mutated_version_has_incremented_generation(self, store: PromptEvolutionStore) -> None:
        _orig, mut = _register_and_mutate(store)
        assert mut.generation == 1  # type: ignore[attr-defined]

    def test_second_mutation_increments_again(self, store: PromptEvolutionStore) -> None:
        store.register_prompt("a1", "n1", "v0", activate=True)
        store.mutate("a1", "n1", "v1", MutationType.TONE_SHIFT, auto_test=False)
        m2 = store.mutate("a1", "n1", "v2", MutationType.TONE_SHIFT, auto_test=False)
        assert m2.generation == 2

    def test_parent_version_id_points_to_active(self, store: PromptEvolutionStore) -> None:
        orig, mut = _register_and_mutate(store)
        assert mut.parent_version_id == orig.version_id  # type: ignore[attr-defined]

    def test_mutation_type_is_recorded(self, store: PromptEvolutionStore) -> None:
        _orig, mut = _register_and_mutate(store)
        assert mut.mutation_type == MutationType.INSTRUCTION_REFINE  # type: ignore[attr-defined]

    def test_mutation_reason_is_recorded(self, store: PromptEvolutionStore) -> None:
        store.register_prompt("a1", "n1", "v0", activate=True)
        mut = store.mutate(
            "a1", "n1", "v1", MutationType.EXAMPLE_ADD, reason="add few-shot examples"
        )
        assert mut.mutation_reason == "add few-shot examples"

    def test_auto_test_true_sets_testing_status(self, store: PromptEvolutionStore) -> None:
        _orig, mut = _register_and_mutate(store, auto_test=True)
        assert mut.status == PromptStatus.TESTING  # type: ignore[attr-defined]

    def test_auto_test_false_sets_draft_status(self, store: PromptEvolutionStore) -> None:
        _orig, mut = _register_and_mutate(store, auto_test=False)
        assert mut.status == PromptStatus.DRAFT  # type: ignore[attr-defined]

    def test_auto_test_starts_ab_test(self, store: PromptEvolutionStore) -> None:
        orig, mut = _register_and_mutate(store, auto_test=True)
        test = store.get_active_ab_test("agent1", "investigate")
        assert test is not None
        assert test.champion_id == orig.version_id  # type: ignore[attr-defined]
        assert test.challenger_id == mut.version_id  # type: ignore[attr-defined]

    def test_auto_test_false_does_not_start_ab_test(self, store: PromptEvolutionStore) -> None:
        _register_and_mutate(store, auto_test=False)
        assert store.get_active_ab_test("agent1", "investigate") is None

    def test_mutate_without_active_parent_has_empty_parent_id(
        self, store: PromptEvolutionStore
    ) -> None:
        # Mutate on an agent/node with no active version
        mut = store.mutate("no_agent", "no_node", "content", MutationType.LLM_REWRITE)
        assert mut.parent_version_id == ""

    def test_mutate_without_active_parent_does_not_start_ab_test(
        self, store: PromptEvolutionStore
    ) -> None:
        store.mutate("no_agent", "no_node", "content", MutationType.LLM_REWRITE, auto_test=True)
        assert store.get_active_ab_test("no_agent", "no_node") is None


# ===================================================================
# TestABTesting
# ===================================================================


class TestABTesting:
    """A/B test lifecycle: observations, running mean, conclusion outcomes."""

    def test_challenger_wins_when_score_exceeds_threshold(
        self, store: PromptEvolutionStore
    ) -> None:
        orig, mut = _register_and_mutate(store)
        champion_score = 0.70
        challenger_score = champion_score + AB_SIGNIFICANCE_THRESHOLD + 0.01

        result = _run_ab_test_to_conclusion(
            store,
            "agent1",
            "investigate",
            orig.version_id,
            mut.version_id,
            champion_score,
            challenger_score,
        )
        assert result == ABTestResult.CHALLENGER_WINS

    def test_champion_wins_when_champion_exceeds_threshold(
        self, store: PromptEvolutionStore
    ) -> None:
        orig, mut = _register_and_mutate(store)
        champion_score = 0.80
        challenger_score = champion_score - AB_SIGNIFICANCE_THRESHOLD - 0.01

        result = _run_ab_test_to_conclusion(
            store,
            "agent1",
            "investigate",
            orig.version_id,
            mut.version_id,
            champion_score,
            challenger_score,
        )
        assert result == ABTestResult.CHAMPION_WINS

    def test_no_difference_when_scores_within_threshold(self, store: PromptEvolutionStore) -> None:
        orig, mut = _register_and_mutate(store)
        result = _run_ab_test_to_conclusion(
            store,
            "agent1",
            "investigate",
            orig.version_id,
            mut.version_id,
            0.75,
            0.75,
        )
        assert result == ABTestResult.NO_DIFFERENCE

    def test_no_difference_at_exact_threshold_boundary(self, store: PromptEvolutionStore) -> None:
        orig, mut = _register_and_mutate(store)
        # delta == threshold exactly -- not strictly greater, so NO_DIFFERENCE
        result = _run_ab_test_to_conclusion(
            store,
            "agent1",
            "investigate",
            orig.version_id,
            mut.version_id,
            0.70,
            0.70 + AB_SIGNIFICANCE_THRESHOLD,
        )
        assert result == ABTestResult.NO_DIFFERENCE

    def test_insufficient_data_before_min_observations(self, store: PromptEvolutionStore) -> None:
        orig, mut = _register_and_mutate(store)
        # Feed fewer than min_observations
        for _ in range(MIN_AB_OBSERVATIONS - 1):
            store.record_ab_observation("agent1", "investigate", orig.version_id, 0.8)
            result = store.record_ab_observation("agent1", "investigate", mut.version_id, 0.9)
        assert result is None  # not concluded yet
        test = store.get_active_ab_test("agent1", "investigate")
        assert test is not None
        assert test.result == ABTestResult.INSUFFICIENT_DATA

    def test_running_mean_is_correct(self, store: PromptEvolutionStore) -> None:
        orig, mut = _register_and_mutate(store)
        scores = [0.6, 0.8, 0.7]
        for s in scores:
            store.record_ab_observation("agent1", "investigate", orig.version_id, s)

        test = store.get_active_ab_test("agent1", "investigate")
        expected_mean = sum(scores) / len(scores)
        assert test.champion_score == pytest.approx(expected_mean, abs=1e-9)  # type: ignore[union-attr]
        assert test.champion_observations == 3  # type: ignore[union-attr]

    def test_challenger_wins_auto_activates(self, store: PromptEvolutionStore) -> None:
        orig, mut = _register_and_mutate(store)
        _run_ab_test_to_conclusion(
            store,
            "agent1",
            "investigate",
            orig.version_id,
            mut.version_id,
            0.70,
            0.80,
        )
        assert (
            store.get_active_prompt("agent1", "investigate") == "You are a senior security analyst."
        )

    def test_champion_wins_marks_challenger_superseded(self, store: PromptEvolutionStore) -> None:
        orig, mut = _register_and_mutate(store)
        _run_ab_test_to_conclusion(
            store,
            "agent1",
            "investigate",
            orig.version_id,
            mut.version_id,
            0.90,
            0.70,
        )
        # Find the challenger version object
        lineage = store.get_lineage("agent1", "investigate")
        challenger = [v for v in lineage.versions if v.version_id == mut.version_id][0]
        assert challenger.status == PromptStatus.SUPERSEDED

    def test_observation_for_unknown_version_returns_none(
        self, store: PromptEvolutionStore
    ) -> None:
        _register_and_mutate(store)
        result = store.record_ab_observation("agent1", "investigate", "nonexistent_id", 0.8)
        assert result is None

    def test_observation_with_no_active_test_returns_none(
        self, store: PromptEvolutionStore
    ) -> None:
        store.register_prompt("a1", "n1", "content")
        result = store.record_ab_observation("a1", "n1", "some_id", 0.8)
        assert result is None

    def test_concluded_test_no_longer_found_as_active(self, store: PromptEvolutionStore) -> None:
        orig, mut = _register_and_mutate(store)
        _run_ab_test_to_conclusion(
            store,
            "agent1",
            "investigate",
            orig.version_id,
            mut.version_id,
            0.70,
            0.80,
        )
        assert store.get_active_ab_test("agent1", "investigate") is None

    def test_concluded_test_has_concluded_at_timestamp(self, store: PromptEvolutionStore) -> None:
        orig, mut = _register_and_mutate(store)
        _run_ab_test_to_conclusion(
            store,
            "agent1",
            "investigate",
            orig.version_id,
            mut.version_id,
            0.70,
            0.80,
        )
        # Find the concluded test
        tests = [t for t in store._ab_tests.values() if t.concluded_at > 0]
        assert len(tests) == 1

    def test_asymmetric_observations_waits_for_both_sides(
        self, store: PromptEvolutionStore
    ) -> None:
        orig, mut = _register_and_mutate(store)
        # Give champion enough observations but not challenger
        for _ in range(MIN_AB_OBSERVATIONS):
            store.record_ab_observation("agent1", "investigate", orig.version_id, 0.8)
        # Challenger has 0 observations -- test should still be active
        test = store.get_active_ab_test("agent1", "investigate")
        assert test is not None
        assert test.result == ABTestResult.INSUFFICIENT_DATA


# ===================================================================
# TestActivateRollback
# ===================================================================


class TestActivateRollback:
    """Activation and rollback correctly transition version statuses."""

    def test_activate_sets_version_active(self, store: PromptEvolutionStore) -> None:
        v = store.register_prompt("a1", "n1", "c1", activate=False)
        result = store.activate("a1", "n1", v.version_id)
        assert result is True
        assert store.get_active_prompt("a1", "n1") == "c1"

    def test_activate_supersedes_previous_active(self, store: PromptEvolutionStore) -> None:
        v1 = store.register_prompt("a1", "n1", "c1", activate=True)
        v2 = store.register_prompt("a1", "n1", "c2", activate=False)
        store.activate("a1", "n1", v2.version_id)

        lineage = store.get_lineage("a1", "n1")
        old = [v for v in lineage.versions if v.version_id == v1.version_id][0]
        assert old.status == PromptStatus.SUPERSEDED
        assert old.deactivated_at > 0.0

    def test_activate_nonexistent_version_returns_false(self, store: PromptEvolutionStore) -> None:
        store.register_prompt("a1", "n1", "c1")
        assert store.activate("a1", "n1", "does_not_exist") is False

    def test_rollback_restores_parent(self, store: PromptEvolutionStore) -> None:
        orig, mut = _register_and_mutate(store, auto_test=False)
        store.activate("agent1", "investigate", mut.version_id)
        rolled = store.rollback("agent1", "investigate")
        assert rolled is not None
        assert rolled.version_id == orig.version_id
        assert rolled.status == PromptStatus.ACTIVE

    def test_rollback_marks_current_as_rolled_back(self, store: PromptEvolutionStore) -> None:
        orig, mut = _register_and_mutate(store, auto_test=False)
        store.activate("agent1", "investigate", mut.version_id)
        store.rollback("agent1", "investigate")

        lineage = store.get_lineage("agent1", "investigate")
        rolled = [v for v in lineage.versions if v.version_id == mut.version_id][0]
        assert rolled.status == PromptStatus.ROLLED_BACK
        assert rolled.deactivated_at > 0.0

    def test_rollback_updates_active_prompt(self, store: PromptEvolutionStore) -> None:
        orig, mut = _register_and_mutate(store, auto_test=False)
        store.activate("agent1", "investigate", mut.version_id)
        store.rollback("agent1", "investigate")
        assert store.get_active_prompt("agent1", "investigate") == orig.content

    def test_rollback_with_no_active_returns_none(self, store: PromptEvolutionStore) -> None:
        assert store.rollback("a1", "n1") is None

    def test_rollback_with_no_parent_returns_none(self, store: PromptEvolutionStore) -> None:
        # Original version has no parent
        store.register_prompt("a1", "n1", "original", activate=True)
        assert store.rollback("a1", "n1") is None

    def test_get_active_version_returns_version_object(self, store: PromptEvolutionStore) -> None:
        v = store.register_prompt("a1", "n1", "content", activate=True)
        active = store.get_active_version("a1", "n1")
        assert active is not None
        assert active.version_id == v.version_id

    def test_get_active_version_returns_none_when_empty(self, store: PromptEvolutionStore) -> None:
        assert store.get_active_version("a1", "n1") is None

    def test_get_active_prompt_returns_empty_when_no_versions(
        self, store: PromptEvolutionStore
    ) -> None:
        assert store.get_active_prompt("a1", "n1") == ""


# ===================================================================
# TestLineage
# ===================================================================


class TestLineage:
    """Lineage returns a complete view of all versions and computed metrics."""

    def test_lineage_total_versions(self, store: PromptEvolutionStore) -> None:
        store.register_prompt("a1", "n1", "v0", activate=True)
        store.mutate("a1", "n1", "v1", MutationType.TONE_SHIFT, auto_test=False)
        store.mutate("a1", "n1", "v2", MutationType.TONE_SHIFT, auto_test=False)

        lineage = store.get_lineage("a1", "n1")
        assert lineage.total_versions == 3

    def test_lineage_total_generations(self, store: PromptEvolutionStore) -> None:
        store.register_prompt("a1", "n1", "v0", activate=True)
        store.mutate("a1", "n1", "v1", MutationType.TONE_SHIFT, auto_test=False)
        store.mutate("a1", "n1", "v2", MutationType.TONE_SHIFT, auto_test=False)

        lineage = store.get_lineage("a1", "n1")
        assert lineage.total_generations == 2

    def test_lineage_active_version_id(self, store: PromptEvolutionStore) -> None:
        v = store.register_prompt("a1", "n1", "v0", activate=True)
        lineage = store.get_lineage("a1", "n1")
        assert lineage.active_version_id == v.version_id

    def test_lineage_versions_list_contains_all(self, store: PromptEvolutionStore) -> None:
        store.register_prompt("a1", "n1", "v0", activate=True)
        store.mutate("a1", "n1", "v1", MutationType.TONE_SHIFT, auto_test=False)

        lineage = store.get_lineage("a1", "n1")
        contents = [v.content for v in lineage.versions]
        assert "v0" in contents
        assert "v1" in contents

    def test_lineage_improvement_rate_with_scored_versions(
        self, store: PromptEvolutionStore
    ) -> None:
        v0 = store.register_prompt("a1", "n1", "v0", activate=True)
        v1 = store.mutate("a1", "n1", "v1", MutationType.TONE_SHIFT, auto_test=False)

        # Manually set scores to compute improvement
        v0.performance_score = 0.50
        v0.observation_count = 5
        v1.performance_score = 0.75
        v1.observation_count = 5

        lineage = store.get_lineage("a1", "n1")
        # improvement_rate = (0.75 - 0.50) / 0.50 = 0.50
        assert lineage.improvement_rate == pytest.approx(0.50, abs=1e-4)

    def test_lineage_improvement_rate_zero_when_no_scored_versions(  # type: ignore[no-untyped-def]
        self, store: PromptEvolutionStore
    ):
        store.register_prompt("a1", "n1", "v0", activate=True)
        lineage = store.get_lineage("a1", "n1")
        assert lineage.improvement_rate == 0.0

    def test_lineage_improvement_rate_zero_when_only_one_scored(
        self, store: PromptEvolutionStore
    ) -> None:
        v0 = store.register_prompt("a1", "n1", "v0", activate=True)
        v0.performance_score = 0.5
        v0.observation_count = 5
        lineage = store.get_lineage("a1", "n1")
        assert lineage.improvement_rate == 0.0

    def test_lineage_for_nonexistent_agent_returns_empty(self, store: PromptEvolutionStore) -> None:
        lineage = store.get_lineage("ghost", "node")
        assert lineage.total_versions == 0
        assert lineage.versions == []
        assert lineage.active_version_id == ""


# ===================================================================
# TestVersionLimits
# ===================================================================


class TestVersionLimits:
    """When versions exceed MAX_VERSIONS_PER_PROMPT, oldest superseded/rolled_back are evicted."""

    def test_eviction_triggers_above_max_versions(self, store: PromptEvolutionStore) -> None:
        store.register_prompt("a1", "n1", "v0", activate=True)
        # Create MAX_VERSIONS_PER_PROMPT mutations to cross the limit
        for i in range(1, MAX_VERSIONS_PER_PROMPT + 1):
            m = store.mutate("a1", "n1", f"v{i}", MutationType.TONE_SHIFT, auto_test=False)
            # Mark older ones as superseded so they're eligible for eviction
            if i < MAX_VERSIONS_PER_PROMPT:
                m.status = PromptStatus.SUPERSEDED

        lineage = store.get_lineage("a1", "n1")
        assert lineage.total_versions <= MAX_VERSIONS_PER_PROMPT

    def test_active_versions_survive_eviction(self, store: PromptEvolutionStore) -> None:
        v0 = store.register_prompt("a1", "n1", "v0", activate=True)
        for i in range(1, MAX_VERSIONS_PER_PROMPT + 5):
            m = store.mutate("a1", "n1", f"v{i}", MutationType.TONE_SHIFT, auto_test=False)
            m.status = PromptStatus.SUPERSEDED

        # The original (ACTIVE) should still be present
        lineage = store.get_lineage("a1", "n1")
        ids = [v.version_id for v in lineage.versions]
        assert v0.version_id in ids

    def test_below_limit_no_eviction(self, store: PromptEvolutionStore) -> None:
        store.register_prompt("a1", "n1", "v0", activate=True)
        for i in range(1, 5):
            store.mutate("a1", "n1", f"v{i}", MutationType.TONE_SHIFT, auto_test=False)

        lineage = store.get_lineage("a1", "n1")
        assert lineage.total_versions == 5


# ===================================================================
# TestGetStats
# ===================================================================


class TestGetStats:
    """Global statistics reflect the store's full state."""

    def test_empty_store_stats(self, store: PromptEvolutionStore) -> None:
        stats = store.get_stats()
        assert stats["total_prompts_tracked"] == 0
        assert stats["total_versions"] == 0
        assert stats["active_ab_tests"] == 0

    def test_stats_after_register_and_mutate(self, store: PromptEvolutionStore) -> None:
        _register_and_mutate(store)
        stats = store.get_stats()
        assert stats["total_prompts_tracked"] == 1
        assert stats["total_versions"] == 2
        assert stats["active_versions"] == 1
        assert stats["total_mutations"] == 1
        assert stats["active_ab_tests"] == 1

    def test_mutations_by_type_tracked(self, store: PromptEvolutionStore) -> None:
        store.register_prompt("a1", "n1", "v0", activate=True)
        store.mutate("a1", "n1", "v1", MutationType.TONE_SHIFT, auto_test=False)
        store.mutate("a1", "n1", "v2", MutationType.EXAMPLE_ADD, auto_test=False)

        stats = store.get_stats()
        assert stats["mutations_by_type"][MutationType.TONE_SHIFT] == 1
        assert stats["mutations_by_type"][MutationType.EXAMPLE_ADD] == 1

    def test_max_generation_tracked(self, store: PromptEvolutionStore) -> None:
        store.register_prompt("a1", "n1", "v0", activate=True)
        store.mutate("a1", "n1", "v1", MutationType.TONE_SHIFT, auto_test=False)
        store.mutate("a1", "n1", "v2", MutationType.TONE_SHIFT, auto_test=False)
        stats = store.get_stats()
        assert stats["max_generation"] == 2

    def test_challenger_win_rate(self, store: PromptEvolutionStore) -> None:
        orig, mut = _register_and_mutate(store)
        _run_ab_test_to_conclusion(
            store,
            "agent1",
            "investigate",
            orig.version_id,
            mut.version_id,
            0.70,
            0.90,
        )
        stats = store.get_stats()
        assert stats["concluded_ab_tests"] == 1
        assert stats["challenger_win_rate"] == pytest.approx(1.0)


# ===================================================================
# TestSingleton
# ===================================================================


class TestSingleton:
    """get_prompt_store() returns a module-level singleton."""

    def test_singleton_returns_same_instance(self) -> None:
        import shieldops.utils.prompt_evolution as mod

        # Reset to ensure clean state
        mod._store = None
        s1 = get_prompt_store()
        s2 = get_prompt_store()
        assert s1 is s2
        # Clean up
        mod._store = None

    def test_singleton_is_prompt_evolution_store(self) -> None:
        import shieldops.utils.prompt_evolution as mod

        mod._store = None
        s = get_prompt_store()
        assert isinstance(s, PromptEvolutionStore)
        mod._store = None
