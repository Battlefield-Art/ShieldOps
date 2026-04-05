"""Behavioral tests for FitnessTracker — multi-dimensional agent fitness scoring."""

from __future__ import annotations

import time

import pytest

from shieldops.utils.evolution_enums import EvolutionReadiness, FitnessDimension, FitnessTrend
from shieldops.utils.fitness_tracker import (
    DEFAULT_WEIGHTS,
    MIN_OBSERVATIONS,
    FitnessTracker,
    get_fitness_tracker,
)


@pytest.fixture()
def tracker() -> FitnessTracker:
    """Fresh tracker with default settings for each test."""
    return FitnessTracker()


def _fill_dimension(
    tracker: FitnessTracker,
    agent_id: str,
    dimension: FitnessDimension,
    values: list[float],
    agent_type: str = "",
) -> None:
    """Record a sequence of values for a single dimension."""
    for v in values:
        tracker.record(agent_id, dimension, v, agent_type=agent_type)


def _fill_all_dimensions(
    tracker: FitnessTracker,
    agent_id: str,
    value: float,
    count: int = 1,
    agent_type: str = "test",
) -> None:
    """Record the same value across all dimensions `count` times."""
    for _ in range(count):
        for dim in FitnessDimension:
            tracker.record(agent_id, dim, value, agent_type=agent_type)


# ---------------------------------------------------------------------------
# TestRecord — recording, clamping, observation storage
# ---------------------------------------------------------------------------


class TestRecord:
    def test_record_returns_observation_with_clamped_value(self, tracker: FitnessTracker) -> None:
        obs = tracker.record("a1", FitnessDimension.ACCURACY, 0.75)
        assert obs.value == pytest.approx(0.75)
        assert obs.dimension == FitnessDimension.ACCURACY

    def test_record_clamps_value_above_one(self, tracker: FitnessTracker) -> None:
        obs = tracker.record("a1", FitnessDimension.SPEED, 1.5)
        assert obs.value == pytest.approx(1.0)

    def test_record_clamps_negative_value_to_zero(self, tracker: FitnessTracker) -> None:
        obs = tracker.record("a1", FitnessDimension.COST, -0.3)
        assert obs.value == pytest.approx(0.0)

    def test_record_at_boundary_zero_and_one(self, tracker: FitnessTracker) -> None:
        obs_zero = tracker.record("a1", FitnessDimension.SAFETY, 0.0)
        obs_one = tracker.record("a1", FitnessDimension.SAFETY, 1.0)
        assert obs_zero.value == pytest.approx(0.0)
        assert obs_one.value == pytest.approx(1.0)

    def test_record_creates_agent_profile(self, tracker: FitnessTracker) -> None:
        tracker.record("a1", FitnessDimension.ACCURACY, 0.8, agent_type="scanner")
        profile = tracker.get_fitness("a1")
        assert profile.agent_id == "a1"
        assert profile.agent_type == "scanner"

    def test_record_updates_agent_type_on_subsequent_call(self, tracker: FitnessTracker) -> None:
        tracker.record("a1", FitnessDimension.ACCURACY, 0.8, agent_type="old")
        tracker.record("a1", FitnessDimension.ACCURACY, 0.9, agent_type="new")
        assert tracker.get_fitness("a1").agent_type == "new"

    def test_record_increments_total_observations(self, tracker: FitnessTracker) -> None:
        _fill_all_dimensions(tracker, "a1", 0.5, count=2)
        profile = tracker.get_fitness("a1")
        assert profile.total_observations == 2 * len(FitnessDimension)

    def test_rolling_window_evicts_oldest(self) -> None:
        small_tracker = FitnessTracker(rolling_window=3)
        for v in [0.1, 0.2, 0.3, 0.4, 0.5]:
            small_tracker.record("a1", FitnessDimension.ACCURACY, v)

        dim_score = small_tracker.get_dimension("a1", FitnessDimension.ACCURACY)
        # Only the last 3 (0.3, 0.4, 0.5) should remain
        assert dim_score.observation_count == 3
        expected_avg = (0.3 + 0.4 + 0.5) / 3
        assert dim_score.rolling_avg == pytest.approx(expected_avg, abs=1e-3)

    def test_rolling_window_default_is_50(self, tracker: FitnessTracker) -> None:
        for _i in range(60):
            tracker.record("a1", FitnessDimension.ACCURACY, 0.5)
        dim_score = tracker.get_dimension("a1", FitnessDimension.ACCURACY)
        assert dim_score.observation_count == 50

    def test_get_fitness_unknown_agent_returns_empty_profile(self, tracker: FitnessTracker) -> None:
        profile = tracker.get_fitness("nonexistent")
        assert profile.agent_id == "nonexistent"
        assert profile.composite_score == 0.0
        assert profile.total_observations == 0

    def test_get_dimension_unknown_agent_returns_empty_score(self, tracker: FitnessTracker) -> None:
        score = tracker.get_dimension("nonexistent", FitnessDimension.ACCURACY)
        assert score.dimension == FitnessDimension.ACCURACY
        assert score.observation_count == 0

    def test_record_context_is_stored(self, tracker: FitnessTracker) -> None:
        obs = tracker.record("a1", FitnessDimension.ACCURACY, 0.8, context={"task": "scan"})
        assert obs.context == {"task": "scan"}


# ---------------------------------------------------------------------------
# TestTrendDetection — first/second half comparison with 0.03 threshold
# ---------------------------------------------------------------------------


class TestTrendDetection:
    def test_insufficient_data_when_fewer_than_6_observations(
        self, tracker: FitnessTracker
    ) -> None:
        for _ in range(5):
            tracker.record("a1", FitnessDimension.ACCURACY, 0.5)
        score = tracker.get_dimension("a1", FitnessDimension.ACCURACY)
        assert score.trend == FitnessTrend.INSUFFICIENT_DATA

    def test_improving_trend_when_second_half_higher(self, tracker: FitnessTracker) -> None:
        # First half avg ~0.3, second half avg ~0.7 => delta 0.4 > 0.03
        values = [0.2, 0.3, 0.4, 0.6, 0.7, 0.8]
        _fill_dimension(tracker, "a1", FitnessDimension.ACCURACY, values)
        score = tracker.get_dimension("a1", FitnessDimension.ACCURACY)
        assert score.trend == FitnessTrend.IMPROVING

    def test_declining_trend_when_second_half_lower(self, tracker: FitnessTracker) -> None:
        # First half avg ~0.8, second half avg ~0.3 => delta -0.5 < -0.03
        values = [0.7, 0.8, 0.9, 0.2, 0.3, 0.4]
        _fill_dimension(tracker, "a1", FitnessDimension.ACCURACY, values)
        score = tracker.get_dimension("a1", FitnessDimension.ACCURACY)
        assert score.trend == FitnessTrend.DECLINING

    def test_stable_trend_when_delta_within_threshold(self, tracker: FitnessTracker) -> None:
        # All same value => delta 0.0
        values = [0.5, 0.5, 0.5, 0.5, 0.5, 0.5]
        _fill_dimension(tracker, "a1", FitnessDimension.ACCURACY, values)
        score = tracker.get_dimension("a1", FitnessDimension.ACCURACY)
        assert score.trend == FitnessTrend.STABLE

    def test_stable_trend_at_boundary_delta_below_003(self, tracker: FitnessTracker) -> None:
        # First 3 avg = 0.5, second 3 avg = 0.529 => delta = 0.029 < 0.03 => STABLE
        values = [0.5, 0.5, 0.5, 0.529, 0.529, 0.529]
        _fill_dimension(tracker, "a1", FitnessDimension.ACCURACY, values)
        score = tracker.get_dimension("a1", FitnessDimension.ACCURACY)
        assert score.trend == FitnessTrend.STABLE

    def test_floating_point_boundary_053_is_improving(self, tracker: FitnessTracker) -> None:
        # 0.53 - 0.5 = 0.030...027 in IEEE754, which is > 0.03 => IMPROVING
        # This documents the actual floating-point behavior of the implementation
        values = [0.5, 0.5, 0.5, 0.53, 0.53, 0.53]
        _fill_dimension(tracker, "a1", FitnessDimension.ACCURACY, values)
        score = tracker.get_dimension("a1", FitnessDimension.ACCURACY)
        assert score.trend == FitnessTrend.IMPROVING

    def test_improving_trend_just_above_threshold(self, tracker: FitnessTracker) -> None:
        # First 3 avg = 0.5, second 3 avg = 0.5301 => delta ~ 0.0301 > 0.03
        values = [0.5, 0.5, 0.5, 0.5301, 0.5301, 0.5301]
        _fill_dimension(tracker, "a1", FitnessDimension.ACCURACY, values)
        score = tracker.get_dimension("a1", FitnessDimension.ACCURACY)
        assert score.trend == FitnessTrend.IMPROVING

    def test_trend_with_odd_number_of_observations(self, tracker: FitnessTracker) -> None:
        # 7 obs: first 3 [0.2,0.2,0.2], second 4 [0.8,0.8,0.8,0.8]
        values = [0.2, 0.2, 0.2, 0.8, 0.8, 0.8, 0.8]
        _fill_dimension(tracker, "a1", FitnessDimension.ACCURACY, values)
        score = tracker.get_dimension("a1", FitnessDimension.ACCURACY)
        assert score.trend == FitnessTrend.IMPROVING


# ---------------------------------------------------------------------------
# TestCompositeScore — weighted average across dimensions
# ---------------------------------------------------------------------------


class TestCompositeScore:
    def test_composite_score_with_uniform_values(self, tracker: FitnessTracker) -> None:
        # All dimensions at 0.8 => composite should be ~0.8 (decay negligible for fresh data)
        _fill_all_dimensions(tracker, "a1", 0.8)
        profile = tracker.get_fitness("a1")
        assert profile.composite_score == pytest.approx(0.8, abs=0.01)

    def test_composite_score_reflects_weights(self, tracker: FitnessTracker) -> None:
        # Only accuracy (weight=0.30) at 1.0, rest at 0.0
        tracker.record("a1", FitnessDimension.ACCURACY, 1.0)
        tracker.record("a1", FitnessDimension.SPEED, 0.0)
        tracker.record("a1", FitnessDimension.COST, 0.0)
        tracker.record("a1", FitnessDimension.SAFETY, 0.0)
        tracker.record("a1", FitnessDimension.LEARNING_RATE, 0.0)

        profile = tracker.get_fitness("a1")
        # Expected: (1.0 * 0.30 + 0*rest) / 1.0 = 0.3
        assert profile.composite_score == pytest.approx(0.3, abs=0.01)

    def test_composite_score_with_custom_weights(self) -> None:
        custom = {
            FitnessDimension.ACCURACY: 1.0,
            FitnessDimension.SPEED: 0.0,
            FitnessDimension.COST: 0.0,
            FitnessDimension.SAFETY: 0.0,
            FitnessDimension.LEARNING_RATE: 0.0,
        }
        t = FitnessTracker(weights=custom)
        t.record("a1", FitnessDimension.ACCURACY, 0.9)
        t.record("a1", FitnessDimension.SPEED, 0.1)
        profile = t.get_fitness("a1")
        # accuracy has weight 1.0, speed has weight 0.0
        # weighted_sum = 0.9*1.0 + 0.1*0.0 = 0.9
        # weight_total = 1.0 + 0.0 = 1.0
        assert profile.composite_score == pytest.approx(0.9, abs=0.01)

    def test_composite_zero_when_no_dimensions(self, tracker: FitnessTracker) -> None:
        profile = tracker.get_fitness("nonexistent")
        assert profile.composite_score == pytest.approx(0.0)

    def test_composite_with_partial_dimensions(self, tracker: FitnessTracker) -> None:
        # Only accuracy and safety recorded (both weight 0.30)
        tracker.record("a1", FitnessDimension.ACCURACY, 1.0)
        tracker.record("a1", FitnessDimension.SAFETY, 1.0)
        profile = tracker.get_fitness("a1")
        # weighted_sum = 1.0*0.30 + 1.0*0.30 = 0.60
        # weight_total = 0.30 + 0.30 = 0.60
        # composite = 0.60 / 0.60 = 1.0
        assert profile.composite_score == pytest.approx(1.0, abs=0.01)

    def test_default_weights_sum_to_one(self) -> None:
        total = sum(DEFAULT_WEIGHTS.values())
        assert total == pytest.approx(1.0)

    def test_current_value_is_last_recorded(self, tracker: FitnessTracker) -> None:
        tracker.record("a1", FitnessDimension.ACCURACY, 0.3)
        tracker.record("a1", FitnessDimension.ACCURACY, 0.9)
        dim = tracker.get_dimension("a1", FitnessDimension.ACCURACY)
        assert dim.current == pytest.approx(0.9, abs=1e-3)

    def test_rolling_avg_is_mean_of_window(self, tracker: FitnessTracker) -> None:
        _fill_dimension(tracker, "a1", FitnessDimension.ACCURACY, [0.2, 0.4, 0.6, 0.8])
        dim = tracker.get_dimension("a1", FitnessDimension.ACCURACY)
        assert dim.rolling_avg == pytest.approx(0.5, abs=1e-3)


# ---------------------------------------------------------------------------
# TestLeaderboard — ranking by composite or dimension score
# ---------------------------------------------------------------------------


class TestLeaderboard:
    def test_leaderboard_empty_when_no_agents(self, tracker: FitnessTracker) -> None:
        assert tracker.get_leaderboard() == []

    def test_leaderboard_excludes_agents_with_insufficient_data(
        self, tracker: FitnessTracker
    ) -> None:
        # Record fewer than MIN_OBSERVATIONS total
        tracker.record("a1", FitnessDimension.ACCURACY, 0.9)
        assert tracker.get_leaderboard() == []

    def test_leaderboard_ranks_by_composite_descending(self, tracker: FitnessTracker) -> None:
        # Agent with higher composite first
        _fill_all_dimensions(tracker, "high", 0.9, count=2)
        _fill_all_dimensions(tracker, "low", 0.3, count=2)
        board = tracker.get_leaderboard()
        assert len(board) == 2
        assert board[0].agent_id == "high"
        assert board[0].rank == 1
        assert board[1].agent_id == "low"
        assert board[1].rank == 2

    def test_leaderboard_ranks_by_single_dimension(self, tracker: FitnessTracker) -> None:
        # "fast" has higher speed but lower overall
        _fill_all_dimensions(tracker, "fast", 0.3, count=2)
        _fill_all_dimensions(tracker, "accurate", 0.7, count=2)
        # Bump speed for "fast"
        for _ in range(3):
            tracker.record("fast", FitnessDimension.SPEED, 0.99)

        board = tracker.get_leaderboard(dimension=FitnessDimension.SPEED)
        assert board[0].agent_id == "fast"

    def test_leaderboard_top_n_limits_results(self, tracker: FitnessTracker) -> None:
        for i in range(10):
            _fill_all_dimensions(tracker, f"agent_{i}", 0.5 + i * 0.01, count=2)
        board = tracker.get_leaderboard(top_n=3)
        assert len(board) == 3

    def test_leaderboard_entry_has_strongest_and_weakest(self, tracker: FitnessTracker) -> None:
        # Make accuracy high, cost low
        for _ in range(MIN_OBSERVATIONS):
            tracker.record("a1", FitnessDimension.ACCURACY, 0.95)
            tracker.record("a1", FitnessDimension.COST, 0.1)
            tracker.record("a1", FitnessDimension.SAFETY, 0.5)
            tracker.record("a1", FitnessDimension.SPEED, 0.5)
            tracker.record("a1", FitnessDimension.LEARNING_RATE, 0.5)

        board = tracker.get_leaderboard()
        assert len(board) == 1
        assert board[0].strongest == FitnessDimension.ACCURACY
        assert board[0].weakest == FitnessDimension.COST

    def test_leaderboard_trend_majority_vote(self, tracker: FitnessTracker) -> None:
        # Create an agent where most dimensions are improving
        # Need >= 6 observations per dimension for trend detection
        for dim in FitnessDimension:
            low_values = [0.3, 0.3, 0.3]
            high_values = [0.8, 0.8, 0.8]
            _fill_dimension(tracker, "a1", dim, low_values + high_values)

        board = tracker.get_leaderboard()
        assert len(board) == 1
        assert board[0].trend == FitnessTrend.IMPROVING


# ---------------------------------------------------------------------------
# TestEvolutionReadiness — state transitions based on data and trends
# ---------------------------------------------------------------------------


class TestEvolutionReadiness:
    def test_needs_data_when_below_min_observations(self, tracker: FitnessTracker) -> None:
        tracker.record("a1", FitnessDimension.ACCURACY, 0.8)
        profile = tracker.get_fitness("a1")
        assert profile.evolution_readiness == EvolutionReadiness.NEEDS_DATA

    def test_ready_when_enough_data_no_strong_trend(self, tracker: FitnessTracker) -> None:
        # Stable across all dimensions with enough observations
        _fill_all_dimensions(tracker, "a1", 0.5, count=2)
        profile = tracker.get_fitness("a1")
        assert profile.total_observations >= MIN_OBSERVATIONS
        assert profile.evolution_readiness == EvolutionReadiness.READY

    def test_declining_when_two_or_more_dimensions_decline(self, tracker: FitnessTracker) -> None:
        # Make accuracy and safety declining (high -> low pattern with 6+ obs)
        for dim in [FitnessDimension.ACCURACY, FitnessDimension.SAFETY]:
            _fill_dimension(tracker, "a1", dim, [0.9, 0.9, 0.9, 0.3, 0.3, 0.3])
        # Fill others to get enough total observations
        for dim in [FitnessDimension.SPEED, FitnessDimension.COST, FitnessDimension.LEARNING_RATE]:
            _fill_dimension(tracker, "a1", dim, [0.5, 0.5, 0.5, 0.5, 0.5, 0.5])

        profile = tracker.get_fitness("a1")
        assert profile.evolution_readiness == EvolutionReadiness.DECLINING

    def test_thriving_when_three_or_more_dimensions_improving(
        self, tracker: FitnessTracker
    ) -> None:
        # Make 3 dimensions improving
        for dim in [FitnessDimension.ACCURACY, FitnessDimension.SAFETY, FitnessDimension.SPEED]:
            _fill_dimension(tracker, "a1", dim, [0.3, 0.3, 0.3, 0.9, 0.9, 0.9])
        # Fill rest to reach min obs
        for dim in [FitnessDimension.COST, FitnessDimension.LEARNING_RATE]:
            _fill_dimension(tracker, "a1", dim, [0.5, 0.5, 0.5, 0.5, 0.5, 0.5])

        profile = tracker.get_fitness("a1")
        assert profile.evolution_readiness == EvolutionReadiness.THRIVING

    def test_evolution_candidates_includes_ready_and_declining(
        self, tracker: FitnessTracker
    ) -> None:
        # "ready_agent" — enough data, no strong trend
        _fill_all_dimensions(tracker, "ready_agent", 0.5, count=2)

        # "declining_agent" — 2+ dimensions declining
        for dim in [FitnessDimension.ACCURACY, FitnessDimension.SAFETY]:
            _fill_dimension(tracker, "declining_agent", dim, [0.9, 0.9, 0.9, 0.3, 0.3, 0.3])
        for dim in [FitnessDimension.SPEED, FitnessDimension.COST, FitnessDimension.LEARNING_RATE]:
            _fill_dimension(tracker, "declining_agent", dim, [0.5, 0.5, 0.5, 0.5, 0.5, 0.5])

        candidates = tracker.get_evolution_candidates()
        assert "ready_agent" in candidates
        assert "declining_agent" in candidates

    def test_evolution_candidates_excludes_thriving(self, tracker: FitnessTracker) -> None:
        # Make 3 dimensions improving => THRIVING
        for dim in [FitnessDimension.ACCURACY, FitnessDimension.SAFETY, FitnessDimension.SPEED]:
            _fill_dimension(tracker, "a1", dim, [0.2, 0.2, 0.2, 0.9, 0.9, 0.9])
        for dim in [FitnessDimension.COST, FitnessDimension.LEARNING_RATE]:
            _fill_dimension(tracker, "a1", dim, [0.5, 0.5, 0.5, 0.5, 0.5, 0.5])

        candidates = tracker.get_evolution_candidates()
        assert "a1" not in candidates

    def test_evolution_candidates_excludes_insufficient_data(self, tracker: FitnessTracker) -> None:
        tracker.record("a1", FitnessDimension.ACCURACY, 0.5)
        candidates = tracker.get_evolution_candidates()
        assert "a1" not in candidates

    def test_evolution_candidates_respects_custom_min_observations(
        self, tracker: FitnessTracker
    ) -> None:
        _fill_all_dimensions(tracker, "a1", 0.5, count=2)  # 10 total obs
        # Default MIN_OBSERVATIONS=5 => included; custom 20 => excluded
        assert "a1" in tracker.get_evolution_candidates(min_observations=5)
        assert "a1" not in tracker.get_evolution_candidates(min_observations=20)


# ---------------------------------------------------------------------------
# TestBatchOps — record_batch, mark_evolved, clear_agent, get_stats
# ---------------------------------------------------------------------------


class TestBatchOps:
    def test_record_batch_records_all_dimensions(self, tracker: FitnessTracker) -> None:
        observations = {
            FitnessDimension.ACCURACY: 0.9,
            FitnessDimension.SPEED: 0.7,
            FitnessDimension.COST: 0.5,
            FitnessDimension.SAFETY: 0.8,
            FitnessDimension.LEARNING_RATE: 0.6,
        }
        results = tracker.record_batch("a1", observations, agent_type="scanner")
        assert len(results) == 5
        profile = tracker.get_fitness("a1")
        assert profile.total_observations == 5
        assert profile.agent_type == "scanner"

    def test_record_batch_returns_list_of_observations(self, tracker: FitnessTracker) -> None:
        observations = {FitnessDimension.ACCURACY: 0.9, FitnessDimension.SPEED: 0.7}
        results = tracker.record_batch("a1", observations)
        assert all(hasattr(r, "dimension") for r in results)
        dims = {r.dimension for r in results}
        assert FitnessDimension.ACCURACY in dims
        assert FitnessDimension.SPEED in dims

    def test_record_batch_empty_dict(self, tracker: FitnessTracker) -> None:
        results = tracker.record_batch("a1", {})
        assert results == []

    def test_mark_evolved_increments_generation(self, tracker: FitnessTracker) -> None:
        _fill_all_dimensions(tracker, "a1", 0.5)
        gen1 = tracker.mark_evolved("a1")
        assert gen1 == 1
        gen2 = tracker.mark_evolved("a1")
        assert gen2 == 2
        assert tracker.get_fitness("a1").generation == 2

    def test_mark_evolved_sets_readiness_to_thriving(self, tracker: FitnessTracker) -> None:
        _fill_all_dimensions(tracker, "a1", 0.5, count=2)
        tracker.mark_evolved("a1")
        profile = tracker.get_fitness("a1")
        assert profile.evolution_readiness == EvolutionReadiness.THRIVING

    def test_mark_evolved_sets_last_evolution_timestamp(self, tracker: FitnessTracker) -> None:
        _fill_all_dimensions(tracker, "a1", 0.5)
        before = time.time()
        tracker.mark_evolved("a1")
        after = time.time()
        profile = tracker.get_fitness("a1")
        assert before <= profile.last_evolution <= after

    def test_mark_evolved_on_unknown_agent_still_increments(self, tracker: FitnessTracker) -> None:
        gen = tracker.mark_evolved("ghost")
        assert gen == 1

    def test_clear_agent_removes_all_data(self, tracker: FitnessTracker) -> None:
        _fill_all_dimensions(tracker, "a1", 0.5, count=2)
        tracker.mark_evolved("a1")
        tracker.clear_agent("a1")

        profile = tracker.get_fitness("a1")
        assert profile.total_observations == 0
        assert profile.composite_score == 0.0

    def test_clear_agent_noop_for_unknown(self, tracker: FitnessTracker) -> None:
        # Should not raise
        tracker.clear_agent("nonexistent")

    def test_get_stats_empty_fleet(self, tracker: FitnessTracker) -> None:
        stats = tracker.get_stats()
        assert stats["total_agents"] == 0

    def test_get_stats_with_agents(self, tracker: FitnessTracker) -> None:
        _fill_all_dimensions(tracker, "a1", 0.8, count=2)
        _fill_all_dimensions(tracker, "a2", 0.6, count=2)
        stats = tracker.get_stats()
        assert stats["total_agents_tracked"] == 2
        assert stats["agents_with_sufficient_data"] == 2
        assert stats["avg_composite"] == pytest.approx(0.7, abs=0.05)
        assert stats["total_observations"] == 20
        assert "dimension_averages" in stats
        assert FitnessDimension.ACCURACY in stats["dimension_averages"]

    def test_get_stats_excludes_insufficient_from_avg(self, tracker: FitnessTracker) -> None:
        _fill_all_dimensions(tracker, "rich", 0.8, count=2)
        tracker.record("poor", FitnessDimension.ACCURACY, 0.1)  # only 1 obs
        stats = tracker.get_stats()
        assert stats["total_agents_tracked"] == 2
        assert stats["agents_with_sufficient_data"] == 1

    def test_generation_tracked_in_profile_after_recompute(self, tracker: FitnessTracker) -> None:
        _fill_all_dimensions(tracker, "a1", 0.5)
        tracker.mark_evolved("a1")
        # Recording again triggers _recompute which reads _generations
        tracker.record("a1", FitnessDimension.ACCURACY, 0.6)
        assert tracker.get_fitness("a1").generation == 1


# ---------------------------------------------------------------------------
# TestSingleton — get_fitness_tracker() returns same instance
# ---------------------------------------------------------------------------


class TestSingleton:
    def test_get_fitness_tracker_returns_same_instance(self) -> None:
        import shieldops.utils.fitness_tracker as mod

        # Reset the singleton
        mod._tracker = None
        try:
            t1 = get_fitness_tracker()
            t2 = get_fitness_tracker()
            assert t1 is t2
        finally:
            # Clean up to avoid polluting other tests
            mod._tracker = None

    def test_get_fitness_tracker_returns_fitness_tracker_type(self) -> None:
        import shieldops.utils.fitness_tracker as mod

        mod._tracker = None
        try:
            t = get_fitness_tracker()
            assert isinstance(t, FitnessTracker)
        finally:
            mod._tracker = None
