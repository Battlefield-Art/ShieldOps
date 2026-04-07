"""Contract tests for EvolutionStore — RFC #246 PR-1.

See ghantakiran/ShieldOps#246. The two most important tests in this
file are:

1. :meth:`TestExceptionSafety.test_record_run_exception_does_not_crash_caller`
   — the subtlest invariant. ``EvolutionStore.record_run`` wraps its
   body in a broad try/except so an internal bug cannot crash the
   agent call chain. Without this, the `@define_agent` framework
   wrapper that auto-applies ``evolution.record(...)`` to every agent
   (RFC #247) would be a catastrophic blast radius.

2. :meth:`TestCrossSubsystemIntegration.test_high_fitness_triggers_prompt_mutation_proposal`
   — the cross-subsystem integration that ``DeepAgentMixin`` was
   supposed to provide but never wired. Feeding ``record_run`` enough
   high-accuracy outcomes causes the prompt subsystem to propose a
   new challenger variant.
"""

from __future__ import annotations

import pytest

from shieldops.utils.evolution import (
    EvolutionConfig,
    EvolutionStore,
    FitnessDimension,
    LearningEventType,
    RunOutcome,
    get_evolution_store,
    set_evolution_store,
    use_test_evolution,
)
from shieldops.utils.evolution.store import NullEvolution, _BoundEvolution

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolate_composition_root():
    set_evolution_store(None)
    yield
    set_evolution_store(None)


def _successful_run(latency_ms: float = 100.0) -> RunOutcome:
    return RunOutcome(success=True, latency_ms=latency_ms, tokens_used=100, cost_usd=0.01)


def _failed_run() -> RunOutcome:
    return RunOutcome(success=False, error="tool_call_failed")


# ---------------------------------------------------------------------------
# 1. EXCEPTION SAFETY — the single most important invariant
# ---------------------------------------------------------------------------


class TestExceptionSafety:
    def test_record_run_exception_does_not_crash_caller(self) -> None:
        """A bug in the orchestration body MUST NOT crash agent code.

        We simulate a subsystem failure by monkey-patching an internal
        method to raise. The wrapped ``record_run`` should swallow it,
        increment the error counter, and return cleanly.
        """
        store = EvolutionStore.in_memory()

        # Induce a failure in the mapping step — agents should still
        # continue to execute.
        def _boom(*a, **kw):  # noqa: ARG001
            raise RuntimeError("simulated subsystem bug")

        store._outcome_to_observation = _boom  # type: ignore[assignment]

        # The call must not raise.
        store.record_run("threat_hunter", _successful_run())

        assert store.record_run_error_count == 1

        # And a subsequent call with the patch removed must work —
        # the failure doesn't leave the store in a broken state.
        del store._outcome_to_observation  # restore normal behavior
        store.record_run("threat_hunter", _successful_run())
        # Leaderboard should now contain one successful observation.
        board = store.leaderboard(dim=FitnessDimension.ACCURACY)
        assert len(board) == 1
        assert board[0].agent_id == "threat_hunter"
        assert board[0].value == 1.0

    def test_multiple_exceptions_accumulate_in_counter(self) -> None:
        store = EvolutionStore.in_memory()

        def _boom(*a, **kw):  # noqa: ARG001
            raise RuntimeError("always fails")

        store._outcome_to_observation = _boom  # type: ignore[assignment]

        for _ in range(5):
            store.record_run("x", _successful_run())

        assert store.record_run_error_count == 5

    def test_bound_evolution_record_also_swallows_exceptions(self) -> None:
        """The handle returned by for_agent() must also be exception-safe."""
        store = EvolutionStore.in_memory()
        store._outcome_to_observation = lambda *a, **kw: (_ for _ in ()).throw(  # type: ignore[assignment]
            ValueError("bound bug")
        )

        handle = store.for_agent("x")
        # Must not raise:
        handle.record(_successful_run())
        assert store.record_run_error_count == 1


# ---------------------------------------------------------------------------
# 2. CROSS-SUBSYSTEM INTEGRATION — the whole point of the RFC
# ---------------------------------------------------------------------------


class TestCrossSubsystemIntegration:
    def test_high_fitness_triggers_prompt_mutation_proposal(self) -> None:
        """DeepAgentMixin's intent: when fitness crosses a threshold,
        a prompt variant is proposed. This test proves the integration
        is actually wired — something that was never true before this RFC.
        """
        store = EvolutionStore.in_memory()

        # Baseline: no prompt mutation proposed yet, champion prompt active.
        prompt_before = store.prompt_for("soc_analyst")
        assert prompt_before.is_challenger is False

        # Record enough high-accuracy runs to cross the mutation threshold.
        for _ in range(5):
            store.record_run(
                "soc_analyst",
                RunOutcome(
                    success=True,
                    latency_ms=50.0,  # fast → high speed score
                    tokens_used=50,
                    cost_usd=0.001,  # cheap → high cost score
                    helped=True,  # downstream says it helped → high learning score
                ),
            )

        # The learning bus should now contain a PROMPT_VARIANT_PROPOSED event.
        events = store._learning  # internal, but OK for a contract test
        proposed_events = [
            e for e in events if e.event_type == LearningEventType.PROMPT_VARIANT_PROPOSED
        ]
        assert len(proposed_events) >= 1
        assert proposed_events[0].agent_id == "soc_analyst"

    def test_fitness_observed_event_published_on_every_record(self) -> None:
        store = EvolutionStore.in_memory()
        for _ in range(3):
            store.record_run("x", _successful_run())

        observed_events = [
            e for e in store._learning if e.event_type == LearningEventType.FITNESS_OBSERVED
        ]
        assert len(observed_events) == 3
        assert all(e.agent_id == "x" for e in observed_events)

    def test_failed_runs_lower_accuracy_without_triggering_mutation(self) -> None:
        store = EvolutionStore.in_memory()
        # All failures — accuracy averages 0.0, way below threshold.
        for _ in range(5):
            store.record_run("x", _failed_run())

        prompt = store.prompt_for("x")
        assert prompt.is_challenger is False  # no mutation proposed

        board = store.leaderboard(dim=FitnessDimension.ACCURACY)
        assert board[0].value == 0.0


# ---------------------------------------------------------------------------
# 3. Multi-tenant isolation
# ---------------------------------------------------------------------------


class TestMultiTenant:
    def test_two_tenants_have_isolated_fitness_state(self) -> None:
        store = EvolutionStore.in_memory()

        for _ in range(5):
            store.record_run("x", _successful_run(), tenant_id="acme")
            store.record_run("x", _failed_run(), tenant_id="globex")

        acme_board = store.leaderboard(dim=FitnessDimension.ACCURACY, tenant_id="acme")
        globex_board = store.leaderboard(dim=FitnessDimension.ACCURACY, tenant_id="globex")

        assert acme_board[0].value == 1.0  # all successes
        assert globex_board[0].value == 0.0  # all failures

    def test_bound_handles_are_keyed_by_tenant(self) -> None:
        store = EvolutionStore.in_memory()
        handle_a = store.for_agent("x", tenant_id="acme")
        handle_b = store.for_agent("x", tenant_id="globex")

        handle_a.record(_successful_run())
        handle_b.record(_failed_run())

        assert store.leaderboard(dim=FitnessDimension.ACCURACY, tenant_id="acme")[0].value == 1.0
        assert store.leaderboard(dim=FitnessDimension.ACCURACY, tenant_id="globex")[0].value == 0.0


# ---------------------------------------------------------------------------
# 4. RunOutcome → FitnessObservation mapping
# ---------------------------------------------------------------------------


class TestOutcomeMapping:
    def test_successful_run_gives_accuracy_one(self) -> None:
        store = EvolutionStore.in_memory()
        store.record_run("x", _successful_run())
        board = store.leaderboard(dim=FitnessDimension.ACCURACY)
        assert board[0].value == 1.0

    def test_failed_run_gives_accuracy_zero(self) -> None:
        store = EvolutionStore.in_memory()
        store.record_run("x", _failed_run())
        board = store.leaderboard(dim=FitnessDimension.ACCURACY)
        assert board[0].value == 0.0

    def test_fast_run_gives_higher_speed_score_than_slow_run(self) -> None:
        store = EvolutionStore.in_memory()
        store.record_run("fast", _successful_run(latency_ms=10.0))
        store.record_run("slow", _successful_run(latency_ms=10_000.0))

        board = store.leaderboard(dim=FitnessDimension.SPEED)
        fast_score = next(s for s in board if s.agent_id == "fast").value
        slow_score = next(s for s in board if s.agent_id == "slow").value
        assert fast_score > slow_score


# ---------------------------------------------------------------------------
# 5. Evolution handle + for_agent
# ---------------------------------------------------------------------------


class TestEvolutionHandle:
    def test_for_agent_returns_bound_handle(self) -> None:
        store = EvolutionStore.in_memory()
        handle = store.for_agent("x", tenant_id="acme")
        assert isinstance(handle, _BoundEvolution)
        assert handle.agent_id == "x"
        assert handle.tenant_id == "acme"

    def test_handle_record_routes_through_store(self) -> None:
        store = EvolutionStore.in_memory()
        store.for_agent("x").record(_successful_run())
        board = store.leaderboard(dim=FitnessDimension.ACCURACY)
        assert len(board) == 1

    def test_handle_prompt_returns_current_version(self) -> None:
        store = EvolutionStore.in_memory()
        handle = store.for_agent("x")
        prompt = handle.prompt()
        assert prompt.version_id == "v1"

    def test_handle_prompt_version_returns_string(self) -> None:
        store = EvolutionStore.in_memory()
        assert store.for_agent("x").prompt_version() == "v1"

    def test_null_evolution_is_safe_default(self) -> None:
        """An agent with a NullEvolution handle does not crash on record()."""
        handle = NullEvolution()
        handle.record(_successful_run())  # no-op
        assert handle.prompt().version_id == "null"
        assert handle.prompt_version() == "null"


# ---------------------------------------------------------------------------
# 6. Composition root + use_test_evolution
# ---------------------------------------------------------------------------


class TestComposition:
    def test_get_store_raises_when_not_installed(self) -> None:
        with pytest.raises(RuntimeError, match="No EvolutionStore installed"):
            get_evolution_store()

    def test_use_test_evolution_installs_and_restores(self) -> None:
        original = EvolutionStore.in_memory()
        set_evolution_store(original)

        with use_test_evolution() as fresh:
            assert get_evolution_store() is fresh
            assert fresh is not original

        assert get_evolution_store() is original

    def test_use_test_evolution_restores_on_exception(self) -> None:
        original = EvolutionStore.in_memory()
        set_evolution_store(original)

        with pytest.raises(ValueError, match="test"), use_test_evolution():
            raise ValueError("test")

        assert get_evolution_store() is original

    def test_use_test_evolution_with_custom_store(self) -> None:
        config = EvolutionConfig(mutation_threshold=0.5)
        custom = EvolutionStore(config=config)
        with use_test_evolution(custom) as s:
            assert s is custom
            assert s.config.mutation_threshold == 0.5


# ---------------------------------------------------------------------------
# 7. Leaderboard
# ---------------------------------------------------------------------------


class TestLeaderboard:
    def test_leaderboard_orders_descending_by_score(self) -> None:
        store = EvolutionStore.in_memory()
        store.record_run("low", _failed_run())
        store.record_run("high", _successful_run())
        store.record_run("mid", _successful_run())
        store.record_run("mid", _failed_run())

        board = store.leaderboard(dim=FitnessDimension.ACCURACY)
        assert [s.agent_id for s in board] == ["high", "mid", "low"]

    def test_leaderboard_respects_top_limit(self) -> None:
        store = EvolutionStore.in_memory()
        for i in range(10):
            store.record_run(f"agent-{i}", _successful_run())
        board = store.leaderboard(dim=FitnessDimension.ACCURACY, top=3)
        assert len(board) == 3

    def test_empty_store_returns_empty_leaderboard(self) -> None:
        store = EvolutionStore.in_memory()
        assert store.leaderboard(dim=FitnessDimension.ACCURACY) == []
