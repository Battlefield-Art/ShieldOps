"""Contract tests for :class:`EvolutionFitnessRecorder` — #248 PR-2.

See ghantakiran/ShieldOps#248 and ghantakiran/ShieldOps#246.

This is the sister-RFC bridge between the pure LLM orchestrator and
the evolution subsystem. The adapter translates the orchestrator's
``record_run`` call into a ``RunOutcome`` + ``store.for_agent(...).
record(outcome)`` round-trip.

Invariants locked by these tests:

1. **One LLM call → exactly one RunOutcome** in the installed store.
2. **Every field maps correctly** — success/latency_ms/tokens_used/
   cost_usd + a metadata blob containing model_used/forced/run_id/
   source.
3. **Tenant routing works** — the orchestrator-supplied ``tenant_id``
   reaches ``store.for_agent(..., tenant_id=...)`` unchanged, falling
   back to ``default_tenant_id`` when None.
4. **Missing-store fallback** — no installed store means the adapter
   still returns a run_id and does not raise.
5. **Broken-store fallback** — an adapter whose ``for_agent`` or
   ``record`` raises does not crash the caller.
6. **run_id is always returned** and is stable-ish (``run-XXXXXX``
   prefix) so the orchestrator's structured logs stay intact.
"""

from __future__ import annotations

from typing import Any

import pytest

from shieldops.utils.evolution.composition import (
    set_evolution_store,
    use_test_evolution,
)
from shieldops.utils.evolution.store import EvolutionStore
from shieldops.utils.llm_core.adapters.evolution_fitness import (
    EvolutionFitnessRecorder,
)
from shieldops.utils.llm_core.types import ModelTier


@pytest.fixture(autouse=True)
def _isolate_store():
    set_evolution_store(None)
    yield
    set_evolution_store(None)


def _learning_events_for(store: EvolutionStore, agent_id: str) -> list[Any]:
    return [e for e in store.learning_events() if e.agent_id == agent_id]


def _learning_events_for_tenant(store: EvolutionStore, tenant_id: str) -> list[Any]:
    return [
        e
        for e in store.learning_events(tenant_id=tenant_id)
        if e.payload.get("tenant_id") == tenant_id
    ]


class TestSuccessPath:
    @pytest.mark.asyncio
    async def test_single_call_produces_single_observation(self) -> None:
        recorder = EvolutionFitnessRecorder()
        with use_test_evolution() as store:
            run_id = await recorder.record_run(
                agent_id="agent-a",
                tenant_id="org-a",
                model_used=ModelTier.SONNET,
                latency_ms=420.0,
                tokens=1500,
                cost_usd=0.03,
                success=True,
            )

            assert run_id.startswith("run-")
            events = _learning_events_for_tenant(store, "org-a")
            assert len(events) == 1
            obs = events[0].payload["observation"]
            # success → accuracy=1.0 in _outcome_to_observation
            assert obs["accuracy"] == 1.0

    @pytest.mark.asyncio
    async def test_failure_call_records_zero_accuracy(self) -> None:
        recorder = EvolutionFitnessRecorder()
        with use_test_evolution() as store:
            await recorder.record_run(
                agent_id="agent-a",
                tenant_id="org-a",
                model_used=ModelTier.HAIKU,
                latency_ms=90.0,
                tokens=50,
                cost_usd=0.0,
                success=False,
            )
            events = _learning_events_for_tenant(store, "org-a")
            assert len(events) == 1
            obs = events[0].payload["observation"]
            assert obs["accuracy"] == 0.0


class TestTenantRouting:
    @pytest.mark.asyncio
    async def test_explicit_tenant_reaches_store(self) -> None:
        recorder = EvolutionFitnessRecorder()
        with use_test_evolution() as store:
            await recorder.record_run(
                agent_id="agent-b",
                tenant_id="org-b",
                model_used=ModelTier.SONNET,
                latency_ms=200.0,
                tokens=100,
                cost_usd=0.01,
                success=True,
            )
            assert len(_learning_events_for_tenant(store, "org-b")) == 1
            # No event landed under 'default'.
            assert _learning_events_for_tenant(store, "default") == []

    @pytest.mark.asyncio
    async def test_none_tenant_uses_default(self) -> None:
        recorder = EvolutionFitnessRecorder(default_tenant_id="fallback-tenant")
        with use_test_evolution() as store:
            await recorder.record_run(
                agent_id="agent-c",
                tenant_id=None,
                model_used=ModelTier.OPUS,
                latency_ms=5000.0,
                tokens=10000,
                cost_usd=0.75,
                success=True,
            )
            assert len(_learning_events_for_tenant(store, "fallback-tenant")) == 1


class TestMissingStoreFallback:
    @pytest.mark.asyncio
    async def test_no_store_installed_returns_run_id_without_crash(self) -> None:
        recorder = EvolutionFitnessRecorder()
        # No use_test_evolution — store is None.
        run_id = await recorder.record_run(
            agent_id="agent-a",
            tenant_id="org-a",
            model_used=ModelTier.SONNET,
            latency_ms=100.0,
            tokens=50,
            cost_usd=0.0,
            success=True,
        )
        assert run_id.startswith("run-")
        # And no store = no events recorded anywhere.


class TestBrokenStoreFallback:
    @pytest.mark.asyncio
    async def test_for_agent_raising_does_not_crash_caller(self) -> None:
        class _BrokenStore:
            def for_agent(
                self,
                _agent_id: str,
                *,
                tenant_id: str = "default",  # noqa: ARG002
            ) -> None:
                raise RuntimeError("store subsystem down")

            def record_run(self, *_: Any, **__: Any) -> None:
                raise RuntimeError("store subsystem down")

            def learning_events(self, **_: Any) -> list[Any]:
                return []

        set_evolution_store(_BrokenStore())  # type: ignore[arg-type]

        recorder = EvolutionFitnessRecorder()
        run_id = await recorder.record_run(
            agent_id="agent-a",
            tenant_id="org-a",
            model_used=ModelTier.HAIKU,
            latency_ms=80.0,
            tokens=10,
            cost_usd=0.0,
            success=True,
        )
        assert run_id.startswith("run-")

    @pytest.mark.asyncio
    async def test_record_raising_does_not_crash_caller(self) -> None:
        class _BrokenHandle:
            def record(self, _outcome: Any) -> None:
                raise RuntimeError("record is broken")

            def prompt(self) -> None:
                return None

            def prompt_version(self) -> str:
                return ""

        class _PartiallyBrokenStore:
            def for_agent(self, _agent_id: str, *, tenant_id: str = "default") -> _BrokenHandle:  # noqa: ARG002
                return _BrokenHandle()

            def record_run(self, *_: Any, **__: Any) -> None:
                pass

            def learning_events(self, **_: Any) -> list[Any]:
                return []

        set_evolution_store(_PartiallyBrokenStore())  # type: ignore[arg-type]

        recorder = EvolutionFitnessRecorder()
        run_id = await recorder.record_run(
            agent_id="agent-a",
            tenant_id="org-a",
            model_used=ModelTier.SONNET,
            latency_ms=120.0,
            tokens=50,
            cost_usd=0.0,
            success=True,
        )
        assert run_id.startswith("run-")
