"""Evolution-backed FitnessRecorder — the sister-RFC bridge (#248 PR-2).

See ghantakiran/ShieldOps#248 and ghantakiran/ShieldOps#246.

This adapter is the production implementation of
:class:`shieldops.utils.llm_core.ports.FitnessRecorderPort`. It
translates the orchestrator-shaped ``record_run`` call into a
:class:`shieldops.utils.evolution.store.RunOutcome` and hands it to
the installed :class:`EvolutionStore` via
``store.for_agent(agent_id).record(outcome)``.

Why this is its own adapter (rather than an engine-internal call):

1. **Keeps the orchestrator pure.** The orchestrator has zero imports
   from ``shieldops.utils.evolution`` — only from ``llm_core.ports``.
   The cross-subsystem coupling lives in this adapter, where it can
   be unit-tested against an in-memory store.

2. **PR-2 is reversible.** If the evolution store is rolled back or
   swapped, the orchestrator keeps running by swapping this adapter
   for :class:`InMemoryFitnessRecorder` in the composition root. No
   code changes elsewhere.

3. **Exception safety is layered.** ``EvolutionStore.record_run`` is
   already exception-safe (RFC #246 PR-1 locked that), but we wrap
   the call in this adapter too so a broken ``for_agent`` override
   or a missing-store ``RuntimeError`` at call time cannot bubble up
   into the orchestrator's hot path.

Usage (in composition root / lifespan hook)::

    deps = LLMDeps(
        ...,
        fitness=EvolutionFitnessRecorder(),
        ...,
    )

The adapter resolves the store lazily via
:func:`shieldops.utils.evolution.composition.get_evolution_store` on
every call, so ``use_test_evolution(...)`` round-trips work without
rebuilding the orchestrator.
"""

from __future__ import annotations

from uuid import uuid4

import structlog

from shieldops.utils.evolution.composition import get_evolution_store
from shieldops.utils.evolution.store import RunOutcome
from shieldops.utils.llm_core.types import ModelTier

logger = structlog.get_logger(__name__)


class EvolutionFitnessRecorder:
    """Production ``FitnessRecorderPort`` backed by #246's EvolutionStore.

    Shape matches :class:`InMemoryFitnessRecorder` exactly so the
    composition root is a one-line swap.
    """

    def __init__(self, *, default_tenant_id: str = "default") -> None:
        self._default_tenant_id = default_tenant_id

    async def record_run(
        self,
        *,
        agent_id: str,
        tenant_id: str | None,
        model_used: ModelTier,
        latency_ms: float,
        tokens: int,
        cost_usd: float,
        success: bool,
        forced: bool = False,
    ) -> str:
        """Record the run in the evolution store.

        Returns a run_id even if the evolution store is missing or the
        underlying call raises — the orchestrator uses the returned id
        in its structured logs and a missing id would corrupt those.
        """
        run_id = f"run-{uuid4().hex[:12]}"

        outcome = RunOutcome(
            success=success,
            latency_ms=latency_ms,
            tokens_used=tokens,
            cost_usd=cost_usd,
            metadata={
                "source": "llm_orchestrator",
                "model_used": str(model_used),
                "forced": forced,
                "run_id": run_id,
            },
        )

        try:
            store = get_evolution_store()
        except RuntimeError:
            # No store installed — same compatibility guarantee as the
            # sister adapters in #244 PR-2 and #246 PR-2. Log once at
            # debug and move on.
            logger.debug(
                "llm_orch.fitness.store_not_installed",
                agent_id=agent_id,
                run_id=run_id,
            )
            return run_id

        try:
            handle = store.for_agent(
                agent_id,
                tenant_id=tenant_id or self._default_tenant_id,
            )
            handle.record(outcome)
        except Exception as exc:  # noqa: BLE001
            # Store is broken but the caller must not crash.
            logger.warning(
                "llm_orch.fitness.record_failed",
                agent_id=agent_id,
                run_id=run_id,
                error=str(exc),
            )

        return run_id
