"""In-memory fitness recorder — records every call for test assertions.

Implements :class:`shieldops.utils.llm_core.ports.FitnessRecorderPort`.
In production the :class:`EvolutionStoreFitnessAdapter` (PR-2) wraps
RFC #246's :class:`EvolutionStore.record_run`. The contract is the
same — every call, success or failure, records exactly one entry.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4

from shieldops.utils.llm_core.types import ModelTier


@dataclass
class FitnessRecord:
    agent_id: str
    tenant_id: str | None
    model_used: ModelTier
    latency_ms: float
    tokens: int
    cost_usd: float
    success: bool
    forced: bool = False
    run_id: str = ""


class InMemoryFitnessRecorder:
    """Captures every ``record_run`` call on ``.records``."""

    def __init__(self) -> None:
        self.records: list[FitnessRecord] = []

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
        run_id = f"run-{uuid4().hex[:12]}"
        self.records.append(
            FitnessRecord(
                agent_id=agent_id,
                tenant_id=tenant_id,
                model_used=model_used,
                latency_ms=latency_ms,
                tokens=tokens,
                cost_usd=cost_usd,
                success=success,
                forced=forced,
                run_id=run_id,
            )
        )
        return run_id

    def for_agent(self, agent_id: str) -> list[FitnessRecord]:
        return [r for r in self.records if r.agent_id == agent_id]
