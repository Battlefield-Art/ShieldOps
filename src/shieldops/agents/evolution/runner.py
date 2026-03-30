"""Runner for the Evolution Engine Agent."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from shieldops.agents.evolution.graph import create_evolution_graph
from shieldops.agents.evolution.models import EvolutionState

logger = structlog.get_logger()


class EvolutionRunner:
    """Entry point for running agent evolution cycles.

    Usage:
        runner = EvolutionRunner()

        # Evolve all eligible agents
        result = await runner.evolve()

        # Evolve specific agents
        result = await runner.evolve(target_agent_ids=["agent_1", "agent_2"])

        # Dry run (no actual changes)
        result = await runner.evolve(dry_run=True)
    """

    def __init__(self) -> None:
        self._graph = create_evolution_graph()
        self._compiled = self._graph.compile()
        self._results: dict[str, EvolutionState] = {}

    async def evolve(
        self,
        target_agent_ids: list[str] | None = None,
        max_candidates: int = 10,
        dry_run: bool = False,
        tenant_id: str = "",
    ) -> EvolutionState:
        """Run a full evolution cycle.

        Args:
            target_agent_ids: Specific agents to evolve. None = auto-select.
            max_candidates: Maximum agents to evolve in one cycle.
            dry_run: If True, analyze but don't deploy changes.
            tenant_id: Tenant ID for multi-tenant isolation.

        Returns:
            Final EvolutionState with all metrics and results.
        """
        request_id = f"evo_{uuid.uuid4().hex[:12]}"
        start = time.time()

        initial_state = EvolutionState(
            request_id=request_id,
            tenant_id=tenant_id,
            target_agent_ids=target_agent_ids or [],
            max_candidates=max_candidates,
            dry_run=dry_run,
        )

        logger.info(
            "evolution.cycle_start",
            request_id=request_id,
            targets=len(target_agent_ids or []),
            max_candidates=max_candidates,
            dry_run=dry_run,
        )

        result = await self._compiled.ainvoke(initial_state.model_dump())
        state = EvolutionState(**result)

        duration_ms = int((time.time() - start) * 1000)
        logger.info(
            "evolution.cycle_complete",
            request_id=request_id,
            candidates=state.total_candidates,
            mutations=state.total_mutations,
            deployments=state.total_deployments,
            improvement_pct=state.improvement_pct,
            duration_ms=duration_ms,
        )

        self._results[request_id] = state
        return state

    def get_result(self, request_id: str) -> EvolutionState | None:
        """Get the result of a previous evolution cycle."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all evolution cycle results."""
        return [
            {
                "request_id": rid,
                "candidates": s.total_candidates,
                "mutations": s.total_mutations,
                "deployments": s.total_deployments,
                "improvement_pct": s.improvement_pct,
                "fleet_fitness": s.fleet_fitness_after,
            }
            for rid, s in self._results.items()
        ]
