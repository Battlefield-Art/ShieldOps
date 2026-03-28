"""Agent Fleet Optimizer runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.agent_fleet_optimizer.graph import (
    create_agent_fleet_optimizer_graph,
)
from shieldops.agents.agent_fleet_optimizer.models import (
    AgentFleetOptimizerState,
)
from shieldops.agents.agent_fleet_optimizer.nodes import (
    set_toolkit,
)
from shieldops.agents.agent_fleet_optimizer.tools import (
    AgentFleetOptimizerToolkit,
)
from shieldops.observability.tracing import get_tracer

logger = structlog.get_logger()


class AgentFleetOptimizerRunner:
    """Runs agent fleet optimization cycles.

    Usage::

        runner = AgentFleetOptimizerRunner()
        result = await runner.optimize(
            tenant_id="acme",
        )
    """

    def __init__(
        self,
        registry_client: Any | None = None,
        metrics_client: Any | None = None,
        scheduler_client: Any | None = None,
    ) -> None:
        self._toolkit = AgentFleetOptimizerToolkit(
            registry_client=registry_client,
            metrics_client=metrics_client,
            scheduler_client=scheduler_client,
        )
        set_toolkit(self._toolkit)

        graph = create_agent_fleet_optimizer_graph()
        self._app = graph.compile()
        self._runs: dict[str, AgentFleetOptimizerState] = {}

    async def optimize(
        self,
        tenant_id: str,
        context: dict[str, Any] | None = None,
    ) -> AgentFleetOptimizerState:
        """Run a fleet optimization cycle.

        Args:
            tenant_id: Tenant identifier.
            context: Optional overrides.

        Returns:
            Completed state with recommendations.
        """
        request_id = f"fleet-{uuid4().hex[:12]}"

        logger.info(
            "fleet_optimizer_started",
            request_id=request_id,
            tenant_id=tenant_id,
        )

        initial = AgentFleetOptimizerState(
            request_id=request_id,
            tenant_id=tenant_id,
        )

        try:
            tracer = get_tracer("shieldops.agents")
            with tracer.start_as_current_span("fleet_optimizer.optimize") as span:
                span.set_attribute(
                    "fleet_optimizer.request_id",
                    request_id,
                )
                span.set_attribute(
                    "fleet_optimizer.tenant_id",
                    tenant_id,
                )

                final_dict = await self._app.ainvoke(
                    initial.model_dump(),
                    config={
                        "metadata": {
                            "request_id": request_id,
                            "tenant_id": tenant_id,
                        },
                    },
                )

                final = AgentFleetOptimizerState.model_validate(final_dict)

                span.set_attribute(
                    "fleet_optimizer.healthy",
                    final.agents_healthy,
                )
                span.set_attribute(
                    "fleet_optimizer.issues",
                    final.agents_issues,
                )

            logger.info(
                "fleet_optimizer_completed",
                request_id=request_id,
                healthy=final.agents_healthy,
                issues=final.agents_issues,
                recs=len(final.recommendations),
                duration_ms=final.session_duration_ms,
            )

            self._runs[request_id] = final
            return final

        except Exception as e:
            logger.error(
                "fleet_optimizer_failed",
                request_id=request_id,
                error=str(e),
            )
            err = AgentFleetOptimizerState(
                request_id=request_id,
                tenant_id=tenant_id,
                error=str(e),
                current_step="failed",
            )
            self._runs[request_id] = err
            return err

    def get_run(
        self,
        request_id: str,
    ) -> AgentFleetOptimizerState | None:
        """Retrieve a completed run."""
        return self._runs.get(request_id)

    def list_runs(self) -> list[dict[str, Any]]:
        """List all optimization runs."""
        return [
            {
                "request_id": rid,
                "tenant_id": s.tenant_id,
                "status": s.current_step,
                "healthy": s.agents_healthy,
                "issues": s.agents_issues,
                "utilization": s.utilization_pct,
                "recommendations": len(s.recommendations),
                "duration_ms": s.session_duration_ms,
                "error": s.error,
            }
            for rid, s in self._runs.items()
        ]
