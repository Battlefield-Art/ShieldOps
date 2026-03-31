"""Security Telemetry Optimizer Agent runner — entry point
for executing telemetry optimization campaigns."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.security_telemetry_optimizer.graph import (
    create_security_telemetry_optimizer_graph,
)
from shieldops.agents.security_telemetry_optimizer.models import (
    SecurityTelemetryOptimizerState,
)
from shieldops.agents.security_telemetry_optimizer.nodes import (
    set_toolkit,
)
from shieldops.agents.security_telemetry_optimizer.tools import (
    SecurityTelemetryOptimizerToolkit,
)

logger = structlog.get_logger()


class SecurityTelemetryOptimizerRunner:
    """Runner for the Security Telemetry Optimizer Agent."""

    def __init__(
        self,
        pipeline_manager: Any | None = None,
        volume_analyzer: Any | None = None,
        waste_detector: Any | None = None,
        routing_engine: Any | None = None,
        quality_validator: Any | None = None,
        cost_engine: Any | None = None,
        metrics_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecurityTelemetryOptimizerToolkit(
            pipeline_manager=pipeline_manager,
            volume_analyzer=volume_analyzer,
            waste_detector=waste_detector,
            routing_engine=routing_engine,
            quality_validator=quality_validator,
            cost_engine=cost_engine,
            metrics_store=metrics_store,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_security_telemetry_optimizer_graph()
        self._app = graph.compile()
        self._results: dict[str, SecurityTelemetryOptimizerState] = {}
        logger.info("sto_runner.initialized")

    async def optimize(
        self,
        pipeline_name: str,
        target_sources: list[str] | None = None,
        budget_limit: float = 0.0,
        quality_threshold: float = 0.95,
        tenant_id: str = "",
    ) -> SecurityTelemetryOptimizerState:
        """Run a telemetry optimization campaign."""
        request_id = f"sto-{uuid4().hex[:12]}"

        initial_state = SecurityTelemetryOptimizerState(
            request_id=request_id,
            tenant_id=tenant_id,
            pipeline_name=pipeline_name,
            target_sources=target_sources or [],
            budget_limit=budget_limit,
            quality_threshold=quality_threshold,
        )

        logger.info(
            "sto_runner.starting",
            request_id=request_id,
            pipeline=pipeline_name,
            targets=len(target_sources or []),
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": ("security_telemetry_optimizer"),
                    },
                },
            )
            final = SecurityTelemetryOptimizerState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "sto_runner.completed",
                request_id=request_id,
                savings_gb=final.total_savings_gb,
                savings_cost=final.total_savings_cost,
                quality=final.quality_maintained,
                sources=final.sources_optimized,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "sto_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = SecurityTelemetryOptimizerState(
                request_id=request_id,
                tenant_id=tenant_id,
                pipeline_name=pipeline_name,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> SecurityTelemetryOptimizerState | None:
        """Retrieve a cached optimization result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all optimization results as summaries."""
        return [
            {
                "request_id": rid,
                "pipeline": s.pipeline_name,
                "savings_gb": s.total_savings_gb,
                "savings_cost": s.total_savings_cost,
                "quality_maintained": s.quality_maintained,
                "sources_optimized": s.sources_optimized,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
