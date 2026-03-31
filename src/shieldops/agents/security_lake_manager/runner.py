"""Security Lake Manager Agent runner — entry point
for security data lake management."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.security_lake_manager.graph import (
    create_security_lake_manager_graph,
)
from shieldops.agents.security_lake_manager.models import (
    SecurityLakeState,
)
from shieldops.agents.security_lake_manager.nodes import (
    set_toolkit,
)
from shieldops.agents.security_lake_manager.tools import (
    SecurityLakeManagerToolkit,
)

logger = structlog.get_logger()


class SecurityLakeManagerRunner:
    """Runner for the Security Lake Manager Agent."""

    def __init__(
        self,
        source_registry: Any | None = None,
        ingestion_engine: Any | None = None,
        schema_mapper: Any | None = None,
        storage_manager: Any | None = None,
        query_engine: Any | None = None,
        metrics_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecurityLakeManagerToolkit(
            source_registry=source_registry,
            ingestion_engine=ingestion_engine,
            schema_mapper=schema_mapper,
            storage_manager=storage_manager,
            query_engine=query_engine,
            metrics_store=metrics_store,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_security_lake_manager_graph()
        self._app = graph.compile()
        self._results: dict[str, SecurityLakeState] = {}
        logger.info("slm_runner.initialized")

    async def manage(
        self,
        tenant_id: str = "",
    ) -> SecurityLakeState:
        """Run security lake management cycle."""
        request_id = f"slm-{uuid4().hex[:12]}"

        initial_state = SecurityLakeState(
            request_id=request_id,
            tenant_id=tenant_id,
        )

        logger.info(
            "slm_runner.starting",
            request_id=request_id,
            tenant_id=tenant_id,
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "security_lake_manager",
                    },
                },
            )
            final = SecurityLakeState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "slm_runner.completed",
                request_id=request_id,
                sources=final.total_sources,
                volume_gb=final.total_daily_volume_gb,
                savings_pct=final.cost_savings_pct,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "slm_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = SecurityLakeState(
                request_id=request_id,
                tenant_id=tenant_id,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> SecurityLakeState | None:
        """Retrieve a cached management result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all management results as summaries."""
        return [
            {
                "request_id": rid,
                "total_sources": s.total_sources,
                "volume_gb": s.total_daily_volume_gb,
                "savings_pct": s.cost_savings_pct,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
