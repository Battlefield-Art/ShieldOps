"""Security Alert Router Agent runner — entry point
for intelligent alert routing and assignment."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.security_alert_router.graph import (
    create_security_alert_router_graph,
)
from shieldops.agents.security_alert_router.models import (
    SecurityAlertRouterState,
)
from shieldops.agents.security_alert_router.nodes import (
    set_toolkit,
)
from shieldops.agents.security_alert_router.tools import (
    SecurityAlertRouterToolkit,
)

logger = structlog.get_logger()


class SecurityAlertRouterRunner:
    """Runner for the Security Alert Router Agent."""

    def __init__(
        self,
        alert_source: Any | None = None,
        classifier: Any | None = None,
        team_registry: Any | None = None,
        notification_engine: Any | None = None,
        ack_tracker: Any | None = None,
        metrics_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecurityAlertRouterToolkit(
            alert_source=alert_source,
            classifier=classifier,
            team_registry=team_registry,
            notification_engine=notification_engine,
            ack_tracker=ack_tracker,
            metrics_store=metrics_store,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_security_alert_router_graph()
        self._app = graph.compile()
        self._results: dict[str, SecurityAlertRouterState] = {}
        logger.info("sar_runner.initialized")

    async def route(
        self,
        alert_sources: list[str] | None = None,
        scope: dict[str, Any] | None = None,
        routing_rules: dict[str, Any] | None = None,
        tenant_id: str = "",
    ) -> SecurityAlertRouterState:
        """Run alert routing for incoming security alerts."""
        request_id = f"sar-{uuid4().hex[:12]}"

        initial_state = SecurityAlertRouterState(
            request_id=request_id,
            tenant_id=tenant_id,
            alert_sources=alert_sources or [],
            scope=scope or {},
            routing_rules=routing_rules or {},
        )

        logger.info(
            "sar_runner.starting",
            request_id=request_id,
            sources=len(alert_sources or []),
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "security_alert_router",
                    },
                },
            )
            final = SecurityAlertRouterState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "sar_runner.completed",
                request_id=request_id,
                total=final.total_alerts,
                routed=final.routed_count,
                acked=final.acked_count,
                avg_response=final.avg_response_minutes,
            )
            return final

        except Exception as e:
            logger.error(
                "sar_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = SecurityAlertRouterState(
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
    ) -> SecurityAlertRouterState | None:
        """Retrieve a cached routing result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all routing results as summaries."""
        return [
            {
                "request_id": rid,
                "total_alerts": s.total_alerts,
                "routed_count": s.routed_count,
                "acked_count": s.acked_count,
                "avg_response": s.avg_response_minutes,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
