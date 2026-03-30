"""Service Health Monitor Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.service_health_monitor.graph import (
    create_service_health_monitor_graph,
)
from shieldops.agents.service_health_monitor.models import (
    ServiceHealthMonitorState,
)
from shieldops.agents.service_health_monitor.nodes import (
    set_toolkit,
)
from shieldops.agents.service_health_monitor.tools import (
    ServiceHealthMonitorToolkit,
)

logger = structlog.get_logger()


class ServiceHealthMonitorRunner:
    """Runner for the Service Health Monitor Agent."""

    def __init__(
        self,
        service_registry: Any | None = None,
        health_checker: Any | None = None,
        dependency_mapper: Any | None = None,
        remediation_engine: Any | None = None,
        notification_service: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ServiceHealthMonitorToolkit(
            service_registry=service_registry,
            health_checker=health_checker,
            dependency_mapper=dependency_mapper,
            remediation_engine=remediation_engine,
            notification_service=notification_service,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_service_health_monitor_graph()
        self._app = graph.compile()
        self._results: dict[str, ServiceHealthMonitorState] = {}
        logger.info("shm_runner.initialized")

    async def monitor(
        self,
        tenant_id: str,
    ) -> ServiceHealthMonitorState:
        """Run health monitoring for a tenant."""
        session_id = f"shm-{uuid4().hex[:12]}"
        initial = ServiceHealthMonitorState(
            tenant_id=tenant_id,
        )

        logger.info(
            "shm_runner.starting",
            session_id=session_id,
            tenant_id=tenant_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={
                    "metadata": {
                        "session_id": session_id,
                        "agent": ("service_health_monitor"),
                    },
                },
            )
            final = ServiceHealthMonitorState.model_validate(result)
            self._results[session_id] = final

            logger.info(
                "shm_runner.completed",
                session_id=session_id,
                services=len(final.services),
                degradation_events=len(final.degradation_events),
                remediation_actions=len(final.remediation_actions),
                duration_ms=(final.session_duration_ms),
            )
            return final

        except Exception as e:
            logger.error(
                "shm_runner.failed",
                session_id=session_id,
                error=str(e),
            )
            error_state = ServiceHealthMonitorState(
                tenant_id=tenant_id,
                error=str(e),
                current_step="failed",
            )
            self._results[session_id] = error_state
            return error_state

    def get_result(
        self,
        session_id: str,
    ) -> ServiceHealthMonitorState | None:
        """Get result by session ID."""
        return self._results.get(session_id)

    def list_results(
        self,
    ) -> list[dict[str, Any]]:
        """List all monitoring results."""
        return [
            {
                "session_id": sid,
                "tenant_id": state.tenant_id,
                "services": len(state.services),
                "degradation_events": len(state.degradation_events),
                "remediation_actions": len(state.remediation_actions),
                "current_step": state.current_step,
                "error": state.error,
            }
            for sid, state in self._results.items()
        ]
