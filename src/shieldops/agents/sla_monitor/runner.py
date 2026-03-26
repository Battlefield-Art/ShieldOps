"""SLA Monitor Agent runner — entry point for executing SLA monitoring workflows."""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.sla_monitor.graph import create_sla_monitor_graph
from shieldops.agents.sla_monitor.models import SLAMonitorState
from shieldops.agents.sla_monitor.nodes import set_toolkit
from shieldops.agents.sla_monitor.tools import SLAMonitorToolkit

logger = structlog.get_logger()


class SLAMonitorRunner:
    """Runner for the SLA Monitor Agent."""

    def __init__(
        self,
        metrics_provider: Any | None = None,
        slo_store: Any | None = None,
        alerting_engine: Any | None = None,
        notification_service: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SLAMonitorToolkit(
            metrics_provider=metrics_provider,
            slo_store=slo_store,
            alerting_engine=alerting_engine,
            notification_service=notification_service,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_sla_monitor_graph()
        self._app = graph.compile()
        self._results: dict[str, SLAMonitorState] = {}
        logger.info("sla_monitor_runner.initialized")

    async def monitor(
        self,
        tenant_id: str,
        services: list[str] | None = None,
    ) -> SLAMonitorState:
        """Run SLA monitoring for a tenant."""
        session_id = f"sla-{uuid4().hex[:12]}"
        initial_state = SLAMonitorState(
            tenant_id=tenant_id,
            services=services or [],
        )

        logger.info(
            "sla_monitor_runner.starting",
            session_id=session_id,
            tenant_id=tenant_id,
            service_count=len(initial_state.services),
        )

        try:
            final_state_dict = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={"metadata": {"session_id": session_id, "agent": "sla_monitor"}},
            )
            final_state = SLAMonitorState.model_validate(final_state_dict)
            self._results[session_id] = final_state

            logger.info(
                "sla_monitor_runner.completed",
                session_id=session_id,
                sli_count=len(final_state.sli_metrics),
                slo_count=len(final_state.slo_statuses),
                alert_count=len(final_state.burn_rate_alerts),
                duration_ms=final_state.session_duration_ms,
            )
            return final_state

        except Exception as e:
            logger.error("sla_monitor_runner.failed", session_id=session_id, error=str(e))
            error_state = SLAMonitorState(
                tenant_id=tenant_id,
                services=services or [],
                error=str(e),
                current_step="failed",
            )
            self._results[session_id] = error_state
            return error_state

    def get_result(self, session_id: str) -> SLAMonitorState | None:
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        return [
            {
                "session_id": sid,
                "tenant_id": state.tenant_id,
                "slo_count": len(state.slo_statuses),
                "alert_count": len(state.burn_rate_alerts),
                "current_step": state.current_step,
                "error": state.error,
            }
            for sid, state in self._results.items()
        ]
