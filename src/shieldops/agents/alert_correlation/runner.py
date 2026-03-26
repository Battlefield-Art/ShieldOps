"""Alert Correlation Agent runner — entry point for executing correlation workflows."""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.alert_correlation.graph import (
    create_alert_correlation_graph,
)
from shieldops.agents.alert_correlation.models import AlertCorrelationState
from shieldops.agents.alert_correlation.nodes import set_toolkit
from shieldops.agents.alert_correlation.tools import AlertCorrelationToolkit

logger = structlog.get_logger()


class AlertCorrelationRunner:
    """Runner for the Alert Correlation Agent."""

    def __init__(
        self,
        alert_sources: Any | None = None,
        correlation_engine: Any | None = None,
        kill_chain_mapper: Any | None = None,
        topology_resolver: Any | None = None,
        identity_resolver: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = AlertCorrelationToolkit(
            alert_sources=alert_sources,
            correlation_engine=correlation_engine,
            kill_chain_mapper=kill_chain_mapper,
            topology_resolver=topology_resolver,
            identity_resolver=identity_resolver,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_alert_correlation_graph()
        self._app = graph.compile()
        self._results: dict[str, AlertCorrelationState] = {}
        logger.info("alert_correlation_runner.initialized")

    async def correlate(
        self,
        tenant_id: str,
        time_window_minutes: int = 60,
    ) -> AlertCorrelationState:
        """Run alert correlation for a tenant over a time window."""
        session_id = f"corr-{uuid4().hex[:12]}"
        initial_state = AlertCorrelationState(
            tenant_id=tenant_id,
            time_window_minutes=time_window_minutes,
        )

        logger.info(
            "alert_correlation_runner.starting",
            session_id=session_id,
            tenant_id=tenant_id,
            time_window_minutes=time_window_minutes,
        )

        try:
            final_state_dict = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": session_id,
                        "agent": "alert_correlation",
                    }
                },
            )
            final_state = AlertCorrelationState.model_validate(final_state_dict)
            self._results[session_id] = final_state

            logger.info(
                "alert_correlation_runner.completed",
                session_id=session_id,
                total_alerts=final_state.total_alerts_ingested,
                clusters=len(final_state.clusters),
                incidents=len(final_state.incidents),
                noise_reduction=final_state.noise_reduction_ratio,
                duration_ms=final_state.session_duration_ms,
            )
            return final_state

        except Exception as e:
            logger.error(
                "alert_correlation_runner.failed",
                session_id=session_id,
                error=str(e),
            )
            error_state = AlertCorrelationState(
                tenant_id=tenant_id,
                time_window_minutes=time_window_minutes,
                error=str(e),
                current_stage="failed",  # type: ignore[arg-type]
            )
            self._results[session_id] = error_state
            return error_state

    def get_result(self, session_id: str) -> AlertCorrelationState | None:
        """Retrieve a stored correlation result by session ID."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all correlation run summaries."""
        return [
            {
                "session_id": sid,
                "tenant_id": state.tenant_id,
                "total_alerts": state.total_alerts_ingested,
                "clusters": len(state.clusters),
                "incidents": len(state.incidents),
                "noise_reduction_ratio": state.noise_reduction_ratio,
                "current_stage": state.current_stage,
                "error": state.error,
            }
            for sid, state in self._results.items()
        ]
