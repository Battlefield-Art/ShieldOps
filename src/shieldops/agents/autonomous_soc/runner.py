"""Autonomous SOC Agent runner -- entry point for operations."""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.autonomous_soc.graph import (
    create_autonomous_soc_graph,
)
from shieldops.agents.autonomous_soc.models import (
    AutonomousSOCState,
)
from shieldops.agents.autonomous_soc.nodes import (
    set_toolkit,
)
from shieldops.agents.autonomous_soc.tools import (
    AutonomousSOCToolkit,
)

logger = structlog.get_logger()


class AutonomousSOCRunner:
    """Runner for the Autonomous SOC Agent."""

    def __init__(
        self,
        splunk_client: Any | None = None,
        elastic_client: Any | None = None,
        sentinel_client: Any | None = None,
        threat_intel: Any | None = None,
        policy_engine: Any | None = None,
        soar_engine: Any | None = None,
        metrics_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = AutonomousSOCToolkit(
            splunk_client=splunk_client,
            elastic_client=elastic_client,
            sentinel_client=sentinel_client,
            threat_intel=threat_intel,
            policy_engine=policy_engine,
            soar_engine=soar_engine,
            metrics_store=metrics_store,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_autonomous_soc_graph()
        self._app = graph.compile()
        self._results: dict[str, AutonomousSOCState] = {}
        logger.info(
            "autonomous_soc_runner.initialized",
        )

    async def operate(
        self,
        tenant_id: str,
        siem_sources: list[str] | None = None,
        time_range_minutes: int = 60,
        automation_config: (dict[str, Any] | None) = None,
    ) -> AutonomousSOCState:
        """Run the autonomous SOC cycle.

        This is the primary entry point. Ingests
        events from configured SIEMs, detects
        anomalies, correlates incidents, auto-triages,
        orchestrates response, and measures outcomes.
        """
        session_id = f"asoc-{uuid4().hex[:12]}"
        initial_state = AutonomousSOCState(
            tenant_id=tenant_id,
            siem_sources=siem_sources or ["splunk", "elastic", "sentinel"],
            time_range_minutes=time_range_minutes,
            automation_config=(automation_config or {}),
            session_id=session_id,
        )

        logger.info(
            "autonomous_soc_runner.operate",
            session_id=session_id,
            tenant_id=tenant_id,
            siem_sources=(initial_state.siem_sources),
            time_range=time_range_minutes,
        )

        return await self._run(
            session_id,
            initial_state,
        )

    async def process_alert(
        self,
        tenant_id: str,
        siem_source: str,
        alert_data: dict[str, Any],
    ) -> AutonomousSOCState:
        """Process a single incoming alert."""
        session_id = f"asoc-{uuid4().hex[:12]}"
        initial_state = AutonomousSOCState(
            tenant_id=tenant_id,
            siem_sources=[siem_source],
            time_range_minutes=5,
            session_id=session_id,
        )

        logger.info(
            "autonomous_soc_runner.process_alert",
            session_id=session_id,
            siem=siem_source,
        )

        return await self._run(
            session_id,
            initial_state,
        )

    async def get_soc_metrics(
        self,
    ) -> dict[str, Any]:
        """Get aggregated SOC performance metrics."""
        total_events = 0
        total_anomalies = 0
        total_incidents = 0
        total_auto = 0
        mttd_values: list[float] = []
        mttr_values: list[float] = []

        for state in self._results.values():
            total_events += state.events_processed
            total_anomalies += state.anomalies_detected
            total_incidents += state.incidents_created
            total_auto += state.auto_triaged
            if state.mean_time_to_detect_seconds > 0:
                mttd_values.append(
                    state.mean_time_to_detect_seconds,
                )
            if state.mean_time_to_respond_seconds > 0:
                mttr_values.append(
                    state.mean_time_to_respond_seconds,
                )

        import statistics

        return {
            "total_sessions": len(self._results),
            "total_events_processed": total_events,
            "total_anomalies_detected": (total_anomalies),
            "total_incidents_created": (total_incidents),
            "total_auto_triaged": total_auto,
            "avg_mttd_seconds": (statistics.mean(mttd_values) if mttd_values else 0.0),
            "avg_mttr_seconds": (statistics.mean(mttr_values) if mttr_values else 0.0),
            "automation_rate": (total_auto / total_incidents if total_incidents > 0 else 0.0),
        }

    async def get_active_incidents(
        self,
    ) -> list[dict[str, Any]]:
        """List open incidents across all sessions."""
        incidents: list[dict[str, Any]] = []
        for state in self._results.values():
            for inc in state.incidents:
                incidents.append(
                    inc.model_dump(),
                )
        return incidents

    async def _run(
        self,
        session_id: str,
        initial_state: AutonomousSOCState,
    ) -> AutonomousSOCState:
        """Execute the Autonomous SOC graph."""
        try:
            final_dict = await self._app.ainvoke(
                initial_state.model_dump(),
                config={
                    "metadata": {
                        "session_id": session_id,
                        "agent": "autonomous_soc",
                    },
                },
            )
            final_state = AutonomousSOCState.model_validate(
                final_dict,
            )
            self._results[session_id] = final_state

            logger.info(
                "autonomous_soc_runner.completed",
                session_id=session_id,
                events=final_state.events_processed,
                anomalies=(final_state.anomalies_detected),
                incidents=(final_state.incidents_created),
                auto_triaged=(final_state.auto_triaged),
                responses=(final_state.responses_orchestrated),
                duration_ms=(final_state.session_duration_ms),
            )
            return final_state

        except Exception as e:
            logger.error(
                "autonomous_soc_runner.failed",
                session_id=session_id,
                error=str(e),
            )
            error_state = AutonomousSOCState(
                tenant_id=(initial_state.tenant_id),
                siem_sources=(initial_state.siem_sources),
                session_id=session_id,
                error=str(e),
                current_stage="failed",
            )
            self._results[session_id] = error_state
            return error_state

    def get_result(
        self,
        session_id: str,
    ) -> AutonomousSOCState | None:
        return self._results.get(session_id)

    def list_results(
        self,
    ) -> list[dict[str, Any]]:
        return [
            {
                "session_id": sid,
                "tenant_id": state.tenant_id,
                "events": (state.events_processed),
                "anomalies": (state.anomalies_detected),
                "incidents": (state.incidents_created),
                "auto_triaged": (state.auto_triaged),
                "responses": (state.responses_orchestrated),
                "automation_rate": (state.automation_rate),
                "current_stage": (state.current_stage),
                "duration_ms": (state.session_duration_ms),
                "error": state.error,
            }
            for sid, state in (self._results.items())
        ]
