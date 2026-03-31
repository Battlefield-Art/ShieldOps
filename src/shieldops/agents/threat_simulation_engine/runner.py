"""Threat Simulation Engine Agent runner — entry point
for executing adversary simulation campaigns."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.threat_simulation_engine.graph import (
    create_threat_simulation_engine_graph,
)
from shieldops.agents.threat_simulation_engine.models import (
    SimulationType,
    ThreatSimulationEngineState,
)
from shieldops.agents.threat_simulation_engine.nodes import (
    set_toolkit,
)
from shieldops.agents.threat_simulation_engine.tools import (
    ThreatSimulationEngineToolkit,
)

logger = structlog.get_logger()


class ThreatSimulationEngineRunner:
    """Runner for the Threat Simulation Engine Agent."""

    def __init__(
        self,
        mitre_mapper: Any | None = None,
        bas_platform: Any | None = None,
        detection_pipeline: Any | None = None,
        alert_store: Any | None = None,
        gap_analyzer: Any | None = None,
        metrics_store: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ThreatSimulationEngineToolkit(
            mitre_mapper=mitre_mapper,
            bas_platform=bas_platform,
            detection_pipeline=detection_pipeline,
            alert_store=alert_store,
            gap_analyzer=gap_analyzer,
            metrics_store=metrics_store,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_threat_simulation_engine_graph()
        self._app = graph.compile()
        self._results: dict[str, ThreatSimulationEngineState] = {}
        logger.info("tse_runner.initialized")

    async def simulate(
        self,
        campaign_name: str,
        simulation_type: str = "purple_team",
        target_techniques: list[str] | None = None,
        scope: dict[str, Any] | None = None,
        tenant_id: str = "",
    ) -> ThreatSimulationEngineState:
        """Run an adversary simulation campaign."""
        request_id = f"tse-{uuid4().hex[:12]}"

        initial_state = ThreatSimulationEngineState(
            request_id=request_id,
            tenant_id=tenant_id,
            campaign_name=campaign_name,
            simulation_type=SimulationType(simulation_type),
            target_techniques=target_techniques or [],
            scope=scope or {},
        )

        logger.info(
            "tse_runner.starting",
            request_id=request_id,
            campaign=campaign_name,
            simulation_type=simulation_type,
            techniques=len(initial_state.target_techniques),
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": ("threat_simulation_engine"),
                    },
                },
            )
            final = ThreatSimulationEngineState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "tse_runner.completed",
                request_id=request_id,
                total_attacks=final.total_attacks,
                detected=final.detected_count,
                gaps=final.gap_count,
                detection_rate=final.detection_rate,
                overall_score=final.overall_score,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "tse_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = ThreatSimulationEngineState(
                request_id=request_id,
                tenant_id=tenant_id,
                campaign_name=campaign_name,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> ThreatSimulationEngineState | None:
        """Retrieve a cached campaign result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all campaign results as summaries."""
        return [
            {
                "request_id": rid,
                "campaign": s.campaign_name,
                "simulation_type": s.simulation_type.value,
                "total_attacks": s.total_attacks,
                "detected": s.detected_count,
                "gaps": s.gap_count,
                "detection_rate": s.detection_rate,
                "overall_score": s.overall_score,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
