"""Threat Hunt Orchestrator Agent runner — entry point
for executing proactive hunt campaigns."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.threat_hunt_orchestrator.graph import (
    create_threat_hunt_orchestrator_graph,
)
from shieldops.agents.threat_hunt_orchestrator.models import (
    HuntType,
    TacticCategory,
    ThreatHuntOrchestratorState,
)
from shieldops.agents.threat_hunt_orchestrator.nodes import (
    set_toolkit,
)
from shieldops.agents.threat_hunt_orchestrator.tools import (
    ThreatHuntOrchestratorToolkit,
)

logger = structlog.get_logger()


class ThreatHuntOrchestratorRunner:
    """Runner for the Threat Hunt Orchestrator Agent."""

    def __init__(
        self,
        mitre_mapper: Any | None = None,
        threat_intel: Any | None = None,
        data_collector: Any | None = None,
        evidence_store: Any | None = None,
        finding_validator: Any | None = None,
        hunt_metrics: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ThreatHuntOrchestratorToolkit(
            mitre_mapper=mitre_mapper,
            threat_intel=threat_intel,
            data_collector=data_collector,
            evidence_store=evidence_store,
            finding_validator=finding_validator,
            hunt_metrics=hunt_metrics,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_threat_hunt_orchestrator_graph()
        self._app = graph.compile()
        self._results: dict[str, ThreatHuntOrchestratorState] = {}
        logger.info("tho_runner.initialized")

    async def orchestrate(
        self,
        campaign_name: str,
        hunt_type: str = "hypothesis_driven",
        target_tactics: list[str] | None = None,
        scope: dict[str, Any] | None = None,
        data_sources: list[str] | None = None,
        tenant_id: str = "",
    ) -> ThreatHuntOrchestratorState:
        """Run a proactive threat hunting campaign."""
        request_id = f"tho-{uuid4().hex[:12]}"

        tactics = [
            TacticCategory(t)
            for t in (target_tactics or [])
            if t in TacticCategory.__members__.values()
        ]

        initial_state = ThreatHuntOrchestratorState(
            request_id=request_id,
            tenant_id=tenant_id,
            campaign_name=campaign_name,
            hunt_type=HuntType(hunt_type),
            target_tactics=tactics,
            scope=scope or {},
            data_sources=data_sources or [],
        )

        logger.info(
            "tho_runner.starting",
            request_id=request_id,
            campaign=campaign_name,
            hunt_type=hunt_type,
            tactics=len(tactics),
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": ("threat_hunt_orchestrator"),
                    },
                },
            )
            final = ThreatHuntOrchestratorState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "tho_runner.completed",
                request_id=request_id,
                threat_found=final.threat_found,
                total_findings=final.total_findings,
                validated=final.validated_findings,
                effectiveness=final.effectiveness_score,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "tho_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = ThreatHuntOrchestratorState(
                request_id=request_id,
                tenant_id=tenant_id,
                campaign_name=campaign_name,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(self, request_id: str) -> ThreatHuntOrchestratorState | None:
        """Retrieve a cached campaign result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all campaign results as summaries."""
        return [
            {
                "request_id": rid,
                "campaign": s.campaign_name,
                "hunt_type": s.hunt_type.value,
                "threat_found": s.threat_found,
                "total_findings": s.total_findings,
                "validated": s.validated_findings,
                "effectiveness": s.effectiveness_score,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
