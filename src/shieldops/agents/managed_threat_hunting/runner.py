"""Managed Threat Hunting Agent runner — entry point."""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.managed_threat_hunting.graph import (
    create_managed_threat_hunting_graph,
)
from shieldops.agents.managed_threat_hunting.models import (
    ManagedThreatHuntingState,
)
from shieldops.agents.managed_threat_hunting.nodes import (
    set_toolkit,
)
from shieldops.agents.managed_threat_hunting.tools import (
    ManagedThreatHuntingToolkit,
)

logger = structlog.get_logger()


class ManagedThreatHuntingRunner:
    """Runner for the Managed Threat Hunting Agent."""

    def __init__(
        self,
        mitre_mapper: Any | None = None,
        threat_intel: Any | None = None,
        telemetry_collector: Any | None = None,
        hunt_engine: Any | None = None,
        finding_analyzer: Any | None = None,
        escalation_service: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ManagedThreatHuntingToolkit(
            mitre_mapper=mitre_mapper,
            threat_intel=threat_intel,
            telemetry_collector=telemetry_collector,
            hunt_engine=hunt_engine,
            finding_analyzer=finding_analyzer,
            escalation_service=escalation_service,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_managed_threat_hunting_graph()
        self._app = graph.compile()
        self._results: dict[str, ManagedThreatHuntingState] = {}
        logger.info("managed_threat_hunting_runner.initialized")

    async def hunt(
        self,
        tenant_id: str,
        vendor_sources: list[str] | None = None,
        hunt_scope: dict[str, Any] | None = None,
    ) -> ManagedThreatHuntingState:
        """Run a managed threat hunting campaign."""
        campaign_id = f"mth-{uuid4().hex[:12]}"
        sources = vendor_sources or [
            "crowdstrike",
            "defender",
            "splunk",
        ]
        scope = hunt_scope or {}

        initial_state = ManagedThreatHuntingState(
            tenant_id=tenant_id,
            hunt_campaign_id=campaign_id,
            hunt_scope=scope,
            vendor_sources=sources,
        )

        logger.info(
            "managed_threat_hunting.starting",
            campaign_id=campaign_id,
            tenant_id=tenant_id,
            vendor_count=len(sources),
        )

        try:
            final_dict = await self._app.ainvoke(
                initial_state.model_dump(),
                config={
                    "metadata": {
                        "session_id": campaign_id,
                        "agent": ("managed_threat_hunting"),
                    },
                },
            )
            final = ManagedThreatHuntingState.model_validate(final_dict)
            self._results[campaign_id] = final

            logger.info(
                "managed_threat_hunting.completed",
                campaign_id=campaign_id,
                threats_found=final.threats_found,
                escalations=len(final.escalations),
                hunts_per_day=final.hunts_per_day,
                coverage_pct=final.coverage_pct,
                duration_ms=(final.session_duration_ms),
            )
            return final

        except Exception as e:
            logger.error(
                "managed_threat_hunting.failed",
                campaign_id=campaign_id,
                error=str(e),
            )
            error_state = ManagedThreatHuntingState(
                tenant_id=tenant_id,
                hunt_campaign_id=campaign_id,
                error=str(e),
                current_step="failed",
            )
            self._results[campaign_id] = error_state
            return error_state

    def get_result(self, campaign_id: str) -> ManagedThreatHuntingState | None:
        """Get result for a specific campaign."""
        return self._results.get(campaign_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all campaign results."""
        return [
            {
                "campaign_id": cid,
                "tenant_id": state.tenant_id,
                "threats_found": state.threats_found,
                "escalations": len(state.escalations),
                "hunts_per_day": state.hunts_per_day,
                "coverage_pct": state.coverage_pct,
                "current_step": state.current_step,
                "error": state.error,
            }
            for cid, state in self._results.items()
        ]
