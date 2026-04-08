"""Threat Attribution Agent runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.threat_attribution.graph import (
    create_threat_attribution_graph,
)
from shieldops.agents.threat_attribution.models import (
    ThreatAttributionState,
)
from shieldops.agents.threat_attribution.nodes import (
    set_toolkit,
)
from shieldops.agents.threat_attribution.tools import (
    ThreatAttributionToolkit,
)
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class ThreatAttributionRunner:
    """Runner for the Threat Attribution Agent."""

    def __init__(
        self,
        threat_intel_db: Any | None = None,
        ioc_service: Any | None = None,
        mitre_service: Any | None = None,
    ) -> None:
        self._toolkit = ThreatAttributionToolkit(
            threat_intel_db=threat_intel_db,
            ioc_service=ioc_service,
            mitre_service=mitre_service,
        )
        set_toolkit(self._toolkit)
        graph = create_threat_attribution_graph()
        self._app = graph.compile()
        self._results: dict[str, ThreatAttributionState] = {}
        logger.info("threat_attribution_runner.initialized")

    @enforced("threat_attribution")
    async def execute(
        self,
        tenant_id: str,
        incident_id: str,
    ) -> ThreatAttributionState:
        """Run the threat attribution workflow.

        Args:
            tenant_id: Tenant identifier for multi-tenant
                isolation.
            incident_id: The incident to attribute.

        Returns:
            Final ``ThreatAttributionState`` with actor
            profile, TTP mappings, and confidence assessment.
        """
        request_id = f"ta-{uuid4().hex[:12]}"

        initial_state = ThreatAttributionState(
            request_id=request_id,
            tenant_id=tenant_id,
            incident_id=incident_id,
        )

        logger.info(
            "threat_attribution_runner.starting",
            request_id=request_id,
            tenant_id=tenant_id,
            incident_id=incident_id,
        )

        try:
            final_dict = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": request_id,
                        "agent": "threat_attribution",
                        "tenant_id": tenant_id,
                    },
                },
            )
            final_state = ThreatAttributionState.model_validate(
                final_dict,
            )
            self._results[request_id] = final_state

            logger.info(
                "threat_attribution_runner.completed",
                request_id=request_id,
                actor=final_state.actor_profile.name,
                confidence=final_state.confidence.value,
                ttp_count=len(final_state.ttp_mappings),
            )
            return final_state

        except Exception as e:
            logger.error(
                "threat_attribution_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = ThreatAttributionState(
                request_id=request_id,
                tenant_id=tenant_id,
                incident_id=incident_id,
                error=str(e),
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> ThreatAttributionState | None:
        """Retrieve a previous result by request ID."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all attribution results with summary info."""
        return [
            {
                "request_id": rid,
                "tenant_id": s.tenant_id,
                "incident_id": s.incident_id,
                "actor": s.actor_profile.name,
                "confidence": s.confidence.value,
                "ttp_count": len(s.ttp_mappings),
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
