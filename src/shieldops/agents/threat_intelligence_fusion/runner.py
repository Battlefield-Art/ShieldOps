"""Threat Intelligence Fusion runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.threat_intelligence_fusion.graph import (
    create_threat_intelligence_fusion_graph,
)
from shieldops.agents.threat_intelligence_fusion.models import (
    ThreatIntelligenceFusionState,
)
from shieldops.agents.threat_intelligence_fusion.nodes import (
    set_toolkit,
)
from shieldops.agents.threat_intelligence_fusion.tools import (
    ThreatIntelligenceFusionToolkit,
)

logger = structlog.get_logger()


class ThreatIntelligenceFusionRunner:
    """Runner for the Threat Intelligence Fusion Agent."""

    def __init__(
        self,
        feed_client: Any | None = None,
        stix_parser: Any | None = None,
        enrichment_service: Any | None = None,
        scoring_engine: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ThreatIntelligenceFusionToolkit(
            feed_client=feed_client,
            stix_parser=stix_parser,
            enrichment_service=enrichment_service,
            scoring_engine=scoring_engine,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_threat_intelligence_fusion_graph()
        self._app = graph.compile()
        self._results: dict[str, ThreatIntelligenceFusionState] = {}
        logger.info("tif_runner.initialized")

    async def scan(
        self,
        request_id: str,
        tenant_id: str = "",
        fusion_config: dict[str, Any] | None = None,
    ) -> ThreatIntelligenceFusionState:
        """Run threat intelligence fusion workflow."""
        sid = f"tif-{uuid4().hex[:12]}"
        initial = ThreatIntelligenceFusionState(
            request_id=request_id,
            tenant_id=tenant_id,
            fusion_config=fusion_config or {},
        )

        logger.info(
            "tif_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "threat_intelligence_fusion",
                    },
                },
            )
            final = ThreatIntelligenceFusionState.model_validate(
                result,
            )
            self._results[sid] = final

            logger.info(
                "tif_runner.completed",
                session_id=sid,
                feeds=len(final.collected_feeds),
                unique_iocs=final.unique_ioc_count,
                correlations=len(final.correlations),
                campaigns=final.campaign_count,
                critical=final.critical_threat_count,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "tif_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err_state = ThreatIntelligenceFusionState(
                request_id=request_id,
                tenant_id=tenant_id,
                fusion_config=fusion_config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[sid] = err_state
            return err_state

    def get_result(
        self,
        session_id: str,
    ) -> ThreatIntelligenceFusionState | None:
        """Retrieve a previous fusion result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all fusion results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "tenant_id": s.tenant_id,
                "total_feeds": len(s.collected_feeds),
                "unique_iocs": s.unique_ioc_count,
                "correlations": len(s.correlations),
                "campaigns": s.campaign_count,
                "critical_threats": (s.critical_threat_count),
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]
