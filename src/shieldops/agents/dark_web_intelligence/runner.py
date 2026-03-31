"""Dark Web Intelligence Agent runner — entry point
for dark web monitoring and threat intelligence."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.dark_web_intelligence.graph import (
    create_dark_web_intelligence_graph,
)
from shieldops.agents.dark_web_intelligence.models import (
    DarkWebIntelligenceState,
)
from shieldops.agents.dark_web_intelligence.nodes import (
    set_toolkit,
)
from shieldops.agents.dark_web_intelligence.tools import (
    DarkWebIntelligenceToolkit,
)

logger = structlog.get_logger()


class DarkWebIntelligenceRunner:
    """Runner for the Dark Web Intelligence Agent."""

    def __init__(
        self,
        scraper: Any | None = None,
        threat_intel: Any | None = None,
        alert_service: Any | None = None,
        credibility_engine: Any | None = None,
        metrics_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = DarkWebIntelligenceToolkit(
            scraper=scraper,
            threat_intel=threat_intel,
            alert_service=alert_service,
            credibility_engine=credibility_engine,
            metrics_store=metrics_store,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_dark_web_intelligence_graph()
        self._app = graph.compile()
        self._results: dict[str, DarkWebIntelligenceState] = {}
        logger.info("dwi_runner.initialized")

    async def monitor(
        self,
        tenant_id: str = "",
        keywords: list[str] | None = None,
    ) -> DarkWebIntelligenceState:
        """Run a dark web monitoring cycle."""
        request_id = f"dwi-{uuid4().hex[:12]}"

        initial_state = DarkWebIntelligenceState(
            request_id=request_id,
            tenant_id=tenant_id,
        )

        logger.info(
            "dwi_runner.starting",
            request_id=request_id,
            tenant_id=tenant_id,
            keywords=keywords,
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "dark_web_intelligence",
                    },
                },
            )
            final = DarkWebIntelligenceState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "dwi_runner.completed",
                request_id=request_id,
                mentions=final.total_mentions,
                critical=final.critical_threats,
                alerts=final.alerts_generated,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "dwi_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = DarkWebIntelligenceState(
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
    ) -> DarkWebIntelligenceState | None:
        """Retrieve a cached monitoring result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all monitoring results as summaries."""
        return [
            {
                "request_id": rid,
                "mentions": s.total_mentions,
                "critical": s.critical_threats,
                "alerts": s.alerts_generated,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
