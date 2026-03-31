"""Security Event Enricher Agent runner — entry point
for real-time event enrichment pipelines."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.security_event_enricher.graph import (
    create_security_event_enricher_graph,
)
from shieldops.agents.security_event_enricher.models import (
    EventSource,
    SecurityEventEnricherState,
)
from shieldops.agents.security_event_enricher.nodes import (
    set_toolkit,
)
from shieldops.agents.security_event_enricher.tools import (
    SecurityEventEnricherToolkit,
)

logger = structlog.get_logger()


class SecurityEventEnricherRunner:
    """Runner for the Security Event Enricher Agent."""

    def __init__(
        self,
        siem_client: Any | None = None,
        threat_intel: Any | None = None,
        asset_inventory: Any | None = None,
        geo_service: Any | None = None,
        routing_engine: Any | None = None,
        metrics_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecurityEventEnricherToolkit(
            siem_client=siem_client,
            threat_intel=threat_intel,
            asset_inventory=asset_inventory,
            geo_service=geo_service,
            routing_engine=routing_engine,
            metrics_store=metrics_store,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_security_event_enricher_graph()
        self._app = graph.compile()
        self._results: dict[str, SecurityEventEnricherState] = {}
        logger.info("see_runner.initialized")

    async def enrich(
        self,
        event_sources: list[str] | None = None,
        scope: dict[str, Any] | None = None,
        batch_size: int = 100,
        tenant_id: str = "",
    ) -> SecurityEventEnricherState:
        """Run a security event enrichment pipeline."""
        request_id = f"see-{uuid4().hex[:12]}"

        sources = [
            EventSource(s) for s in (event_sources or []) if s in EventSource.__members__.values()
        ]

        initial_state = SecurityEventEnricherState(
            request_id=request_id,
            tenant_id=tenant_id,
            event_sources=sources,
            scope=scope or {},
            batch_size=batch_size,
        )

        logger.info(
            "see_runner.starting",
            request_id=request_id,
            sources=len(sources),
            batch_size=batch_size,
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "security_event_enricher",
                    },
                },
            )
            final = SecurityEventEnricherState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "see_runner.completed",
                request_id=request_id,
                total=final.total_events,
                enriched=final.enriched_count,
                critical=final.critical_count,
                routed=final.routed_count,
            )
            return final

        except Exception as e:
            logger.error(
                "see_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = SecurityEventEnricherState(
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
    ) -> SecurityEventEnricherState | None:
        """Retrieve a cached enrichment result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all enrichment results as summaries."""
        return [
            {
                "request_id": rid,
                "total_events": s.total_events,
                "enriched_count": s.enriched_count,
                "critical_count": s.critical_count,
                "routed_count": s.routed_count,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
