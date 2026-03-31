"""Threat Feed Orchestrator Agent runner — entry point
for multi-source threat intelligence orchestration."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.threat_feed_orchestrator.graph import (
    create_threat_feed_orchestrator_graph,
)
from shieldops.agents.threat_feed_orchestrator.models import (
    ThreatFeedOrchestratorState,
)
from shieldops.agents.threat_feed_orchestrator.nodes import (
    set_toolkit,
)
from shieldops.agents.threat_feed_orchestrator.tools import (
    ThreatFeedOrchestratorToolkit,
)

logger = structlog.get_logger()


class ThreatFeedOrchestratorRunner:
    """Runner for the Threat Feed Orchestrator Agent."""

    def __init__(
        self,
        feed_connector: Any | None = None,
        normalizer: Any | None = None,
        dedup_engine: Any | None = None,
        enrichment_service: Any | None = None,
        distribution_engine: Any | None = None,
        metrics_collector: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ThreatFeedOrchestratorToolkit(
            feed_connector=feed_connector,
            normalizer=normalizer,
            dedup_engine=dedup_engine,
            enrichment_service=enrichment_service,
            distribution_engine=distribution_engine,
            metrics_collector=metrics_collector,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_threat_feed_orchestrator_graph()
        self._app = graph.compile()
        self._results: dict[str, ThreatFeedOrchestratorState] = {}
        logger.info("tfo_runner.initialized")

    async def orchestrate(
        self,
        feed_urls: list[str] | None = None,
        feed_configs: list[dict[str, Any]] | None = None,
        consumer_configs: list[dict[str, Any]] | None = None,
        enrichment_sources: list[str] | None = None,
        tenant_id: str = "",
    ) -> ThreatFeedOrchestratorState:
        """Run a threat feed orchestration pipeline."""
        request_id = f"tfo-{uuid4().hex[:12]}"

        initial_state = ThreatFeedOrchestratorState(
            request_id=request_id,
            tenant_id=tenant_id,
            feed_urls=feed_urls or [],
            feed_configs=feed_configs or [],
            consumer_configs=consumer_configs or [],
            enrichment_sources=enrichment_sources or [],
        )

        logger.info(
            "tfo_runner.starting",
            request_id=request_id,
            feed_count=len(feed_urls or []),
            consumer_count=len(consumer_configs or []),
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "threat_feed_orchestrator",
                    },
                },
            )
            final = ThreatFeedOrchestratorState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "tfo_runner.completed",
                request_id=request_id,
                total=final.total_indicators,
                unique=final.unique_indicators,
                enriched=final.enriched_count,
                distributed=final.distributed_count,
                dedup_ratio=final.dedup_ratio,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "tfo_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = ThreatFeedOrchestratorState(
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
    ) -> ThreatFeedOrchestratorState | None:
        """Retrieve a cached pipeline result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all pipeline results as summaries."""
        return [
            {
                "request_id": rid,
                "total": s.total_indicators,
                "unique": s.unique_indicators,
                "enriched": s.enriched_count,
                "distributed": s.distributed_count,
                "dedup_ratio": s.dedup_ratio,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
