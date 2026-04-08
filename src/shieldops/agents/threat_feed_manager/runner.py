"""Threat Feed Manager runner — entry point for feed management workflows."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.threat_feed_manager.graph import (
    create_threat_feed_manager_graph,
)
from shieldops.agents.threat_feed_manager.models import (
    ThreatFeedManagerState,
)
from shieldops.agents.threat_feed_manager.nodes import set_toolkit
from shieldops.agents.threat_feed_manager.tools import (
    ThreatFeedManagerToolkit,
)
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class ThreatFeedManagerRunner:
    """Runner for the Threat Feed Manager Agent."""

    def __init__(
        self,
        feed_client: Any | None = None,
        enrichment_client: Any | None = None,
    ) -> None:
        self._toolkit = ThreatFeedManagerToolkit(
            feed_client=feed_client,
            enrichment_client=enrichment_client,
        )
        set_toolkit(self._toolkit)
        graph = create_threat_feed_manager_graph()
        self._app = graph.compile()
        self._results: dict[str, ThreatFeedManagerState] = {}
        logger.info("threat_feed_manager_runner.initialized")

    @enforced("threat_feed_manager")
    async def execute(
        self,
        tenant_id: str,
    ) -> ThreatFeedManagerState:
        """Run the threat feed manager workflow.

        Args:
            tenant_id: Tenant identifier for multi-tenant isolation.

        Returns:
            Final ThreatFeedManagerState with feeds, IOCs, scores,
            and stats.
        """
        request_id = f"tfm-{uuid4().hex[:12]}"

        initial_state = ThreatFeedManagerState(
            request_id=request_id,
            tenant_id=tenant_id,
        )

        logger.info(
            "threat_feed_manager_runner.starting",
            request_id=request_id,
            tenant_id=tenant_id,
        )

        try:
            final_state_dict = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": request_id,
                        "agent": "threat_feed_manager",
                        "tenant_id": tenant_id,
                    },
                },
            )
            final_state = ThreatFeedManagerState.model_validate(final_state_dict)
            self._results[request_id] = final_state

            logger.info(
                "threat_feed_manager_runner.completed",
                request_id=request_id,
                feeds=len(final_state.feeds),
                iocs=len(final_state.normalized_iocs),
                scores=len(final_state.feed_scores),
                duration_ms=final_state.session_duration_ms,
            )
            return final_state

        except Exception as e:
            logger.error(
                "threat_feed_manager_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = ThreatFeedManagerState(
                request_id=request_id,
                tenant_id=tenant_id,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(self, request_id: str) -> ThreatFeedManagerState | None:
        """Retrieve a previous result by request ID."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all execution results with summary info."""
        return [
            {
                "request_id": rid,
                "tenant_id": state.tenant_id,
                "feeds": len(state.feeds),
                "iocs": len(state.normalized_iocs),
                "scores": len(state.feed_scores),
                "current_step": state.current_step,
                "duration_ms": state.session_duration_ms,
                "error": state.error,
            }
            for rid, state in self._results.items()
        ]
