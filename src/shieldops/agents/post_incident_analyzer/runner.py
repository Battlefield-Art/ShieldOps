"""Post-Incident Analyzer Agent runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.post_incident_analyzer.graph import (
    create_post_incident_analyzer_graph,
)
from shieldops.agents.post_incident_analyzer.models import (
    PostIncidentAnalyzerState,
)
from shieldops.agents.post_incident_analyzer.nodes import (
    set_toolkit,
)
from shieldops.agents.post_incident_analyzer.tools import (
    PostIncidentAnalyzerToolkit,
)
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class PostIncidentAnalyzerRunner:
    """Runner for the Post-Incident Analyzer Agent."""

    def __init__(
        self,
        incident_db: Any | None = None,
        alert_service: Any | None = None,
        change_db: Any | None = None,
    ) -> None:
        self._toolkit = PostIncidentAnalyzerToolkit(
            incident_db=incident_db,
            alert_service=alert_service,
            change_db=change_db,
        )
        set_toolkit(self._toolkit)
        graph = create_post_incident_analyzer_graph()
        self._app = graph.compile()
        self._results: dict[str, PostIncidentAnalyzerState] = {}
        logger.info("post_incident_analyzer_runner.initialized")

    @enforced("post_incident_analyzer")
    async def execute(
        self,
        tenant_id: str,
        incident_id: str,
    ) -> PostIncidentAnalyzerState:
        """Run the post-incident analysis workflow.

        Args:
            tenant_id: Tenant identifier for multi-tenant isolation.
            incident_id: The incident to analyse.

        Returns:
            Final ``PostIncidentAnalyzerState`` with root cause,
            impact, action items, and reasoning chain.
        """
        request_id = f"pia-{uuid4().hex[:12]}"

        initial_state = PostIncidentAnalyzerState(
            request_id=request_id,
            tenant_id=tenant_id,
            incident_id=incident_id,
        )

        logger.info(
            "post_incident_analyzer_runner.starting",
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
                        "agent": "post_incident_analyzer",
                        "tenant_id": tenant_id,
                    },
                },
            )
            final_state = PostIncidentAnalyzerState.model_validate(final_dict)
            self._results[request_id] = final_state

            logger.info(
                "post_incident_analyzer_runner.completed",
                request_id=request_id,
                root_cause=final_state.root_cause.value,
                impact=final_state.impact.value,
                action_items=len(final_state.action_items),
                timeline_events=len(final_state.timeline_events),
            )
            return final_state

        except Exception as e:
            logger.error(
                "post_incident_analyzer_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = PostIncidentAnalyzerState(
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
    ) -> PostIncidentAnalyzerState | None:
        """Retrieve a previous analysis result by request ID."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all analysis results with summary info."""
        return [
            {
                "request_id": rid,
                "tenant_id": s.tenant_id,
                "incident_id": s.incident_id,
                "root_cause": s.root_cause.value,
                "impact": s.impact.value,
                "action_items": len(s.action_items),
                "timeline_events": len(s.timeline_events),
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
