"""Intelligence Fusion Center Agent runner — entry point for fusion cycles.

Takes source configuration, constructs the LangGraph,
runs end-to-end, and returns completed IFC state.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.intelligence_fusion_center.graph import (
    create_intelligence_fusion_center_graph,
)
from shieldops.agents.intelligence_fusion_center.models import (
    IntelligenceFusionCenterState,
)
from shieldops.agents.intelligence_fusion_center.nodes import (
    set_toolkit,
)
from shieldops.agents.intelligence_fusion_center.tools import (
    IntelligenceFusionCenterToolkit,
)

logger = structlog.get_logger()


class IntelligenceFusionCenterRunner:
    """Runs intelligence fusion center workflows.

    Usage:
        runner = IntelligenceFusionCenterRunner(
            feed_clients={
                "osint": osint_client,
                "dark_web": dark_web_client,
            },
            siem_client=siem,
        )
        result = await runner.run(
            tenant_id="t-123",
        )
    """

    def __init__(
        self,
        feed_clients: dict[str, Any] | None = None,
        siem_client: Any = None,
        correlation_client: Any = None,
        notification_client: Any = None,
        environment_profile: dict[str, Any] | None = None,
    ) -> None:
        self._toolkit = IntelligenceFusionCenterToolkit(
            feed_clients=feed_clients or {},
            siem_client=siem_client,
            correlation_client=correlation_client,
            notification_client=notification_client,
            environment_profile=environment_profile or {},
        )
        # Configure module-level toolkit for nodes
        set_toolkit(self._toolkit)

        # Build compiled graph
        graph = create_intelligence_fusion_center_graph()
        self._app = graph.compile()

        # In-memory store of completed runs
        self._results: dict[str, IntelligenceFusionCenterState] = {}

    async def run(
        self,
        tenant_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> IntelligenceFusionCenterState:
        """Run a full intelligence fusion cycle.

        Args:
            tenant_id: Tenant ID for scoped queries.
            config: Optional configuration overrides.

        Returns:
            Completed IntelligenceFusionCenterState.
        """
        request_id = f"ifc-{uuid4().hex[:12]}"

        logger.info(
            "ifc_started",
            request_id=request_id,
            tenant_id=tenant_id,
        )

        initial_state = IntelligenceFusionCenterState(
            request_id=request_id,
            tenant_id=tenant_id,
            config=config or {},
        )

        try:
            final_dict = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "tenant_id": tenant_id,
                    },
                },
            )

            final_state = IntelligenceFusionCenterState.model_validate(final_dict)

            # Calculate total duration
            if final_state.session_start:
                elapsed = datetime.now(UTC) - final_state.session_start
                final_state.session_duration_ms = int(elapsed.total_seconds() * 1000)

            logger.info(
                "ifc_completed",
                request_id=request_id,
                feeds=len(final_state.feeds_collected),
                correlated=len(final_state.correlated_threats),
                fused=len(final_state.fusion_results),
                actionable=final_state.actionable_count,
                reports=len(final_state.assessment_output),
                duration_ms=final_state.session_duration_ms,
            )

            self._results[request_id] = final_state
            return final_state

        except Exception as e:
            logger.error(
                "ifc_failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = IntelligenceFusionCenterState(
                request_id=request_id,
                tenant_id=tenant_id,
                config=config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(self, request_id: str) -> IntelligenceFusionCenterState | None:
        """Retrieve a completed run by request ID."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all runs with summary info."""
        return [
            {
                "request_id": rid,
                "tenant_id": st.tenant_id,
                "stage": st.stage,
                "status": st.current_step,
                "feeds": len(st.feeds_collected),
                "correlated": len(st.correlated_threats),
                "fused": len(st.fusion_results),
                "actionable": st.actionable_count,
                "reports": len(st.assessment_output),
                "high_priority": st.high_priority_count,
                "confidence": st.confidence_score,
                "duration_ms": st.session_duration_ms,
                "error": st.error,
            }
            for rid, st in self._results.items()
        ]
