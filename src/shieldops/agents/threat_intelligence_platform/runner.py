"""TIP Agent runner — entry point for intelligence cycles.

Takes source configuration, constructs the LangGraph,
runs end-to-end, and returns completed TIP state.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.threat_intelligence_platform.graph import (
    create_threat_intelligence_platform_graph,
)
from shieldops.agents.threat_intelligence_platform.models import (
    IntelSource,
    ThreatIntelligencePlatformState,
)
from shieldops.agents.threat_intelligence_platform.nodes import (
    set_toolkit,
)
from shieldops.agents.threat_intelligence_platform.tools import (
    ThreatIntelligencePlatformToolkit,
)

logger = structlog.get_logger()


class ThreatIntelligencePlatformRunner:
    """Runs threat intelligence platform workflows.

    Usage:
        runner = ThreatIntelligencePlatformRunner(
            feed_clients={
                "osint": osint_client,
                "dark_web": dark_web_client,
            },
            siem_client=siem,
        )
        result = await runner.collect(
            tenant_id="t-123",
            sources=[
                IntelSource.OSINT,
                IntelSource.DARK_WEB,
            ],
        )
    """

    def __init__(
        self,
        feed_clients: dict[str, Any] | None = None,
        siem_client: Any = None,
        dark_web_client: Any = None,
        stix_client: Any = None,
        notification_client: Any = None,
        environment_profile: (dict[str, Any] | None) = None,
    ) -> None:
        self._toolkit = ThreatIntelligencePlatformToolkit(
            feed_clients=feed_clients or {},
            siem_client=siem_client,
            dark_web_client=dark_web_client,
            stix_client=stix_client,
            notification_client=(notification_client),
            environment_profile=(environment_profile or {}),
        )
        # Configure module-level toolkit for nodes
        set_toolkit(self._toolkit)

        # Build compiled graph
        graph = create_threat_intelligence_platform_graph()
        self._app = graph.compile()

        # In-memory store of completed runs
        self._results: dict[str, ThreatIntelligencePlatformState] = {}

    async def collect(
        self,
        tenant_id: str = "",
        sources: list[IntelSource] | None = None,
    ) -> ThreatIntelligencePlatformState:
        """Run a full threat intelligence cycle.

        Args:
            tenant_id: Tenant ID for scoped queries.
            sources: Intelligence sources to query.
                Defaults to OSINT + INTERNAL_TELEMETRY.

        Returns:
            Completed ThreatIntelligencePlatformState.
        """
        request_id = f"tip-{uuid4().hex[:12]}"

        logger.info(
            "tip_started",
            request_id=request_id,
            tenant_id=tenant_id,
            sources=([s.value for s in sources] if sources else "default"),
        )

        initial_state = ThreatIntelligencePlatformState(
            request_id=request_id,
            tenant_id=tenant_id,
            sources=sources or [],
        )

        try:
            final_dict = await self._app.ainvoke(
                initial_state.model_dump(),
                config={
                    "metadata": {
                        "request_id": request_id,
                        "tenant_id": tenant_id,
                    },
                },
            )

            final_state = ThreatIntelligencePlatformState.model_validate(final_dict)

            # Calculate total duration
            if final_state.session_start:
                elapsed = datetime.now(UTC) - final_state.session_start
                final_state.session_duration_ms = int(elapsed.total_seconds() * 1000)

            logger.info(
                "tip_completed",
                request_id=request_id,
                items=len(final_state.items_collected),
                indicators=len(final_state.indicators_normalized),
                correlations=len(final_state.correlations),
                actionable=(final_state.actionable_intel_count),
                advisories=len(final_state.advisories_generated),
                duration_ms=(final_state.session_duration_ms),
            )

            self._results[request_id] = final_state
            return final_state

        except Exception as e:
            logger.error(
                "tip_failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = ThreatIntelligencePlatformState(
                request_id=request_id,
                tenant_id=tenant_id,
                sources=sources or [],
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(self, request_id: str) -> ThreatIntelligencePlatformState | None:
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
                "items": len(st.items_collected),
                "indicators": len(st.indicators_normalized),
                "actionable": (st.actionable_intel_count),
                "advisories": len(st.advisories_generated),
                "high_priority": (st.high_priority_count),
                "confidence": st.confidence_score,
                "duration_ms": (st.session_duration_ms),
                "error": st.error,
            }
            for rid, st in self._results.items()
        ]
