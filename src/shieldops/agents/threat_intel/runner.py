"""Threat Intel Agent runner — entry point for executing intelligence cycles.

Takes optional source configuration, constructs the LangGraph, runs it
end-to-end, and returns the completed threat intel state.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.threat_intel.graph import create_threat_intel_graph
from shieldops.agents.threat_intel.models import (
    IntelSource,
    ThreatIntelState,
)
from shieldops.agents.threat_intel.nodes import set_toolkit
from shieldops.agents.threat_intel.tools import ThreatIntelToolkit
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class ThreatIntelRunner:
    """Runs threat intelligence gathering workflows.

    Usage:
        runner = ThreatIntelRunner(
            feed_clients={"osint": osint_client},
            siem_client=siem,
        )
        result = await runner.run(sources=[IntelSource.OSINT])
    """

    def __init__(
        self,
        feed_clients: dict[str, Any] | None = None,
        siem_client: Any = None,
        firewall_client: Any = None,
        edr_client: Any = None,
        notification_client: Any = None,
    ) -> None:
        self._toolkit = ThreatIntelToolkit(
            feed_clients=feed_clients or {},
            siem_client=siem_client,
            firewall_client=firewall_client,
            edr_client=edr_client,
            notification_client=notification_client,
        )
        # Configure the module-level toolkit for nodes
        set_toolkit(self._toolkit)

        # Build the compiled graph
        graph = create_threat_intel_graph()
        self._app = graph.compile()

        # In-memory store of completed runs (fallback when no DB)
        self._results: dict[str, ThreatIntelState] = {}

    @enforced("threat_intel")
    async def run(
        self,
        sources: list[IntelSource] | None = None,
        distribution_channels: list[str] | None = None,
    ) -> ThreatIntelState:
        """Run a full threat intelligence cycle.

        Args:
            sources: Intelligence sources to query. Defaults to OSINT + INTERNAL.
            distribution_channels: Channels for distributing results.

        Returns:
            The completed ThreatIntelState with assessments and distribution results.
        """
        request_id = f"ti-{uuid4().hex[:12]}"

        logger.info(
            "threat_intel_started",
            request_id=request_id,
            sources=[s.value for s in sources] if sources else "default",
        )

        initial_state = ThreatIntelState(
            request_id=request_id,
            sources=sources or [],
            distribution_channels=distribution_channels or [],
        )

        try:
            final_state_dict = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                    },
                },
            )

            final_state = ThreatIntelState.model_validate(final_state_dict)

            # Calculate total duration
            if final_state.session_start:
                final_state.session_duration_ms = int(
                    (datetime.now(UTC) - final_state.session_start).total_seconds() * 1000
                )

            logger.info(
                "threat_intel_completed",
                request_id=request_id,
                indicators=len(final_state.indicators_collected),
                correlations=len(final_state.correlations),
                assessments=len(final_state.assessments),
                high_priority=final_state.high_priority_count,
                duration_ms=final_state.session_duration_ms,
            )

            self._results[request_id] = final_state
            return final_state

        except Exception as e:
            logger.error(
                "threat_intel_failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = ThreatIntelState(
                request_id=request_id,
                sources=sources or [],
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(self, request_id: str) -> ThreatIntelState | None:
        """Retrieve a completed run by request ID."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all runs with summary info."""
        return [
            {
                "request_id": rid,
                "stage": state.stage,
                "status": state.current_step,
                "indicators": len(state.indicators_collected),
                "high_priority": state.high_priority_count,
                "confidence": state.confidence_score,
                "duration_ms": state.session_duration_ms,
                "error": state.error,
            }
            for rid, state in self._results.items()
        ]
