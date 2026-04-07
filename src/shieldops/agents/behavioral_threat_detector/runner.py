"""Behavioral Threat Detector Agent runner -- entry point.

Takes runtime configuration, constructs the LangGraph,
runs end-to-end, and returns completed BTD state.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.behavioral_threat_detector.graph import (
    create_behavioral_threat_detector_graph,
)
from shieldops.agents.behavioral_threat_detector.models import (
    BehavioralThreatDetectorState,
)
from shieldops.agents.behavioral_threat_detector.nodes import (
    set_toolkit,
)
from shieldops.agents.behavioral_threat_detector.tools import (
    BehavioralThreatDetectorToolkit,
)
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class BehavioralThreatDetectorRunner:
    """Runs behavioral threat detector workflows.

    Usage:
        runner = BehavioralThreatDetectorRunner(
            behavior_collector=collector,
            threat_scorer=scorer,
        )
        result = await runner.run(tenant_id="t-123")
    """

    def __init__(
        self,
        behavior_collector: Any | None = None,
        baseline_store: Any | None = None,
        deviation_engine: Any | None = None,
        threat_scorer: Any | None = None,
        alert_manager: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = BehavioralThreatDetectorToolkit(
            behavior_collector=behavior_collector,
            baseline_store=baseline_store,
            deviation_engine=deviation_engine,
            threat_scorer=threat_scorer,
            alert_manager=alert_manager,
            repository=repository,
        )
        # Configure module-level toolkit for nodes
        set_toolkit(self._toolkit)

        # Build compiled graph
        graph = create_behavioral_threat_detector_graph()
        self._app = graph.compile()

        # In-memory store of completed runs
        self._results: dict[str, BehavioralThreatDetectorState] = {}

    @enforced("behavioral_threat_detector")
    async def run(
        self,
        tenant_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> BehavioralThreatDetectorState:
        """Run a full behavioral threat detection cycle.

        Args:
            tenant_id: Tenant ID for scoped queries.
            config: Optional configuration overrides.

        Returns:
            Completed BehavioralThreatDetectorState.
        """
        request_id = f"btd-{uuid4().hex[:12]}"

        logger.info(
            "btd_started",
            request_id=request_id,
            tenant_id=tenant_id,
        )

        initial_state = BehavioralThreatDetectorState(
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

            final_state = BehavioralThreatDetectorState.model_validate(final_dict)

            # Calculate total duration
            if final_state.session_start:
                elapsed = datetime.now(UTC) - final_state.session_start
                final_state.session_duration_ms = int(elapsed.total_seconds() * 1000)

            logger.info(
                "btd_completed",
                request_id=request_id,
                behaviors=len(final_state.behaviors),
                baselines=len(final_state.baselines),
                deviations=final_state.deviation_count,
                alerts=final_state.alert_count,
                duration_ms=final_state.session_duration_ms,
            )

            self._results[request_id] = final_state
            return final_state

        except Exception as e:
            logger.error(
                "btd_failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = BehavioralThreatDetectorState(
                request_id=request_id,
                tenant_id=tenant_id,
                config=config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(self, request_id: str) -> BehavioralThreatDetectorState | None:
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
                "behaviors": len(st.behaviors),
                "baselines": len(st.baselines),
                "deviations": st.deviation_count,
                "alerts": st.alert_count,
                "duration_ms": st.session_duration_ms,
                "error": st.error,
            }
            for rid, st in self._results.items()
        ]
