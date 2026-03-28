"""Session Hijack Detector Agent runner — entry point for detection workflows."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.session_hijack_detector.graph import (
    create_session_hijack_detector_graph,
)
from shieldops.agents.session_hijack_detector.models import (
    SessionHijackDetectorState,
)
from shieldops.agents.session_hijack_detector.nodes import (
    set_toolkit,
)
from shieldops.agents.session_hijack_detector.tools import (
    SessionHijackDetectorToolkit,
)

logger = structlog.get_logger()


class SessionHijackDetectorRunner:
    """Runner for the Session Hijack Detector Agent.

    Orchestrates session event collection, anomaly detection,
    indicator correlation, risk assessment, and automated
    response for session hijacking attacks.
    """

    def __init__(
        self,
        session_store: Any | None = None,
        identity_service: Any | None = None,
        geo_service: Any | None = None,
        token_service: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SessionHijackDetectorToolkit(
            session_store=session_store,
            identity_service=identity_service,
            geo_service=geo_service,
            token_service=token_service,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_session_hijack_detector_graph()
        self._app = graph.compile()
        self._results: dict[str, SessionHijackDetectorState] = {}
        logger.info(
            "session_hijack_detector_runner.initialized",
        )

    async def detect(
        self,
        tenant_id: str,
        events: list[dict[str, Any]] | None = None,
        detection_id: str | None = None,
    ) -> SessionHijackDetectorState:
        """Run session hijack detection workflow.

        Args:
            tenant_id: Tenant identifier.
            events: Raw session events to analyze.
            detection_id: Optional detection run ID.

        Returns:
            Final SessionHijackDetectorState with report.
        """
        session_id = f"shd-{uuid4().hex[:12]}"
        did = detection_id or f"det-{uuid4().hex[:8]}"

        initial_state = SessionHijackDetectorState(
            tenant_id=tenant_id,
            detection_id=did,
            raw_events=events or [],
        )

        logger.info(
            "session_hijack_detector_runner.starting",
            session_id=session_id,
            tenant_id=tenant_id,
            detection_id=did,
            event_count=len(initial_state.raw_events),
        )

        try:
            final_dict = await self._app.ainvoke(
                initial_state.model_dump(),
                config={
                    "metadata": {
                        "session_id": session_id,
                        "agent": "session_hijack_detector",
                    },
                },
            )
            final_state = SessionHijackDetectorState.model_validate(
                final_dict,
            )
            self._results[session_id] = final_state

            logger.info(
                "session_hijack_detector_runner.completed",
                session_id=session_id,
                confirmed=final_state.confirmed_hijacks,
                risk=final_state.overall_risk,
                indicators=final_state.anomaly_count,
                responses=final_state.responses_executed,
                duration_ms=final_state.session_duration_ms,
            )
            return final_state

        except Exception as e:
            logger.error(
                "session_hijack_detector_runner.failed",
                session_id=session_id,
                error=str(e),
            )
            error_state = SessionHijackDetectorState(
                tenant_id=tenant_id,
                detection_id=did,
                raw_events=events or [],
                error=str(e),
                current_step="failed",
            )
            self._results[session_id] = error_state
            return error_state

    def get_result(
        self,
        session_id: str,
    ) -> SessionHijackDetectorState | None:
        """Get result by session ID."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all detection run results."""
        return [
            {
                "session_id": sid,
                "tenant_id": state.tenant_id,
                "detection_id": state.detection_id,
                "confirmed_hijacks": (state.confirmed_hijacks),
                "overall_risk": state.overall_risk,
                "risk_score": state.risk_score,
                "anomaly_count": state.anomaly_count,
                "responses_executed": (state.responses_executed),
                "current_step": state.current_step,
                "error": state.error,
            }
            for sid, state in self._results.items()
        ]
