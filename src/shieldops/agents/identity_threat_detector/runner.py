"""Identity Threat Detector runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.identity_threat_detector.graph import (
    create_identity_threat_detector_graph,
)
from shieldops.agents.identity_threat_detector.models import (
    IdentityThreatDetectorState,
)
from shieldops.agents.identity_threat_detector.nodes import (
    set_toolkit,
)
from shieldops.agents.identity_threat_detector.tools import (
    IdentityThreatDetectorToolkit,
)

logger = structlog.get_logger()


class IdentityThreatDetectorRunner:
    """Runner for the Identity Threat Detector Agent."""

    def __init__(
        self,
        iam_provider: Any | None = None,
        ueba_engine: Any | None = None,
        threat_intel: Any | None = None,
        response_engine: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = IdentityThreatDetectorToolkit(
            iam_provider=iam_provider,
            ueba_engine=ueba_engine,
            threat_intel=threat_intel,
            response_engine=response_engine,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_identity_threat_detector_graph()
        self._app = graph.compile()
        self._results: dict[str, IdentityThreatDetectorState] = {}
        logger.info("itd_runner.initialized")

    async def scan(
        self,
        request_id: str,
        tenant_id: str = "",
        detection_config: dict[str, Any] | None = None,
    ) -> IdentityThreatDetectorState:
        """Run identity threat detection workflow."""
        sid = f"itd-{uuid4().hex[:12]}"
        initial = IdentityThreatDetectorState(
            request_id=request_id,
            tenant_id=tenant_id,
            detection_config=detection_config or {},
        )

        logger.info(
            "itd_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "identity_threat_detector",
                    },
                },
            )
            final = IdentityThreatDetectorState.model_validate(
                result,
            )
            self._results[sid] = final

            logger.info(
                "itd_runner.completed",
                session_id=sid,
                events=final.event_count,
                anomalies=final.anomaly_count,
                max_risk=final.max_risk_score,
                responses=final.responded_count,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "itd_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err_state = IdentityThreatDetectorState(
                request_id=request_id,
                tenant_id=tenant_id,
                detection_config=detection_config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[sid] = err_state
            return err_state

    def get_result(
        self,
        session_id: str,
    ) -> IdentityThreatDetectorState | None:
        """Retrieve a previous scan result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all scan results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "tenant_id": s.tenant_id,
                "total_events": s.event_count,
                "anomalies": s.anomaly_count,
                "max_risk": s.max_risk_score,
                "responses": s.responded_count,
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]
