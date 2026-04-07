"""Incident Prediction Model runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.incident_prediction_model.graph import (
    create_incident_prediction_model_graph,
)
from shieldops.agents.incident_prediction_model.models import (
    IncidentPredictionModelState,
)
from shieldops.agents.incident_prediction_model.nodes import (
    set_toolkit,
)
from shieldops.agents.incident_prediction_model.tools import (
    IncidentPredictionModelToolkit,
)
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class IncidentPredictionModelRunner:
    """Runner for the Incident Prediction Model Agent."""

    def __init__(
        self,
        siem_client: Any | None = None,
        threat_intel_client: Any | None = None,
        incident_db: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = IncidentPredictionModelToolkit(
            siem_client=siem_client,
            threat_intel_client=threat_intel_client,
            incident_db=incident_db,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_incident_prediction_model_graph()
        self._app = graph.compile()
        self._results: dict[str, IncidentPredictionModelState] = {}
        logger.info("ipm_runner.initialized")

    @enforced("incident_prediction_model")
    async def run(
        self,
        request_id: str,
        tenant_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> IncidentPredictionModelState:
        """Run incident prediction workflow."""
        sid = f"ipm-{uuid4().hex[:12]}"
        initial = IncidentPredictionModelState(
            request_id=request_id,
            tenant_id=tenant_id,
            config=config or {},
        )

        logger.info(
            "ipm_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "incident_prediction_model",
                    },
                },
            )
            final = IncidentPredictionModelState.model_validate(result)
            self._results[sid] = final

            logger.info(
                "ipm_runner.completed",
                session_id=sid,
                signals=len(final.signals),
                predictions=len(final.predictions),
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error("ipm_runner.failed", session_id=sid, error=str(e))
            err_state = IncidentPredictionModelState(
                request_id=request_id,
                tenant_id=tenant_id,
                config=config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[sid] = err_state
            return err_state

    def get_result(
        self,
        session_id: str,
    ) -> IncidentPredictionModelState | None:
        """Retrieve a previous result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "signals": len(s.signals),
                "predictions": len(s.predictions),
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]
