"""Incident Prediction Engine Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.incident_prediction_engine.graph import (
    create_incident_prediction_engine_graph,
)
from shieldops.agents.incident_prediction_engine.models import IncidentPredictionEngineState
from shieldops.agents.incident_prediction_engine.nodes import set_toolkit
from shieldops.agents.incident_prediction_engine.tools import IncidentPredictionEngineToolkit
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class IncidentPredictionEngineRunner:
    """Runner for incident_prediction_engine."""

    def __init__(self) -> None:
        self._toolkit = IncidentPredictionEngineToolkit()
        set_toolkit(self._toolkit)
        graph = create_incident_prediction_engine_graph()
        self._app = graph.compile()
        self._results: dict[str, IncidentPredictionEngineState] = {}

    @enforced("incident_prediction_engine")
    async def execute(
        self,
        tenant_id: str = "default",
    ) -> IncidentPredictionEngineState:
        rid = f"inc-{uuid4().hex[:12]}"
        initial = IncidentPredictionEngineState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "incident_prediction_engine"}},
            )
            final = IncidentPredictionEngineState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = IncidentPredictionEngineState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> IncidentPredictionEngineState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]
