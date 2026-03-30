"""Anomaly Prediction Engine Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.anomaly_prediction_engine.graph import (
    create_anomaly_prediction_engine_graph,
)
from shieldops.agents.anomaly_prediction_engine.models import (
    AnomalyPredictionEngineState,
)
from shieldops.agents.anomaly_prediction_engine.nodes import (
    set_toolkit,
)
from shieldops.agents.anomaly_prediction_engine.tools import (
    AnomalyPredictionEngineToolkit,
)

logger = structlog.get_logger()


class AnomalyPredictionEngineRunner:
    """Runner for anomaly_prediction_engine."""

    def __init__(self) -> None:
        self._toolkit = AnomalyPredictionEngineToolkit()
        set_toolkit(self._toolkit)
        graph = create_anomaly_prediction_engine_graph()
        self._app = graph.compile()
        self._results: dict[str, AnomalyPredictionEngineState] = {}

    async def execute(
        self,
        tenant_id: str = "default",
    ) -> AnomalyPredictionEngineState:
        rid = f"ape-{uuid4().hex[:12]}"
        initial = AnomalyPredictionEngineState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={
                    "metadata": {
                        "agent": "anomaly_prediction_engine",
                    }
                },
            )
            final = AnomalyPredictionEngineState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = AnomalyPredictionEngineState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> AnomalyPredictionEngineState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]
