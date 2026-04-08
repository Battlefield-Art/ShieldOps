"""model_drift_detector runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.model_drift_detector.graph import create_model_drift_detector_graph
from shieldops.agents.model_drift_detector.models import ModelDriftDetectorState
from shieldops.agents.model_drift_detector.nodes import set_toolkit
from shieldops.agents.model_drift_detector.tools import ModelDriftDetectorToolkit
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class ModelDriftDetectorRunner:
    def __init__(self) -> None:
        self._toolkit = ModelDriftDetectorToolkit()
        set_toolkit(self._toolkit)
        graph = create_model_drift_detector_graph()
        self._app = graph.compile()
        self._results: dict[str, ModelDriftDetectorState] = {}

    @enforced("model_drift_detector")
    async def execute(
        self,
        tenant_id: str = "default",
    ) -> ModelDriftDetectorState:
        rid = f"mdd-{uuid4().hex[:12]}"
        initial = ModelDriftDetectorState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "model_drift_detector"}},
            )
            final = ModelDriftDetectorState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = ModelDriftDetectorState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> ModelDriftDetectorState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]
