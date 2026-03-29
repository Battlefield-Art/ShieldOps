"""Inference Attack Detector Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.inference_attack_detector.graph import create_inference_attack_detector_graph
from shieldops.agents.inference_attack_detector.models import InferenceAttackDetectorState
from shieldops.agents.inference_attack_detector.nodes import set_toolkit
from shieldops.agents.inference_attack_detector.tools import InferenceAttackDetectorToolkit

logger = structlog.get_logger()


class InferenceAttackDetectorRunner:
    """Runner for inference_attack_detector."""

    def __init__(self) -> None:
        self._toolkit = InferenceAttackDetectorToolkit()
        set_toolkit(self._toolkit)
        graph = create_inference_attack_detector_graph()
        self._app = graph.compile()
        self._results: dict[str, InferenceAttackDetectorState] = {}

    async def execute(
        self,
        tenant_id: str = "default",
    ) -> InferenceAttackDetectorState:
        rid = f"inf-{uuid4().hex[:12]}"
        initial = InferenceAttackDetectorState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "inference_attack_detector"}},
            )
            final = InferenceAttackDetectorState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = InferenceAttackDetectorState(request_id=rid, error=str(e))
            self._results[rid] = err
            return err

    def get_result(self, rid: str) -> InferenceAttackDetectorState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]
