"""Micro Segmentation Planner Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.micro_segmentation_planner.graph import (
    create_micro_segmentation_planner_graph,
)
from shieldops.agents.micro_segmentation_planner.models import MicroSegmentationPlannerState
from shieldops.agents.micro_segmentation_planner.nodes import set_toolkit
from shieldops.agents.micro_segmentation_planner.tools import MicroSegmentationPlannerToolkit

logger = structlog.get_logger()


class MicroSegmentationPlannerRunner:
    """Runner for micro_segmentation_planner."""

    def __init__(self) -> None:
        self._toolkit = MicroSegmentationPlannerToolkit()
        set_toolkit(self._toolkit)
        graph = create_micro_segmentation_planner_graph()
        self._app = graph.compile()
        self._results: dict[str, MicroSegmentationPlannerState] = {}

    async def execute(
        self,
        tenant_id: str = "default",
    ) -> MicroSegmentationPlannerState:
        rid = f"mic-{uuid4().hex[:12]}"
        initial = MicroSegmentationPlannerState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "micro_segmentation_planner"}},
            )
            final = MicroSegmentationPlannerState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = MicroSegmentationPlannerState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> MicroSegmentationPlannerState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]
