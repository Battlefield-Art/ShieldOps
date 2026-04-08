"""Data Lineage Tracker Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.data_lineage_tracker.graph import (
    create_data_lineage_tracker_graph,
)
from shieldops.agents.data_lineage_tracker.models import DataLineageTrackerState
from shieldops.agents.data_lineage_tracker.nodes import set_toolkit
from shieldops.agents.data_lineage_tracker.tools import DataLineageTrackerToolkit
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class DataLineageTrackerRunner:
    """Runner for data_lineage_tracker."""

    def __init__(self) -> None:
        self._toolkit = DataLineageTrackerToolkit()
        set_toolkit(self._toolkit)
        graph = create_data_lineage_tracker_graph()
        self._app = graph.compile()
        self._results: dict[str, DataLineageTrackerState] = {}

    @enforced("data_lineage_tracker")
    async def execute(
        self,
        tenant_id: str = "default",
    ) -> DataLineageTrackerState:
        rid = f"dat-{uuid4().hex[:12]}"
        initial = DataLineageTrackerState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "data_lineage_tracker"}},
            )
            final = DataLineageTrackerState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = DataLineageTrackerState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> DataLineageTrackerState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]
