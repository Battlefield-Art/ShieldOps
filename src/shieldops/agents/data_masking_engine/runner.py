"""Data Masking Engine Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.data_masking_engine.graph import (
    create_data_masking_engine_graph,
)
from shieldops.agents.data_masking_engine.models import DataMaskingEngineState
from shieldops.agents.data_masking_engine.nodes import set_toolkit
from shieldops.agents.data_masking_engine.tools import DataMaskingEngineToolkit

logger = structlog.get_logger()


class DataMaskingEngineRunner:
    """Runner for data_masking_engine."""

    def __init__(self) -> None:
        self._toolkit = DataMaskingEngineToolkit()
        set_toolkit(self._toolkit)
        graph = create_data_masking_engine_graph()
        self._app = graph.compile()
        self._results: dict[str, DataMaskingEngineState] = {}

    async def execute(
        self,
        tenant_id: str = "default",
    ) -> DataMaskingEngineState:
        rid = f"dat-{uuid4().hex[:12]}"
        initial = DataMaskingEngineState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "data_masking_engine"}},
            )
            final = DataMaskingEngineState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = DataMaskingEngineState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> DataMaskingEngineState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]
