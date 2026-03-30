"""Capacity Intelligence Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.capacity_intelligence.graph import (
    create_capacity_intelligence_graph,
)
from shieldops.agents.capacity_intelligence.models import (
    CapacityIntelligenceState,
)
from shieldops.agents.capacity_intelligence.nodes import (
    set_toolkit,
)
from shieldops.agents.capacity_intelligence.tools import (
    CapacityIntelligenceToolkit,
)

logger = structlog.get_logger()


class CapacityIntelligenceRunner:
    """Runner for capacity_intelligence."""

    def __init__(self) -> None:
        self._toolkit = CapacityIntelligenceToolkit()
        set_toolkit(self._toolkit)
        graph = create_capacity_intelligence_graph()
        self._app = graph.compile()
        self._results: dict[str, CapacityIntelligenceState] = {}

    async def execute(
        self,
        tenant_id: str = "default",
    ) -> CapacityIntelligenceState:
        rid = f"ci-{uuid4().hex[:12]}"
        initial = CapacityIntelligenceState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={
                    "metadata": {
                        "agent": "capacity_intelligence",
                    }
                },
            )
            final = CapacityIntelligenceState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = CapacityIntelligenceState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> CapacityIntelligenceState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]
