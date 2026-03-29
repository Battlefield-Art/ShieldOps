"""Incident Cost Calculator Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.incident_cost_calculator.graph import (
    create_incident_cost_calculator_graph,
)
from shieldops.agents.incident_cost_calculator.models import IncidentCostCalculatorState
from shieldops.agents.incident_cost_calculator.nodes import set_toolkit
from shieldops.agents.incident_cost_calculator.tools import IncidentCostCalculatorToolkit

logger = structlog.get_logger()


class IncidentCostCalculatorRunner:
    """Runner for incident_cost_calculator."""

    def __init__(self) -> None:
        self._toolkit = IncidentCostCalculatorToolkit()
        set_toolkit(self._toolkit)
        graph = create_incident_cost_calculator_graph()
        self._app = graph.compile()
        self._results: dict[str, IncidentCostCalculatorState] = {}

    async def execute(
        self,
        tenant_id: str = "default",
    ) -> IncidentCostCalculatorState:
        rid = f"inc-{uuid4().hex[:12]}"
        initial = IncidentCostCalculatorState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "incident_cost_calculator"}},
            )
            final = IncidentCostCalculatorState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = IncidentCostCalculatorState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> IncidentCostCalculatorState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]
