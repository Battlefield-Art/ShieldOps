"""SLA Breach Predictor Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.sla_breach_predictor.graph import (
    create_sla_breach_predictor_graph,
)
from shieldops.agents.sla_breach_predictor.models import SlaBreachPredictorState
from shieldops.agents.sla_breach_predictor.nodes import set_toolkit
from shieldops.agents.sla_breach_predictor.tools import SlaBreachPredictorToolkit

logger = structlog.get_logger()


class SlaBreachPredictorRunner:
    """Runner for sla_breach_predictor."""

    def __init__(self) -> None:
        self._toolkit = SlaBreachPredictorToolkit()
        set_toolkit(self._toolkit)
        graph = create_sla_breach_predictor_graph()
        self._app = graph.compile()
        self._results: dict[str, SlaBreachPredictorState] = {}

    async def execute(
        self,
        tenant_id: str = "default",
    ) -> SlaBreachPredictorState:
        rid = f"sla-{uuid4().hex[:12]}"
        initial = SlaBreachPredictorState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "sla_breach_predictor"}},
            )
            final = SlaBreachPredictorState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = SlaBreachPredictorState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> SlaBreachPredictorState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]
