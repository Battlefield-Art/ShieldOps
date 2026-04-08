"""Data Breach Responder Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.data_breach_responder.graph import (
    create_data_breach_responder_graph,
)
from shieldops.agents.data_breach_responder.models import DataBreachResponderState
from shieldops.agents.data_breach_responder.nodes import set_toolkit
from shieldops.agents.data_breach_responder.tools import DataBreachResponderToolkit
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class DataBreachResponderRunner:
    """Runner for data_breach_responder."""

    def __init__(self) -> None:
        self._toolkit = DataBreachResponderToolkit()
        set_toolkit(self._toolkit)
        graph = create_data_breach_responder_graph()
        self._app = graph.compile()
        self._results: dict[str, DataBreachResponderState] = {}

    @enforced("data_breach_responder")
    async def execute(
        self,
        tenant_id: str = "default",
    ) -> DataBreachResponderState:
        rid = f"dat-{uuid4().hex[:12]}"
        initial = DataBreachResponderState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "data_breach_responder"}},
            )
            final = DataBreachResponderState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = DataBreachResponderState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> DataBreachResponderState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]
