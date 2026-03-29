"""Shift Handoff Manager Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.shift_handoff_manager.graph import (
    create_shift_handoff_manager_graph,
)
from shieldops.agents.shift_handoff_manager.models import ShiftHandoffManagerState
from shieldops.agents.shift_handoff_manager.nodes import set_toolkit
from shieldops.agents.shift_handoff_manager.tools import ShiftHandoffManagerToolkit

logger = structlog.get_logger()


class ShiftHandoffManagerRunner:
    """Runner for shift_handoff_manager."""

    def __init__(self) -> None:
        self._toolkit = ShiftHandoffManagerToolkit()
        set_toolkit(self._toolkit)
        graph = create_shift_handoff_manager_graph()
        self._app = graph.compile()
        self._results: dict[str, ShiftHandoffManagerState] = {}

    async def execute(
        self,
        tenant_id: str = "default",
    ) -> ShiftHandoffManagerState:
        rid = f"shi-{uuid4().hex[:12]}"
        initial = ShiftHandoffManagerState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "shift_handoff_manager"}},
            )
            final = ShiftHandoffManagerState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = ShiftHandoffManagerState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> ShiftHandoffManagerState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]
