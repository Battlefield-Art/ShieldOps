"""Ticket Automation Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.ticket_automation.graph import (
    create_ticket_automation_graph,
)
from shieldops.agents.ticket_automation.models import TicketAutomationState
from shieldops.agents.ticket_automation.nodes import set_toolkit
from shieldops.agents.ticket_automation.tools import TicketAutomationToolkit

logger = structlog.get_logger()


class TicketAutomationRunner:
    """Runner for ticket_automation."""

    def __init__(self) -> None:
        self._toolkit = TicketAutomationToolkit()
        set_toolkit(self._toolkit)
        graph = create_ticket_automation_graph()
        self._app = graph.compile()
        self._results: dict[str, TicketAutomationState] = {}

    async def execute(
        self,
        tenant_id: str = "default",
    ) -> TicketAutomationState:
        rid = f"tic-{uuid4().hex[:12]}"
        initial = TicketAutomationState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "ticket_automation"}},
            )
            final = TicketAutomationState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = TicketAutomationState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> TicketAutomationState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]
