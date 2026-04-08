"""Playbook Optimizer Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.playbook_optimizer.graph import (
    create_playbook_optimizer_graph,
)
from shieldops.agents.playbook_optimizer.models import PlaybookOptimizerState
from shieldops.agents.playbook_optimizer.nodes import set_toolkit
from shieldops.agents.playbook_optimizer.tools import PlaybookOptimizerToolkit
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class PlaybookOptimizerRunner:
    """Runner for playbook_optimizer."""

    def __init__(self) -> None:
        self._toolkit = PlaybookOptimizerToolkit()
        set_toolkit(self._toolkit)
        graph = create_playbook_optimizer_graph()
        self._app = graph.compile()
        self._results: dict[str, PlaybookOptimizerState] = {}

    @enforced("playbook_optimizer")
    async def execute(
        self,
        tenant_id: str = "default",
    ) -> PlaybookOptimizerState:
        rid = f"pla-{uuid4().hex[:12]}"
        initial = PlaybookOptimizerState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "playbook_optimizer"}},
            )
            final = PlaybookOptimizerState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = PlaybookOptimizerState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> PlaybookOptimizerState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]
