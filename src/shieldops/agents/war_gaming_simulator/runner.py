"""War Gaming Simulator Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.war_gaming_simulator.graph import (
    create_war_gaming_simulator_graph,
)
from shieldops.agents.war_gaming_simulator.models import WarGamingSimulatorState
from shieldops.agents.war_gaming_simulator.nodes import set_toolkit
from shieldops.agents.war_gaming_simulator.tools import WarGamingSimulatorToolkit
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class WarGamingSimulatorRunner:
    """Runner for war_gaming_simulator."""

    def __init__(self) -> None:
        self._toolkit = WarGamingSimulatorToolkit()
        set_toolkit(self._toolkit)
        graph = create_war_gaming_simulator_graph()
        self._app = graph.compile()
        self._results: dict[str, WarGamingSimulatorState] = {}

    @enforced("war_gaming_simulator")
    async def execute(
        self,
        tenant_id: str = "default",
    ) -> WarGamingSimulatorState:
        rid = f"war-{uuid4().hex[:12]}"
        initial = WarGamingSimulatorState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "war_gaming_simulator"}},
            )
            final = WarGamingSimulatorState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = WarGamingSimulatorState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> WarGamingSimulatorState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]
