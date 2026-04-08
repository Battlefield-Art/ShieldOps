"""Hunt Hypothesis Generator Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.hunt_hypothesis_generator.graph import (
    create_hunt_hypothesis_generator_graph,
)
from shieldops.agents.hunt_hypothesis_generator.models import HuntHypothesisGeneratorState
from shieldops.agents.hunt_hypothesis_generator.nodes import set_toolkit
from shieldops.agents.hunt_hypothesis_generator.tools import HuntHypothesisGeneratorToolkit
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class HuntHypothesisGeneratorRunner:
    """Runner for hunt_hypothesis_generator."""

    def __init__(self) -> None:
        self._toolkit = HuntHypothesisGeneratorToolkit()
        set_toolkit(self._toolkit)
        graph = create_hunt_hypothesis_generator_graph()
        self._app = graph.compile()
        self._results: dict[str, HuntHypothesisGeneratorState] = {}

    @enforced("hunt_hypothesis_generator")
    async def execute(
        self,
        tenant_id: str = "default",
    ) -> HuntHypothesisGeneratorState:
        rid = f"hun-{uuid4().hex[:12]}"
        initial = HuntHypothesisGeneratorState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "hunt_hypothesis_generator"}},
            )
            final = HuntHypothesisGeneratorState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = HuntHypothesisGeneratorState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> HuntHypothesisGeneratorState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]
