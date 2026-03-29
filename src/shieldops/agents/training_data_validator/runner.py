"""Training Data Validator Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.training_data_validator.graph import create_training_data_validator_graph
from shieldops.agents.training_data_validator.models import TrainingDataValidatorState
from shieldops.agents.training_data_validator.nodes import set_toolkit
from shieldops.agents.training_data_validator.tools import TrainingDataValidatorToolkit

logger = structlog.get_logger()


class TrainingDataValidatorRunner:
    """Runner for training_data_validator."""

    def __init__(self) -> None:
        self._toolkit = TrainingDataValidatorToolkit()
        set_toolkit(self._toolkit)
        graph = create_training_data_validator_graph()
        self._app = graph.compile()
        self._results: dict[str, TrainingDataValidatorState] = {}

    async def execute(
        self,
        tenant_id: str = "default",
    ) -> TrainingDataValidatorState:
        rid = f"tra-{uuid4().hex[:12]}"
        initial = TrainingDataValidatorState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "training_data_validator"}},
            )
            final = TrainingDataValidatorState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = TrainingDataValidatorState(request_id=rid, error=str(e))
            self._results[rid] = err
            return err

    def get_result(self, rid: str) -> TrainingDataValidatorState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]
