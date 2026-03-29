"""Adversary Emulator Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.adversary_emulator.graph import (
    create_adversary_emulator_graph,
)
from shieldops.agents.adversary_emulator.models import AdversaryEmulatorState
from shieldops.agents.adversary_emulator.nodes import set_toolkit
from shieldops.agents.adversary_emulator.tools import AdversaryEmulatorToolkit

logger = structlog.get_logger()


class AdversaryEmulatorRunner:
    """Runner for adversary_emulator."""

    def __init__(self) -> None:
        self._toolkit = AdversaryEmulatorToolkit()
        set_toolkit(self._toolkit)
        graph = create_adversary_emulator_graph()
        self._app = graph.compile()
        self._results: dict[str, AdversaryEmulatorState] = {}

    async def execute(
        self,
        tenant_id: str = "default",
    ) -> AdversaryEmulatorState:
        rid = f"adv-{uuid4().hex[:12]}"
        initial = AdversaryEmulatorState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "adversary_emulator"}},
            )
            final = AdversaryEmulatorState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = AdversaryEmulatorState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> AdversaryEmulatorState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]
