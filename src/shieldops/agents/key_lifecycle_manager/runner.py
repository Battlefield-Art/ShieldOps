"""Key Lifecycle Manager Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.key_lifecycle_manager.graph import (
    create_key_lifecycle_manager_graph,
)
from shieldops.agents.key_lifecycle_manager.models import KeyLifecycleManagerState
from shieldops.agents.key_lifecycle_manager.nodes import set_toolkit
from shieldops.agents.key_lifecycle_manager.tools import KeyLifecycleManagerToolkit
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class KeyLifecycleManagerRunner:
    """Runner for key_lifecycle_manager."""

    def __init__(self) -> None:
        self._toolkit = KeyLifecycleManagerToolkit()
        set_toolkit(self._toolkit)
        graph = create_key_lifecycle_manager_graph()
        self._app = graph.compile()
        self._results: dict[str, KeyLifecycleManagerState] = {}

    @enforced("key_lifecycle_manager")
    async def execute(
        self,
        tenant_id: str = "default",
    ) -> KeyLifecycleManagerState:
        rid = f"klm-{uuid4().hex[:12]}"
        initial = KeyLifecycleManagerState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "key_lifecycle_manager"}},
            )
            final = KeyLifecycleManagerState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = KeyLifecycleManagerState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> KeyLifecycleManagerState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]
