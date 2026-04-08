"""Session Manager Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.session_manager.graph import (
    create_session_manager_graph,
)
from shieldops.agents.session_manager.models import (
    SessionManagerState,
)
from shieldops.agents.session_manager.nodes import (
    set_toolkit,
)
from shieldops.agents.session_manager.tools import (
    SessionManagerToolkit,
)
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class SessionManagerRunner:
    """Runner for session_manager."""

    def __init__(self) -> None:
        self._toolkit = SessionManagerToolkit()
        set_toolkit(self._toolkit)
        graph = create_session_manager_graph()
        self._app = graph.compile()
        self._results: dict[str, SessionManagerState] = {}

    @enforced("session_manager")
    async def execute(self, tenant_id: str = "default") -> SessionManagerState:
        rid = f"sm-{uuid4().hex[:12]}"
        initial = SessionManagerState(request_id=rid, tenant_id=tenant_id)
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "session_manager"}},
            )
            final = SessionManagerState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = SessionManagerState(request_id=rid, error=str(e))
            self._results[rid] = err
            return err

    def get_result(self, rid: str) -> SessionManagerState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]
