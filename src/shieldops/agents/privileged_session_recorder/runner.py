"""Privileged Session Recorder Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.privileged_session_recorder.graph import (
    create_privileged_session_recorder_graph,
)
from shieldops.agents.privileged_session_recorder.models import PrivilegedSessionRecorderState
from shieldops.agents.privileged_session_recorder.nodes import set_toolkit
from shieldops.agents.privileged_session_recorder.tools import PrivilegedSessionRecorderToolkit
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class PrivilegedSessionRecorderRunner:
    """Runner for privileged_session_recorder."""

    def __init__(self) -> None:
        self._toolkit = PrivilegedSessionRecorderToolkit()
        set_toolkit(self._toolkit)
        graph = create_privileged_session_recorder_graph()
        self._app = graph.compile()
        self._results: dict[str, PrivilegedSessionRecorderState] = {}

    @enforced("privileged_session_recorder")
    async def execute(
        self,
        tenant_id: str = "default",
    ) -> PrivilegedSessionRecorderState:
        rid = f"pri-{uuid4().hex[:12]}"
        initial = PrivilegedSessionRecorderState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "privileged_session_recorder"}},
            )
            final = PrivilegedSessionRecorderState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = PrivilegedSessionRecorderState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> PrivilegedSessionRecorderState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]
