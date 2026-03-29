"""Security Copilot Agent runner."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.security_copilot.graph import create_security_copilot_graph
from shieldops.agents.security_copilot.models import SecurityCopilotState
from shieldops.agents.security_copilot.nodes import set_toolkit
from shieldops.agents.security_copilot.tools import SecurityCopilotToolkit

logger = structlog.get_logger()


class SecurityCopilotRunner:
    """Runner for security_copilot."""

    def __init__(self) -> None:
        self._toolkit = SecurityCopilotToolkit()
        set_toolkit(self._toolkit)
        graph = create_security_copilot_graph()
        self._app = graph.compile()
        self._results: dict[str, SecurityCopilotState] = {}

    async def execute(
        self,
        tenant_id: str = "default",
    ) -> SecurityCopilotState:
        rid = f"scp-{uuid4().hex[:12]}"
        initial = SecurityCopilotState(
            request_id=rid,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={"metadata": {"agent": "security_copilot"}},
            )
            final = SecurityCopilotState.model_validate(result)
            self._results[rid] = final
            return final
        except Exception as e:
            err = SecurityCopilotState(
                request_id=rid,
                error=str(e),
            )
            self._results[rid] = err
            return err

    def get_result(
        self,
        rid: str,
    ) -> SecurityCopilotState | None:
        return self._results.get(rid)

    def list_results(self) -> list[dict[str, Any]]:
        return [{"request_id": r, "error": s.error} for r, s in self._results.items()]
