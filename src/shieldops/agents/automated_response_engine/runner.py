"""Automated Response Engine runner -- entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.automated_response_engine.graph import (
    create_automated_response_engine_graph,
)
from shieldops.agents.automated_response_engine.models import (
    AutomatedResponseEngineState,
)
from shieldops.agents.automated_response_engine.nodes import (
    set_toolkit,
)
from shieldops.agents.automated_response_engine.tools import (
    AutomatedResponseEngineToolkit,
)
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class AutomatedResponseEngineRunner:
    """Runner for the Automated Response Engine Agent."""

    def __init__(
        self,
        incident_client: Any | None = None,
        playbook_store: Any | None = None,
        action_executor: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = AutomatedResponseEngineToolkit(
            incident_client=incident_client,
            playbook_store=playbook_store,
            action_executor=action_executor,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_automated_response_engine_graph()
        self._app = graph.compile()
        self._results: dict[str, AutomatedResponseEngineState] = {}
        logger.info("are_runner.initialized")

    @enforced("automated_response_engine")
    async def run(
        self,
        request_id: str,
        tenant_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> AutomatedResponseEngineState:
        """Run automated response engine workflow."""
        sid = f"are-{uuid4().hex[:12]}"
        initial = AutomatedResponseEngineState(
            request_id=request_id,
            tenant_id=tenant_id,
            config=config or {},
        )

        logger.info(
            "are_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "automated_response_engine",
                    },
                },
            )
            final = AutomatedResponseEngineState.model_validate(result)
            self._results[sid] = final

            logger.info(
                "are_runner.completed",
                session_id=sid,
                incidents=len(final.incident_context),
                actions=len(final.execution_results),
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error("are_runner.failed", session_id=sid, error=str(e))
            err_state = AutomatedResponseEngineState(
                request_id=request_id,
                tenant_id=tenant_id,
                config=config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[sid] = err_state
            return err_state

    def get_result(
        self,
        session_id: str,
    ) -> AutomatedResponseEngineState | None:
        """Retrieve a previous result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "incidents": len(s.incident_context),
                "actions": len(s.execution_results),
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]
