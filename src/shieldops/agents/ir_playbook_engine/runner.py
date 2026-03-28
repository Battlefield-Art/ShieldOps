"""IR Playbook Engine runner — entry point for executing IR workflows."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.ir_playbook_engine.graph import (
    create_ir_playbook_engine_graph,
)
from shieldops.agents.ir_playbook_engine.models import (
    IRPlaybookEngineState,
)
from shieldops.agents.ir_playbook_engine.nodes import set_toolkit
from shieldops.agents.ir_playbook_engine.tools import (
    IRPlaybookEngineToolkit,
)

logger = structlog.get_logger()


class IRPlaybookEngineRunner:
    """Runner for the IR Playbook Engine Agent."""

    def __init__(
        self,
        playbook_db: Any | None = None,
        infra_client: Any | None = None,
    ) -> None:
        self._toolkit = IRPlaybookEngineToolkit(
            playbook_db=playbook_db,
            infra_client=infra_client,
        )
        set_toolkit(self._toolkit)
        graph = create_ir_playbook_engine_graph()
        self._app = graph.compile()
        self._results: dict[str, IRPlaybookEngineState] = {}
        logger.info("ir_playbook_engine_runner.initialized")

    async def execute(
        self,
        tenant_id: str,
        incident: dict[str, Any] | None = None,
    ) -> IRPlaybookEngineState:
        """Run the IR playbook engine workflow.

        Args:
            tenant_id: Tenant identifier for multi-tenant isolation.
            incident: Raw incident dict with keys like id, title,
                description, severity, indicators, affected_systems.

        Returns:
            Final IRPlaybookEngineState with classification, playbook,
            step results, containment checks, and stats.
        """
        request_id = f"ir-{uuid4().hex[:12]}"

        initial_state = IRPlaybookEngineState(
            request_id=request_id,
            tenant_id=tenant_id,
            incident=incident or {},
        )

        logger.info(
            "ir_playbook_engine_runner.starting",
            request_id=request_id,
            tenant_id=tenant_id,
        )

        try:
            final_state_dict = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": request_id,
                        "agent": "ir_playbook_engine",
                        "tenant_id": tenant_id,
                    },
                },
            )
            final_state = IRPlaybookEngineState.model_validate(final_state_dict)
            self._results[request_id] = final_state

            logger.info(
                "ir_playbook_engine_runner.completed",
                request_id=request_id,
                playbook=final_state.playbook.playbook_name,
                steps=len(final_state.step_results),
                adaptations=len(final_state.adaptations),
                containment_checks=len(final_state.containment_checks),
                duration_ms=final_state.session_duration_ms,
            )
            return final_state

        except Exception as e:
            logger.error(
                "ir_playbook_engine_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = IRPlaybookEngineState(
                request_id=request_id,
                tenant_id=tenant_id,
                incident=incident or {},
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(self, request_id: str) -> IRPlaybookEngineState | None:
        """Retrieve a previous result by request ID."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all execution results with summary info."""
        return [
            {
                "request_id": rid,
                "tenant_id": state.tenant_id,
                "playbook": state.playbook.playbook_name,
                "steps": len(state.step_results),
                "adaptations": len(state.adaptations),
                "containment_checks": len(state.containment_checks),
                "current_step": state.current_step,
                "duration_ms": state.session_duration_ms,
                "error": state.error,
            }
            for rid, state in self._results.items()
        ]
