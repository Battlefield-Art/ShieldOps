"""WorkflowEngineRunner — entry point for executing workflow engine orchestration."""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.workflow_engine.graph import create_workflow_engine_graph
from shieldops.agents.workflow_engine.models import WorkflowEngineState
from shieldops.agents.workflow_engine.nodes import set_toolkit
from shieldops.agents.workflow_engine.tools import WorkflowEngineToolkit
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class WorkflowEngineRunner:
    """Runner for the Workflow Engine Agent."""

    def __init__(
        self,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = WorkflowEngineToolkit(
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_workflow_engine_graph()
        self._app = graph.compile()
        self._results: dict[str, WorkflowEngineState] = {}
        logger.info("workflow_engine_runner.initialized")

    @enforced("workflow_engine")
    async def run(
        self,
        tenant_id: str,
        workflow_name: str,
        trigger_data: dict[str, Any] | None = None,
    ) -> WorkflowEngineState:
        """Run a workflow engine orchestration."""
        session_id = f"wfe-{uuid4().hex[:12]}"
        initial_state = WorkflowEngineState(
            session_id=session_id,
            tenant_id=tenant_id,
            workflow_name=workflow_name,
            trigger_data=trigger_data or {},
        )

        logger.info(
            "workflow_engine_runner.starting",
            session_id=session_id,
            tenant_id=tenant_id,
            workflow_name=workflow_name,
        )

        try:
            final_state_dict = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": session_id,
                        "agent": "workflow_engine",
                    }
                },
            )
            final_state = WorkflowEngineState.model_validate(final_state_dict)
            self._results[session_id] = final_state

            logger.info(
                "workflow_engine_runner.completed",
                session_id=session_id,
                duration_ms=final_state.session_duration_ms,
                steps_executed=len(final_state.executed_steps),
            )
            return final_state

        except Exception as e:
            logger.error(
                "workflow_engine_runner.failed",
                session_id=session_id,
                error=str(e),
            )
            error_state = WorkflowEngineState(
                session_id=session_id,
                tenant_id=tenant_id,
                workflow_name=workflow_name,
                trigger_data=trigger_data or {},
                error=str(e),
                current_step="failed",
            )
            self._results[session_id] = error_state
            return error_state

    def get_result(self, session_id: str) -> WorkflowEngineState | None:
        """Get a stored workflow result by session ID."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all stored workflow results."""
        return [
            {
                "session_id": s.session_id,
                "workflow_name": s.workflow_name,
                "current_step": s.current_step,
                "duration_ms": s.session_duration_ms,
                "error": s.error,
            }
            for s in self._results.values()
        ]
