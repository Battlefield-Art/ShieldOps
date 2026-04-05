"""Security Workflow Optimizer runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.security_workflow_optimizer.graph import (
    create_security_workflow_optimizer_graph,
)
from shieldops.agents.security_workflow_optimizer.models import (
    SecurityWorkflowOptimizerState,
)
from shieldops.agents.security_workflow_optimizer.nodes import (
    set_toolkit,
)
from shieldops.agents.security_workflow_optimizer.tools import (
    SecurityWorkflowOptimizerToolkit,
)

logger = structlog.get_logger()


class SecurityWorkflowOptimizerRunner:
    """Runner for the Security Workflow Optimizer Agent."""

    def __init__(
        self,
        workflow_client: Any | None = None,
        analytics_client: Any | None = None,
        optimizer_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecurityWorkflowOptimizerToolkit(
            workflow_client=workflow_client,
            analytics_client=analytics_client,
            optimizer_engine=optimizer_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_security_workflow_optimizer_graph()
        self._app = graph.compile()
        self._results: dict[str, SecurityWorkflowOptimizerState] = {}
        logger.info("swo_runner.initialized")

    async def run(
        self,
        request_id: str,
        tenant_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> SecurityWorkflowOptimizerState:
        """Run workflow optimization pipeline."""
        sid = f"swo-{uuid4().hex[:12]}"
        initial = SecurityWorkflowOptimizerState(
            request_id=request_id,
            tenant_id=tenant_id,
            config=config or {},
        )

        logger.info(
            "swo_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "security_workflow_optimizer",
                    },
                },
            )
            final = SecurityWorkflowOptimizerState.model_validate(result)
            self._results[sid] = final

            logger.info(
                "swo_runner.completed",
                session_id=sid,
                workflows=len(final.workflows),
                bottlenecks=len(final.bottlenecks),
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "swo_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err_state = SecurityWorkflowOptimizerState(
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
    ) -> SecurityWorkflowOptimizerState | None:
        """Retrieve a previous result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "workflows": len(s.workflows),
                "bottlenecks": len(s.bottlenecks),
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]
