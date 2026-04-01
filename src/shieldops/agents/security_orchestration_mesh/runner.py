"""Security Orchestration Mesh runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.security_orchestration_mesh.graph import (
    create_security_orchestration_mesh_graph,
)
from shieldops.agents.security_orchestration_mesh.models import (
    SecurityOrchestrationMeshState,
)
from shieldops.agents.security_orchestration_mesh.nodes import (
    set_toolkit,
)
from shieldops.agents.security_orchestration_mesh.tools import (
    SecurityOrchestrationMeshToolkit,
)

logger = structlog.get_logger()


class SecurityOrchestrationMeshRunner:
    """Runner for the Security Orchestration Mesh Agent."""

    def __init__(
        self,
        cloud_client: Any | None = None,
        mesh_controller: Any | None = None,
        task_scheduler: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecurityOrchestrationMeshToolkit(
            cloud_client=cloud_client,
            mesh_controller=mesh_controller,
            task_scheduler=task_scheduler,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_security_orchestration_mesh_graph()
        self._app = graph.compile()
        self._results: dict[str, SecurityOrchestrationMeshState] = {}
        logger.info("som_runner.initialized")

    async def run(
        self,
        request_id: str,
        tenant_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> SecurityOrchestrationMeshState:
        """Run orchestration mesh workflow."""
        sid = f"som-{uuid4().hex[:12]}"
        initial = SecurityOrchestrationMeshState(
            request_id=request_id,
            tenant_id=tenant_id,
            config=config or {},
        )

        logger.info(
            "som_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "security_orchestration_mesh",
                    },
                },
            )
            final = SecurityOrchestrationMeshState.model_validate(result)
            self._results[sid] = final

            logger.info(
                "som_runner.completed",
                session_id=sid,
                regions=len(final.regions),
                tasks=len(final.distributed_tasks),
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error("som_runner.failed", session_id=sid, error=str(e))
            err_state = SecurityOrchestrationMeshState(
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
    ) -> SecurityOrchestrationMeshState | None:
        """Retrieve a previous result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "regions": len(s.regions),
                "tasks": len(s.distributed_tasks),
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]
