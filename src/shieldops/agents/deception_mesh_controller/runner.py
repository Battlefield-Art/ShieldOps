"""Deception Mesh Controller runner — entry point."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.deception_mesh_controller.graph import (
    create_deception_mesh_controller_graph,
)
from shieldops.agents.deception_mesh_controller.models import (
    DeceptionMeshControllerState,
)
from shieldops.agents.deception_mesh_controller.nodes import (
    set_toolkit,
)
from shieldops.agents.deception_mesh_controller.tools import (
    DeceptionMeshControllerToolkit,
)
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class DeceptionMeshControllerRunner:
    """Runner for the Deception Mesh Controller Agent."""

    def __init__(
        self,
        deception_platform: Any | None = None,
        threat_intel: Any | None = None,
        network_controller: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = DeceptionMeshControllerToolkit(
            deception_platform=deception_platform,
            threat_intel=threat_intel,
            network_controller=network_controller,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_deception_mesh_controller_graph()
        self._app = graph.compile()
        self._results: dict[str, DeceptionMeshControllerState] = {}
        logger.info("dmc_runner.initialized")

    @enforced("deception_mesh_controller")
    async def run(
        self,
        request_id: str,
        tenant_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> DeceptionMeshControllerState:
        """Run deception mesh workflow."""
        sid = f"dmc-{uuid4().hex[:12]}"
        initial = DeceptionMeshControllerState(
            request_id=request_id,
            tenant_id=tenant_id,
            config=config or {},
        )

        logger.info(
            "dmc_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "deception_mesh_controller",
                    },
                },
            )
            final = DeceptionMeshControllerState.model_validate(
                result,
            )
            self._results[sid] = final

            logger.info(
                "dmc_runner.completed",
                session_id=sid,
                decoys=len(final.deployed_decoys),
                profiles=len(final.attacker_profiles),
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "dmc_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err_state = DeceptionMeshControllerState(
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
    ) -> DeceptionMeshControllerState | None:
        """Retrieve a previous result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "decoys": len(s.deployed_decoys),
                "profiles": len(s.attacker_profiles),
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]
