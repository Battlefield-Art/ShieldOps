"""Autonomous Patch Manager runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.autonomous_patch_manager.graph import (
    create_autonomous_patch_manager_graph,
)
from shieldops.agents.autonomous_patch_manager.models import (
    AutonomousPatchManagerState,
)
from shieldops.agents.autonomous_patch_manager.nodes import set_toolkit
from shieldops.agents.autonomous_patch_manager.tools import (
    AutonomousPatchManagerToolkit,
)

logger = structlog.get_logger()


class AutonomousPatchManagerRunner:
    """Runner for the Autonomous Patch Manager Agent."""

    def __init__(
        self,
        asset_client: Any | None = None,
        patch_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = AutonomousPatchManagerToolkit(
            scanner=asset_client,
            patch_repository=patch_client,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_autonomous_patch_manager_graph()
        self._app = graph.compile()
        self._results: dict[str, AutonomousPatchManagerState] = {}
        logger.info("apm_runner.initialized")

    async def run(
        self,
        request_id: str | None = None,
        tenant_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> AutonomousPatchManagerState:
        """Run patch management workflow."""
        rid = request_id or f"apm-{uuid4().hex[:12]}"
        initial = AutonomousPatchManagerState(
            request_id=rid,
            tenant_id=tenant_id,
            config=config or {},
        )

        logger.info("apm_runner.starting", request_id=rid)

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={"metadata": {"request_id": rid, "agent": "autonomous_patch_manager"}},
            )
            final = AutonomousPatchManagerState.model_validate(result)
            self._results[rid] = final
            logger.info(
                "apm_runner.completed",
                request_id=rid,
                assets=len(final.inventory),
                patches=len(final.patch_assessments),
                duration_ms=final.session_duration_ms,
            )
            return final
        except Exception as e:
            logger.error("apm_runner.failed", request_id=rid, error=str(e))
            err = AutonomousPatchManagerState(
                request_id=rid,
                tenant_id=tenant_id,
                error=str(e),
                current_step="failed",
            )
            self._results[rid] = err
            return err

    def get_result(self, request_id: str) -> AutonomousPatchManagerState | None:
        """Retrieve a previous result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all results."""
        return [
            {
                "request_id": rid,
                "assets": len(s.inventory),
                "patches": len(s.patch_assessments),
                "step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
