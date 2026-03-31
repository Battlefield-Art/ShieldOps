"""Autonomous Patch Manager Agent runner — entry point
for executing patch management cycles."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.autonomous_patch_manager.graph import (
    create_autonomous_patch_manager_graph,
)
from shieldops.agents.autonomous_patch_manager.models import (
    AutonomousPatchManagerState,
    DeploymentStrategy,
)
from shieldops.agents.autonomous_patch_manager.nodes import (
    set_toolkit,
)
from shieldops.agents.autonomous_patch_manager.tools import (
    AutonomousPatchManagerToolkit,
)

logger = structlog.get_logger()


class AutonomousPatchManagerRunner:
    """Runner for the Autonomous Patch Manager Agent."""

    def __init__(
        self,
        scanner: Any | None = None,
        patch_repository: Any | None = None,
        deployment_engine: Any | None = None,
        cmdb_client: Any | None = None,
        policy_engine: Any | None = None,
        metrics_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = AutonomousPatchManagerToolkit(
            scanner=scanner,
            patch_repository=patch_repository,
            deployment_engine=deployment_engine,
            cmdb_client=cmdb_client,
            policy_engine=policy_engine,
            metrics_store=metrics_store,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_autonomous_patch_manager_graph()
        self._app = graph.compile()
        self._results: dict[str, AutonomousPatchManagerState] = {}
        logger.info("apm_runner.initialized")

    async def orchestrate(
        self,
        scan_name: str,
        target_environments: list[str] | None = None,
        strategy: str = "rolling",
        auto_deploy: bool = False,
        scope: dict[str, Any] | None = None,
        tenant_id: str = "",
    ) -> AutonomousPatchManagerState:
        """Run a patch management cycle."""
        request_id = f"apm-{uuid4().hex[:12]}"

        initial_state = AutonomousPatchManagerState(
            request_id=request_id,
            tenant_id=tenant_id,
            scan_name=scan_name,
            target_environments=target_environments or [],
            strategy=DeploymentStrategy(strategy),
            auto_deploy=auto_deploy,
            scope=scope or {},
        )

        logger.info(
            "apm_runner.starting",
            request_id=request_id,
            scan=scan_name,
            strategy=strategy,
            auto_deploy=auto_deploy,
            environments=len(initial_state.target_environments),
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "autonomous_patch_manager",
                    },
                },
            )
            final = AutonomousPatchManagerState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "apm_runner.completed",
                request_id=request_id,
                total_assets=final.total_assets,
                patches_available=final.patches_available,
                patches_deployed=final.patches_deployed,
                success_rate=final.deployment_success_rate,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "apm_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = AutonomousPatchManagerState(
                request_id=request_id,
                tenant_id=tenant_id,
                scan_name=scan_name,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(self, request_id: str) -> AutonomousPatchManagerState | None:
        """Retrieve a cached cycle result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all cycle results as summaries."""
        return [
            {
                "request_id": rid,
                "scan": s.scan_name,
                "strategy": s.strategy.value,
                "total_assets": s.total_assets,
                "patches_available": s.patches_available,
                "patches_deployed": s.patches_deployed,
                "success_rate": s.deployment_success_rate,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
