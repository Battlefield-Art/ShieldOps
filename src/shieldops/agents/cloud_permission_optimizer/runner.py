"""Cloud Permission Optimizer Agent runner — entry point
for executing permission right-sizing campaigns."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.cloud_permission_optimizer.graph import (
    create_cloud_permission_optimizer_graph,
)
from shieldops.agents.cloud_permission_optimizer.models import (
    CloudPermissionOptimizerState,
    CloudProvider,
)
from shieldops.agents.cloud_permission_optimizer.nodes import (
    set_toolkit,
)
from shieldops.agents.cloud_permission_optimizer.tools import (
    CloudPermissionOptimizerToolkit,
)

logger = structlog.get_logger()


class CloudPermissionOptimizerRunner:
    """Runner for the Cloud Permission Optimizer Agent."""

    def __init__(
        self,
        iam_client: Any | None = None,
        usage_analyzer: Any | None = None,
        policy_generator: Any | None = None,
        risk_scorer: Any | None = None,
        metrics_store: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = CloudPermissionOptimizerToolkit(
            iam_client=iam_client,
            usage_analyzer=usage_analyzer,
            policy_generator=policy_generator,
            risk_scorer=risk_scorer,
            metrics_store=metrics_store,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_cloud_permission_optimizer_graph()
        self._app = graph.compile()
        self._results: dict[str, CloudPermissionOptimizerState] = {}
        logger.info("cpo_runner.initialized")

    async def optimize(
        self,
        target_providers: list[str] | None = None,
        scope: dict[str, Any] | None = None,
        lookback_days: int = 90,
        tenant_id: str = "",
    ) -> CloudPermissionOptimizerState:
        """Run a cross-cloud permission optimization."""
        request_id = f"cpo-{uuid4().hex[:12]}"

        providers = [
            CloudProvider(p)
            for p in (target_providers or [])
            if p in CloudProvider.__members__.values()
        ]

        initial_state = CloudPermissionOptimizerState(
            request_id=request_id,
            tenant_id=tenant_id,
            target_providers=providers,
            scope=scope or {},
            lookback_days=lookback_days,
        )

        logger.info(
            "cpo_runner.starting",
            request_id=request_id,
            providers=len(providers),
            lookback_days=lookback_days,
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "cloud_permission_optimizer",
                    },
                },
            )
            final = CloudPermissionOptimizerState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "cpo_runner.completed",
                request_id=request_id,
                total_perms=final.total_permissions,
                excess=final.excess_count,
                reduction=final.reduction_pct,
                risk=final.risk_score,
            )
            return final

        except Exception as e:
            logger.error(
                "cpo_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = CloudPermissionOptimizerState(
                request_id=request_id,
                tenant_id=tenant_id,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> CloudPermissionOptimizerState | None:
        """Retrieve a cached optimization result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all optimization results as summaries."""
        return [
            {
                "request_id": rid,
                "total_permissions": s.total_permissions,
                "excess_count": s.excess_count,
                "reduction_pct": s.reduction_pct,
                "risk_score": s.risk_score,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
