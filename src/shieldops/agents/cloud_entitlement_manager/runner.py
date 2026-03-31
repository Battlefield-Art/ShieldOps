"""Cloud Entitlement Manager Agent runner — entry point
for executing CIEM analysis campaigns."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.cloud_entitlement_manager.graph import (
    create_cloud_entitlement_manager_graph,
)
from shieldops.agents.cloud_entitlement_manager.models import (
    CloudEntitlementManagerState,
    CloudProvider,
)
from shieldops.agents.cloud_entitlement_manager.nodes import (
    set_toolkit,
)
from shieldops.agents.cloud_entitlement_manager.tools import (
    CloudEntitlementManagerToolkit,
)

logger = structlog.get_logger()


class CloudEntitlementManagerRunner:
    """Runner for the Cloud Entitlement Manager Agent."""

    def __init__(
        self,
        iam_connector: Any | None = None,
        permission_analyzer: Any | None = None,
        risk_scorer: Any | None = None,
        policy_generator: Any | None = None,
        compliance_checker: Any | None = None,
        metrics_store: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = CloudEntitlementManagerToolkit(
            iam_connector=iam_connector,
            permission_analyzer=permission_analyzer,
            risk_scorer=risk_scorer,
            policy_generator=policy_generator,
            compliance_checker=compliance_checker,
            metrics_store=metrics_store,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_cloud_entitlement_manager_graph()
        self._app = graph.compile()
        self._results: dict[str, CloudEntitlementManagerState] = {}
        logger.info("cem_runner.initialized")

    async def analyze(
        self,
        target_providers: list[str] | None = None,
        scope: dict[str, Any] | None = None,
        scan_options: dict[str, Any] | None = None,
        tenant_id: str = "",
    ) -> CloudEntitlementManagerState:
        """Run a cloud entitlement analysis."""
        request_id = f"cem-{uuid4().hex[:12]}"

        providers = [
            CloudProvider(p)
            for p in (target_providers or [])
            if p in CloudProvider.__members__.values()
        ]

        initial_state = CloudEntitlementManagerState(
            request_id=request_id,
            tenant_id=tenant_id,
            target_providers=providers,
            scope=scope or {},
            scan_options=scan_options or {},
        )

        logger.info(
            "cem_runner.starting",
            request_id=request_id,
            providers=len(providers),
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": ("cloud_entitlement_manager"),
                    },
                },
            )
            final = CloudEntitlementManagerState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "cem_runner.completed",
                request_id=request_id,
                identities=final.total_identities,
                excess=final.excess_count,
                high_risk=final.high_risk_count,
                risk_score=final.risk_score,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "cem_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = CloudEntitlementManagerState(
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
    ) -> CloudEntitlementManagerState | None:
        """Retrieve a cached analysis result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all analysis results as summaries."""
        return [
            {
                "request_id": rid,
                "identities": s.total_identities,
                "excess": s.excess_count,
                "high_risk": s.high_risk_count,
                "risk_score": s.risk_score,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
