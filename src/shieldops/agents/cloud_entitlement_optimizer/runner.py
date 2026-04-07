"""Cloud Entitlement Optimizer runner — entry point."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.cloud_entitlement_optimizer.graph import (
    create_cloud_entitlement_optimizer_graph,
)
from shieldops.agents.cloud_entitlement_optimizer.models import (
    CloudEntitlementOptimizerState,
)
from shieldops.agents.cloud_entitlement_optimizer.nodes import (
    set_toolkit,
)
from shieldops.agents.cloud_entitlement_optimizer.tools import (
    CloudEntitlementOptimizerToolkit,
)
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class CloudEntitlementOptimizerRunner:
    """Runner for the Cloud Entitlement Optimizer Agent."""

    def __init__(
        self,
        cloud_client: Any | None = None,
        iam_analyzer: Any | None = None,
        risk_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = CloudEntitlementOptimizerToolkit(
            cloud_client=cloud_client,
            iam_analyzer=iam_analyzer,
            risk_engine=risk_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_cloud_entitlement_optimizer_graph()
        self._app = graph.compile()
        self._results: dict[str, CloudEntitlementOptimizerState] = {}
        logger.info("ceo_runner.initialized")

    @enforced("cloud_entitlement_optimizer")
    async def run(
        self,
        request_id: str,
        tenant_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> CloudEntitlementOptimizerState:
        """Run entitlement optimization workflow."""
        sid = f"ceo-{uuid4().hex[:12]}"
        initial = CloudEntitlementOptimizerState(
            request_id=request_id,
            tenant_id=tenant_id,
            config=config or {},
        )

        logger.info(
            "ceo_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "cloud_entitlement_optimizer",
                    },
                },
            )
            final = CloudEntitlementOptimizerState.model_validate(
                result,
            )
            self._results[sid] = final

            logger.info(
                "ceo_runner.completed",
                session_id=sid,
                entitlements=len(final.entitlements),
                recommendations=len(final.recommendations),
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "ceo_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err_state = CloudEntitlementOptimizerState(
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
    ) -> CloudEntitlementOptimizerState | None:
        """Retrieve a previous result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "entitlements": len(s.entitlements),
                "recommendations": len(s.recommendations),
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]
