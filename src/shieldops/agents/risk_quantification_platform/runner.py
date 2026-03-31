"""Risk Quantification Platform Agent runner — entry
point for FAIR methodology cyber risk analysis."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.risk_quantification_platform.graph import (
    create_risk_quantification_platform_graph,
)
from shieldops.agents.risk_quantification_platform.models import (
    RiskQuantificationState,
)
from shieldops.agents.risk_quantification_platform.nodes import (
    set_toolkit,
)
from shieldops.agents.risk_quantification_platform.tools import (
    RiskQuantificationPlatformToolkit,
)

logger = structlog.get_logger()


class RiskQuantificationPlatformRunner:
    """Runner for the Risk Quantification Platform Agent."""

    def __init__(
        self,
        asset_registry: Any | None = None,
        threat_intel: Any | None = None,
        loss_modeler: Any | None = None,
        risk_engine: Any | None = None,
        metrics_store: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = RiskQuantificationPlatformToolkit(
            asset_registry=asset_registry,
            threat_intel=threat_intel,
            loss_modeler=loss_modeler,
            risk_engine=risk_engine,
            metrics_store=metrics_store,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_risk_quantification_platform_graph()
        self._app = graph.compile()
        self._results: dict[str, RiskQuantificationState] = {}
        logger.info("rqp_runner.initialized")

    async def quantify(
        self,
        tenant_id: str = "",
        scope: dict[str, Any] | None = None,
    ) -> RiskQuantificationState:
        """Run a FAIR risk quantification analysis."""
        request_id = f"rqp-{uuid4().hex[:12]}"

        initial_state = RiskQuantificationState(
            request_id=request_id,
            tenant_id=tenant_id,
        )

        logger.info(
            "rqp_runner.starting",
            request_id=request_id,
            tenant_id=tenant_id,
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "risk_quantification_platform",
                    },
                },
            )
            final = RiskQuantificationState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "rqp_runner.completed",
                request_id=request_id,
                total_ale=final.total_ale,
                assets=final.assets_analyzed,
                risks=len(final.risk_scores),
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "rqp_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = RiskQuantificationState(
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
    ) -> RiskQuantificationState | None:
        """Retrieve a cached analysis result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all analysis results as summaries."""
        return [
            {
                "request_id": rid,
                "total_ale": s.total_ale,
                "assets_analyzed": s.assets_analyzed,
                "risk_count": len(s.risk_scores),
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
