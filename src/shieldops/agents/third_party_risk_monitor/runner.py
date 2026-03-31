"""Third Party Risk Monitor Agent runner — entry point
for executing vendor risk continuous monitoring."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.third_party_risk_monitor.graph import (
    create_third_party_risk_monitor_graph,
)
from shieldops.agents.third_party_risk_monitor.models import (
    RiskDomain,
    ThirdPartyRiskMonitorState,
)
from shieldops.agents.third_party_risk_monitor.nodes import (
    set_toolkit,
)
from shieldops.agents.third_party_risk_monitor.tools import (
    ThirdPartyRiskMonitorToolkit,
)

logger = structlog.get_logger()


class ThirdPartyRiskMonitorRunner:
    """Runner for the Third Party Risk Monitor Agent."""

    def __init__(
        self,
        vendor_registry: Any | None = None,
        posture_scanner: Any | None = None,
        change_monitor: Any | None = None,
        risk_scorer: Any | None = None,
        alert_engine: Any | None = None,
        metrics_recorder: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ThirdPartyRiskMonitorToolkit(
            vendor_registry=vendor_registry,
            posture_scanner=posture_scanner,
            change_monitor=change_monitor,
            risk_scorer=risk_scorer,
            alert_engine=alert_engine,
            metrics_recorder=metrics_recorder,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_third_party_risk_monitor_graph()
        self._app = graph.compile()
        self._results: dict[str, ThirdPartyRiskMonitorState] = {}
        logger.info("tprm_runner.initialized")

    async def monitor(
        self,
        vendor_filters: dict[str, Any] | None = None,
        risk_domains: list[str] | None = None,
        monitoring_config: dict[str, Any] | None = None,
        threshold_config: dict[str, Any] | None = None,
        tenant_id: str = "",
    ) -> ThirdPartyRiskMonitorState:
        """Run third-party risk monitoring cycle."""
        request_id = f"tprm-{uuid4().hex[:12]}"

        domains = [
            RiskDomain(d) for d in (risk_domains or []) if d in RiskDomain.__members__.values()
        ]

        initial_state = ThirdPartyRiskMonitorState(
            request_id=request_id,
            tenant_id=tenant_id,
            vendor_filters=vendor_filters or {},
            risk_domains=domains,
            monitoring_config=monitoring_config or {},
            threshold_config=threshold_config or {},
        )

        logger.info(
            "tprm_runner.starting",
            request_id=request_id,
            domains=len(domains),
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": ("third_party_risk_monitor"),
                    },
                },
            )
            final = ThirdPartyRiskMonitorState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "tprm_runner.completed",
                request_id=request_id,
                total_vendors=final.total_vendors,
                high_risk=final.high_risk_vendors,
                changes=final.posture_changes_count,
                alerts=final.alerts_generated,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "tprm_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = ThirdPartyRiskMonitorState(
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
    ) -> ThirdPartyRiskMonitorState | None:
        """Retrieve a cached monitoring result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all monitoring results as summaries."""
        return [
            {
                "request_id": rid,
                "total_vendors": s.total_vendors,
                "high_risk": s.high_risk_vendors,
                "changes": s.posture_changes_count,
                "alerts": s.alerts_generated,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
