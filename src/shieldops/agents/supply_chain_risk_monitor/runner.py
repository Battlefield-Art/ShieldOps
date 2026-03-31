"""Supply Chain Risk Monitor Agent runner — entry point
for executing supply chain risk assessments."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.supply_chain_risk_monitor.graph import (
    create_supply_chain_risk_monitor_graph,
)
from shieldops.agents.supply_chain_risk_monitor.models import (
    SLSALevel,
    SupplyChainRiskMonitorState,
)
from shieldops.agents.supply_chain_risk_monitor.nodes import (
    set_toolkit,
)
from shieldops.agents.supply_chain_risk_monitor.tools import (
    SupplyChainRiskMonitorToolkit,
)

logger = structlog.get_logger()


class SupplyChainRiskMonitorRunner:
    """Runner for the Supply Chain Risk Monitor Agent."""

    def __init__(
        self,
        dependency_scanner: Any | None = None,
        vuln_database: Any | None = None,
        provenance_verifier: Any | None = None,
        mitigation_engine: Any | None = None,
        metrics_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SupplyChainRiskMonitorToolkit(
            dependency_scanner=dependency_scanner,
            vuln_database=vuln_database,
            provenance_verifier=provenance_verifier,
            mitigation_engine=mitigation_engine,
            metrics_store=metrics_store,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_supply_chain_risk_monitor_graph()
        self._app = graph.compile()
        self._results: dict[str, SupplyChainRiskMonitorState] = {}
        logger.info("scrm_runner.initialized")

    async def monitor(
        self,
        scan_target: str,
        ecosystems: list[str] | None = None,
        slsa_required_level: str = "level_2",
        include_transitive: bool = True,
        tenant_id: str = "",
    ) -> SupplyChainRiskMonitorState:
        """Run a supply chain risk monitoring scan."""
        request_id = f"scrm-{uuid4().hex[:12]}"

        initial_state = SupplyChainRiskMonitorState(
            request_id=request_id,
            tenant_id=tenant_id,
            scan_target=scan_target,
            ecosystems=ecosystems or [],
            slsa_required_level=SLSALevel(slsa_required_level),
            include_transitive=include_transitive,
        )

        logger.info(
            "scrm_runner.starting",
            request_id=request_id,
            target=scan_target,
            ecosystems=len(ecosystems or []),
            slsa_level=slsa_required_level,
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": ("supply_chain_risk_monitor"),
                    },
                },
            )
            final = SupplyChainRiskMonitorState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "scrm_runner.completed",
                request_id=request_id,
                deps=final.total_dependencies,
                risks=final.risks_detected,
                critical=final.critical_risks,
                mitigated=final.mitigations_applied,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "scrm_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = SupplyChainRiskMonitorState(
                request_id=request_id,
                tenant_id=tenant_id,
                scan_target=scan_target,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> SupplyChainRiskMonitorState | None:
        """Retrieve a cached monitoring result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all monitoring results as summaries."""
        return [
            {
                "request_id": rid,
                "target": s.scan_target,
                "dependencies": s.total_dependencies,
                "risks": s.risks_detected,
                "critical": s.critical_risks,
                "mitigated": s.mitigations_applied,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
