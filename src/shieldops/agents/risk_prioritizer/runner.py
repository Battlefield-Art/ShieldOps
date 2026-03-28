"""Risk Prioritizer Agent runner — entry point."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.risk_prioritizer.graph import (
    create_risk_prioritizer_graph,
)
from shieldops.agents.risk_prioritizer.models import (
    RiskPrioritizerState,
)
from shieldops.agents.risk_prioritizer.nodes import (
    set_toolkit,
)
from shieldops.agents.risk_prioritizer.tools import (
    RiskPrioritizerToolkit,
)

logger = structlog.get_logger()


class RiskPrioritizerRunner:
    """Runner for the Risk Prioritizer Agent."""

    def __init__(
        self,
        finding_store: Any | None = None,
        asset_inventory: Any | None = None,
        epss_client: Any | None = None,
        cmdb_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = RiskPrioritizerToolkit(
            finding_store=finding_store,
            asset_inventory=asset_inventory,
            epss_client=epss_client,
            cmdb_client=cmdb_client,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_risk_prioritizer_graph()
        self._app = graph.compile()
        self._results: dict[str, RiskPrioritizerState] = {}
        logger.info("risk_prioritizer_runner.initialized")

    async def prioritize(
        self,
        tenant_id: str,
    ) -> RiskPrioritizerState:
        """Run risk prioritization."""
        sid = f"rpri-{uuid4().hex[:12]}"
        initial = RiskPrioritizerState(
            tenant_id=tenant_id,
            request_id=sid,
        )

        logger.info(
            "risk_prioritizer_runner.starting",
            session_id=sid,
            tenant_id=tenant_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "risk_prioritizer",
                    }
                },
            )
            final = RiskPrioritizerState.model_validate(result)
            self._results[sid] = final

            logger.info(
                "risk_prioritizer_runner.completed",
                session_id=sid,
                findings=(len(final.findings_collected)),
                critical=final.critical_count,
                immediate=final.immediate_actions,
                duration_ms=(final.session_duration_ms),
            )
            return final

        except Exception as e:
            logger.error(
                "risk_prioritizer_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err = RiskPrioritizerState(
                tenant_id=tenant_id,
                request_id=sid,
                error=str(e),
            )
            self._results[sid] = err
            return err

    def get_result(
        self,
        session_id: str,
    ) -> RiskPrioritizerState | None:
        """Retrieve a stored result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all prioritization summaries."""
        return [
            {
                "session_id": sid,
                "tenant_id": s.tenant_id,
                "findings": (len(s.findings_collected)),
                "critical": s.critical_count,
                "immediate": s.immediate_actions,
                "stage": s.current_stage,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]
