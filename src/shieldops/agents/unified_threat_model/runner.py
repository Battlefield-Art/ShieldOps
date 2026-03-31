"""Unified Threat Model runner -- entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.unified_threat_model.graph import (
    create_unified_threat_model_graph,
)
from shieldops.agents.unified_threat_model.models import (
    UnifiedThreatModelState,
)
from shieldops.agents.unified_threat_model.nodes import (
    set_toolkit,
)
from shieldops.agents.unified_threat_model.tools import (
    UnifiedThreatModelToolkit,
)

logger = structlog.get_logger()


class UnifiedThreatModelRunner:
    """Runner for the Unified Threat Model Agent."""

    def __init__(
        self,
        asset_inventory: Any | None = None,
        threat_library: Any | None = None,
        control_catalog: Any | None = None,
        risk_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = UnifiedThreatModelToolkit(
            asset_inventory=asset_inventory,
            threat_library=threat_library,
            control_catalog=control_catalog,
            risk_engine=risk_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_unified_threat_model_graph()
        self._app = graph.compile()
        self._results: dict[str, UnifiedThreatModelState] = {}
        logger.info("utm_runner.initialized")

    async def model(
        self,
        request_id: str,
        tenant_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> UnifiedThreatModelState:
        """Run unified threat modeling workflow."""
        sid = f"utm-{uuid4().hex[:12]}"
        initial = UnifiedThreatModelState(
            request_id=request_id,
            tenant_id=tenant_id,
            config=config or {},
        )

        logger.info(
            "utm_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "unified_threat_model",
                    },
                },
            )
            final = UnifiedThreatModelState.model_validate(
                result,
            )
            self._results[sid] = final

            logger.info(
                "utm_runner.completed",
                session_id=sid,
                assets=final.asset_count,
                threats=final.threat_count,
                gaps=final.control_gaps,
                risk=final.max_risk_score,
                mitigations=len(final.prioritized_mitigations),
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "utm_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err_state = UnifiedThreatModelState(
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
    ) -> UnifiedThreatModelState | None:
        """Retrieve a previous threat model result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all threat model results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "tenant_id": s.tenant_id,
                "assets": s.asset_count,
                "threats": s.threat_count,
                "control_gaps": s.control_gaps,
                "max_risk": s.max_risk_score,
                "mitigations": len(s.prioritized_mitigations),
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]
