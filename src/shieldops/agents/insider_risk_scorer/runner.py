"""Insider Risk Scorer Agent runner — entry point for
executing insider risk scoring workflows."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.insider_risk_scorer.graph import (
    create_insider_risk_scorer_graph,
)
from shieldops.agents.insider_risk_scorer.models import (
    InsiderRiskScorerState,
)
from shieldops.agents.insider_risk_scorer.nodes import (
    set_toolkit,
)
from shieldops.agents.insider_risk_scorer.tools import (
    InsiderRiskScorerToolkit,
)

logger = structlog.get_logger()


class InsiderRiskScorerRunner:
    """Runner for the Insider Risk Scorer Agent."""

    def __init__(
        self,
        identity_provider: Any | None = None,
        ueba_engine: Any | None = None,
        hr_system: Any | None = None,
        dlp_engine: Any | None = None,
        siem_connector: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = InsiderRiskScorerToolkit(
            identity_provider=identity_provider,
            ueba_engine=ueba_engine,
            hr_system=hr_system,
            dlp_engine=dlp_engine,
            siem_connector=siem_connector,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_insider_risk_scorer_graph()
        self._app = graph.compile()
        self._results: dict[str, InsiderRiskScorerState] = {}
        logger.info("irs_runner.initialized")

    async def score(
        self,
        tenant_id: str = "",
        context: dict[str, Any] | None = None,
    ) -> InsiderRiskScorerState:
        """Execute an insider risk scoring workflow."""
        request_id = f"irs-{uuid4().hex[:12]}"

        initial_state = InsiderRiskScorerState(
            request_id=request_id,
            tenant_id=tenant_id,
        )

        logger.info(
            "irs_runner.starting",
            request_id=request_id,
            tenant_id=tenant_id,
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "insider_risk_scorer",
                    },
                },
            )
            final = InsiderRiskScorerState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "irs_runner.completed",
                request_id=request_id,
                users_scored=final.total_users_scored,
                high_risk=len(final.high_risk_users),
                anomalies=final.anomaly_count,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "irs_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = InsiderRiskScorerState(
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
    ) -> InsiderRiskScorerState | None:
        """Retrieve a cached scoring result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all scoring results as summaries."""
        return [
            {
                "request_id": rid,
                "total_users": s.total_users_scored,
                "high_risk": len(s.high_risk_users),
                "anomalies": s.anomaly_count,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
