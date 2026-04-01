"""Risk Appetite Engine runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.risk_appetite_engine.graph import (
    create_risk_appetite_engine_graph,
)
from shieldops.agents.risk_appetite_engine.models import (
    RiskAppetiteEngineState,
)
from shieldops.agents.risk_appetite_engine.nodes import (
    set_toolkit,
)
from shieldops.agents.risk_appetite_engine.tools import (
    RiskAppetiteEngineToolkit,
)

logger = structlog.get_logger()


class RiskAppetiteEngineRunner:
    """Runner for the Risk Appetite Engine Agent."""

    def __init__(
        self,
        risk_data_source: Any | None = None,
        policy_engine: Any | None = None,
        metrics_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = RiskAppetiteEngineToolkit(
            risk_data_source=risk_data_source,
            policy_engine=policy_engine,
            metrics_store=metrics_store,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_risk_appetite_engine_graph()
        self._app = graph.compile()
        self._results: dict[str, RiskAppetiteEngineState] = {}
        logger.info("rae_runner.initialized")

    async def run(
        self,
        request_id: str,
        tenant_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> RiskAppetiteEngineState:
        """Run risk appetite workflow."""
        sid = f"rae-{uuid4().hex[:12]}"
        initial = RiskAppetiteEngineState(
            request_id=request_id,
            tenant_id=tenant_id,
            config=config or {},
        )

        logger.info(
            "rae_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "risk_appetite_engine",
                    },
                },
            )
            final = RiskAppetiteEngineState.model_validate(result)
            self._results[sid] = final

            logger.info(
                "rae_runner.completed",
                session_id=sid,
                definitions=len(final.appetite_definitions),
                breaches=len(final.breach_records),
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "rae_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err_state = RiskAppetiteEngineState(
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
    ) -> RiskAppetiteEngineState | None:
        """Retrieve a previous result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "definitions": len(s.appetite_definitions),
                "breaches": len(s.breach_records),
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]
