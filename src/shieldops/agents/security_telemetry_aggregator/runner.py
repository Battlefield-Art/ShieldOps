"""Security Telemetry Aggregator runner — entry point."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.security_telemetry_aggregator.graph import (
    create_security_telemetry_aggregator_graph,
)
from shieldops.agents.security_telemetry_aggregator.models import (
    SecurityTelemetryAggregatorState,
)
from shieldops.agents.security_telemetry_aggregator.nodes import (
    set_toolkit,
)
from shieldops.agents.security_telemetry_aggregator.tools import (
    SecurityTelemetryAggregatorToolkit,
)
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class SecurityTelemetryAggregatorRunner:
    """Runner for the Security Telemetry Aggregator Agent."""

    def __init__(
        self,
        telemetry_bus: Any | None = None,
        enrichment_service: Any | None = None,
        alert_router: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecurityTelemetryAggregatorToolkit(
            telemetry_bus=telemetry_bus,
            enrichment_service=enrichment_service,
            alert_router=alert_router,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_security_telemetry_aggregator_graph()
        self._app = graph.compile()
        self._results: dict[str, SecurityTelemetryAggregatorState] = {}
        logger.info("sta_runner.initialized")

    @enforced("security_telemetry_aggregator")
    async def run(
        self,
        request_id: str,
        tenant_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> SecurityTelemetryAggregatorState:
        """Run telemetry aggregation workflow."""
        sid = f"sta-{uuid4().hex[:12]}"
        initial = SecurityTelemetryAggregatorState(
            request_id=request_id,
            tenant_id=tenant_id,
            config=config or {},
        )

        logger.info(
            "sta_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "security_telemetry_aggregator",
                    },
                },
            )
            final = SecurityTelemetryAggregatorState.model_validate(
                result,
            )
            self._results[sid] = final

            logger.info(
                "sta_runner.completed",
                session_id=sid,
                records=len(final.telemetry_records),
                alerts=len(final.alert_routings),
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "sta_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err_state = SecurityTelemetryAggregatorState(
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
    ) -> SecurityTelemetryAggregatorState | None:
        """Retrieve a previous result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "records": len(s.telemetry_records),
                "alerts": len(s.alert_routings),
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]
