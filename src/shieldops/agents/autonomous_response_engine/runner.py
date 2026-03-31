"""Autonomous Response Engine Agent runner — entry point
for executing autonomous incident response."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.autonomous_response_engine.graph import (
    create_autonomous_response_engine_graph,
)
from shieldops.agents.autonomous_response_engine.models import (
    AutonomousResponseEngineState,
)
from shieldops.agents.autonomous_response_engine.nodes import (
    set_toolkit,
)
from shieldops.agents.autonomous_response_engine.tools import (
    AutonomousResponseEngineToolkit,
)

logger = structlog.get_logger()


class AutonomousResponseEngineRunner:
    """Runner for the Autonomous Response Engine Agent."""

    def __init__(
        self,
        siem_client: Any | None = None,
        soar_client: Any | None = None,
        edr_client: Any | None = None,
        playbook_store: Any | None = None,
        containment_engine: Any | None = None,
        metrics_store: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = AutonomousResponseEngineToolkit(
            siem_client=siem_client,
            soar_client=soar_client,
            edr_client=edr_client,
            playbook_store=playbook_store,
            containment_engine=containment_engine,
            metrics_store=metrics_store,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_autonomous_response_engine_graph()
        self._app = graph.compile()
        self._results: dict[str, AutonomousResponseEngineState] = {}
        logger.info("are_runner.initialized")

    async def respond(
        self,
        incident_name: str,
        alert_source: str = "",
        alert_data: dict[str, Any] | None = None,
        auto_execute: bool = True,
        tenant_id: str = "",
    ) -> AutonomousResponseEngineState:
        """Run an autonomous incident response."""
        request_id = f"are-{uuid4().hex[:12]}"

        initial_state = AutonomousResponseEngineState(
            request_id=request_id,
            tenant_id=tenant_id,
            incident_name=incident_name,
            alert_source=alert_source,
            alert_data=alert_data or {},
            auto_execute=auto_execute,
        )

        logger.info(
            "are_runner.starting",
            request_id=request_id,
            incident=incident_name,
            source=alert_source,
            auto_execute=auto_execute,
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": ("autonomous_response_engine"),
                    },
                },
            )
            final = AutonomousResponseEngineState.model_validate(
                result,
            )
            self._results[request_id] = final

            logger.info(
                "are_runner.completed",
                request_id=request_id,
                severity=final.severity.value,
                contained=final.threat_contained,
                actions=final.actions_taken,
                response_ms=final.response_time_ms,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "are_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = AutonomousResponseEngineState(
                request_id=request_id,
                tenant_id=tenant_id,
                incident_name=incident_name,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> AutonomousResponseEngineState | None:
        """Retrieve a cached response result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all response results as summaries."""
        return [
            {
                "request_id": rid,
                "incident": s.incident_name,
                "severity": s.severity.value,
                "contained": s.threat_contained,
                "actions_taken": s.actions_taken,
                "response_ms": s.response_time_ms,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
