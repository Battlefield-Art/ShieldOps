"""Security Orchestration Hub Agent runner — entry point
for executing security orchestration workflows."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.security_orchestration_hub.graph import (
    create_security_orchestration_hub_graph,
)
from shieldops.agents.security_orchestration_hub.models import (
    SecurityOrchestrationHubState,
)
from shieldops.agents.security_orchestration_hub.nodes import (
    set_toolkit,
)
from shieldops.agents.security_orchestration_hub.tools import (
    SecurityOrchestrationHubToolkit,
)

logger = structlog.get_logger()


class SecurityOrchestrationHubRunner:
    """Runner for the Security Orchestration Hub Agent."""

    def __init__(
        self,
        event_ingester: Any | None = None,
        severity_classifier: Any | None = None,
        playbook_engine: Any | None = None,
        action_executor: Any | None = None,
        outcome_validator: Any | None = None,
        metrics_recorder: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecurityOrchestrationHubToolkit(
            event_ingester=event_ingester,
            severity_classifier=severity_classifier,
            playbook_engine=playbook_engine,
            action_executor=action_executor,
            outcome_validator=outcome_validator,
            metrics_recorder=metrics_recorder,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_security_orchestration_hub_graph()
        self._app = graph.compile()
        self._results: dict[str, SecurityOrchestrationHubState] = {}
        logger.info("soh_runner.initialized")

    async def orchestrate(
        self,
        event_source: str,
        event_type: str = "alert",
        raw_event: dict[str, Any] | None = None,
        tenant_id: str = "",
    ) -> SecurityOrchestrationHubState:
        """Run a security orchestration workflow."""
        request_id = f"soh-{uuid4().hex[:12]}"

        initial_state = SecurityOrchestrationHubState(
            request_id=request_id,
            tenant_id=tenant_id,
            event_source=event_source,
            event_type=event_type,
            raw_event=raw_event or {},
        )

        logger.info(
            "soh_runner.starting",
            request_id=request_id,
            source=event_source,
            event_type=event_type,
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": ("security_orchestration_hub"),
                    },
                },
            )
            final = SecurityOrchestrationHubState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "soh_runner.completed",
                request_id=request_id,
                actions_executed=final.actions_executed,
                actions_succeeded=final.actions_succeeded,
                validated=final.outcome_validated,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "soh_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = SecurityOrchestrationHubState(
                request_id=request_id,
                tenant_id=tenant_id,
                event_source=event_source,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> SecurityOrchestrationHubState | None:
        """Retrieve a cached orchestration result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all orchestration results as summaries."""
        return [
            {
                "request_id": rid,
                "source": s.event_source,
                "event_type": s.event_type,
                "severity": s.severity.value,
                "actions_executed": s.actions_executed,
                "actions_succeeded": s.actions_succeeded,
                "validated": s.outcome_validated,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
