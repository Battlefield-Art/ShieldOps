"""Remediation Orchestrator Agent runner."""

from __future__ import annotations

from typing import Any

import structlog

from shieldops.agents.remediation_orchestrator.graph import (
    build_graph,
)
from shieldops.agents.remediation_orchestrator.models import (
    RemediationOrchestratorState,
)
from shieldops.agents.remediation_orchestrator.nodes import (
    set_toolkit,
)
from shieldops.agents.remediation_orchestrator.tools import (
    RemediationOrchestratorToolkit,
)
from shieldops.observability.tracing import get_tracer

logger = structlog.get_logger()


class RemediationOrchestratorRunner:
    """Runs remediation orchestration workflows."""

    def __init__(
        self,
        jira_client: Any = None,
        servicenow_client: Any = None,
    ) -> None:
        self._toolkit = RemediationOrchestratorToolkit(
            jira_client=jira_client,
            servicenow_client=servicenow_client,
        )
        set_toolkit(self._toolkit)
        graph = build_graph()
        self._app = graph.compile()
        self._runs: dict[str, RemediationOrchestratorState] = {}

    async def orchestrate(
        self,
        tenant_id: str,
    ) -> RemediationOrchestratorState:
        """Run a full remediation orchestration."""
        logger.info(
            "remediation_orchestration_started",
            tenant_id=tenant_id,
        )

        initial = RemediationOrchestratorState(
            tenant_id=tenant_id,
        )

        try:
            tracer = get_tracer("shieldops.agents")
            with tracer.start_as_current_span("remediation_orchestrator.orchestrate") as span:
                span.set_attribute("remorch.tenant_id", tenant_id)

                result = await self._app.ainvoke(
                    initial.model_dump(),
                    config={
                        "metadata": {
                            "tenant_id": tenant_id,
                        },
                    },
                )

                final = RemediationOrchestratorState.model_validate(result)
                span.set_attribute(
                    "remorch.auto",
                    final.auto_remediated_count,
                )
                span.set_attribute(
                    "remorch.tickets",
                    final.tickets_opened,
                )
                span.set_attribute(
                    "remorch.escalated",
                    final.escalated,
                )

            self._runs[final.request_id] = final
            logger.info(
                "remediation_orchestration_completed",
                tenant_id=tenant_id,
                auto=final.auto_remediated_count,
                tickets=final.tickets_opened,
                escalated=final.escalated,
            )
            return final

        except Exception as e:
            logger.error(
                "remediation_orchestration_failed",
                tenant_id=tenant_id,
                error=str(e),
            )
            return RemediationOrchestratorState(
                tenant_id=tenant_id,
                error=str(e),
                current_stage="failed",
            )
