"""Compliance Workflow Agent runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.compliance_workflow.graph import (
    create_compliance_workflow_graph,
)
from shieldops.agents.compliance_workflow.models import (
    ComplianceWorkflowState,
    Framework,
)
from shieldops.agents.compliance_workflow.nodes import (
    set_toolkit,
)
from shieldops.agents.compliance_workflow.tools import (
    ComplianceWorkflowToolkit,
)

logger = structlog.get_logger()


class ComplianceWorkflowRunner:
    """Runner for the Compliance Workflow Agent."""

    def __init__(
        self,
        evidence_service: Any | None = None,
        policy_store: Any | None = None,
    ) -> None:
        self._toolkit = ComplianceWorkflowToolkit(
            evidence_service=evidence_service,
            policy_store=policy_store,
        )
        set_toolkit(self._toolkit)
        graph = create_compliance_workflow_graph()
        self._app = graph.compile()
        self._results: dict[str, ComplianceWorkflowState] = {}
        logger.info(
            "compliance_workflow_runner.initialized",
        )

    async def execute(
        self,
        tenant_id: str,
        framework: str = "soc2",
    ) -> ComplianceWorkflowState:
        """Run the compliance workflow.

        Args:
            tenant_id: Tenant identifier.
            framework: Compliance framework to audit.

        Returns:
            Final ComplianceWorkflowState with results.
        """
        request_id = f"cw-{uuid4().hex[:12]}"

        try:
            fw = Framework(framework.lower())
        except ValueError:
            fw = Framework.SOC2

        initial_state = ComplianceWorkflowState(
            request_id=request_id,
            tenant_id=tenant_id,
            framework=fw,
        )

        logger.info(
            "compliance_workflow_runner.starting",
            request_id=request_id,
            tenant_id=tenant_id,
            framework=fw.value,
        )

        try:
            final_state_dict = await self._app.ainvoke(
                initial_state.model_dump(),
                config={
                    "metadata": {
                        "session_id": request_id,
                        "agent": "compliance_workflow",
                        "tenant_id": tenant_id,
                        "framework": fw.value,
                    },
                },
            )
            final_state = ComplianceWorkflowState.model_validate(
                final_state_dict,
            )
            self._results[request_id] = final_state

            logger.info(
                "compliance_workflow_runner.completed",
                request_id=request_id,
                controls=len(final_state.controls),
                gaps=len(final_state.gaps),
                score=final_state.overall_score,
            )
            return final_state

        except Exception as e:
            logger.error(
                "compliance_workflow_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = ComplianceWorkflowState(
                request_id=request_id,
                tenant_id=tenant_id,
                framework=fw,
                error=str(e),
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> ComplianceWorkflowState | None:
        """Retrieve a previous result by request ID."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all workflow results with summary info."""
        return [
            {
                "request_id": rid,
                "tenant_id": state.tenant_id,
                "framework": state.framework.value,
                "controls": len(state.controls),
                "gaps": len(state.gaps),
                "score": state.overall_score,
                "stage": state.stage.value,
                "error": state.error,
            }
            for rid, state in self._results.items()
        ]
