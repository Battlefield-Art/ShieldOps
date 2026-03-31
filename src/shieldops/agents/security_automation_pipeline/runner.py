"""Security Automation Pipeline runner -- entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.security_automation_pipeline.graph import (
    create_security_automation_pipeline_graph,
)
from shieldops.agents.security_automation_pipeline.models import (
    SecurityAutomationPipelineState,
)
from shieldops.agents.security_automation_pipeline.nodes import (
    set_toolkit,
)
from shieldops.agents.security_automation_pipeline.tools import (
    SecurityAutomationPipelineToolkit,
)

logger = structlog.get_logger()


class SecurityAutomationPipelineRunner:
    """Runner for the Security Automation Pipeline Agent."""

    def __init__(
        self,
        ci_provider: Any | None = None,
        sast_engine: Any | None = None,
        sca_engine: Any | None = None,
        dast_engine: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecurityAutomationPipelineToolkit(
            ci_provider=ci_provider,
            sast_engine=sast_engine,
            sca_engine=sca_engine,
            dast_engine=dast_engine,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_security_automation_pipeline_graph()
        self._app = graph.compile()
        self._results: dict[str, SecurityAutomationPipelineState] = {}
        logger.info("sap_runner.initialized")

    async def run(
        self,
        request_id: str,
        tenant_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> SecurityAutomationPipelineState:
        """Run security automation pipeline workflow."""
        sid = f"sap-{uuid4().hex[:12]}"
        initial = SecurityAutomationPipelineState(
            request_id=request_id,
            tenant_id=tenant_id,
            config=config or {},
        )

        logger.info(
            "sap_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "security_automation_pipeline",
                    },
                },
            )
            final = SecurityAutomationPipelineState.model_validate(
                result,
            )
            self._results[sid] = final

            logger.info(
                "sap_runner.completed",
                session_id=sid,
                pipelines=final.pipelines_scanned,
                gates=final.gates_injected,
                findings=final.total_findings,
                passed=final.gates_passed,
                failed=final.gates_failed,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "sap_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err_state = SecurityAutomationPipelineState(
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
    ) -> SecurityAutomationPipelineState | None:
        """Retrieve a previous pipeline result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all pipeline results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "tenant_id": s.tenant_id,
                "pipelines_scanned": s.pipelines_scanned,
                "gates_injected": s.gates_injected,
                "total_findings": s.total_findings,
                "gates_passed": s.gates_passed,
                "gates_failed": s.gates_failed,
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]
