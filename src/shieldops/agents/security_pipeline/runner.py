"""Security Pipeline Agent runner — entry point."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.security_pipeline.graph import (
    create_security_pipeline_graph,
)
from shieldops.agents.security_pipeline.models import (
    SecurityPipelineState,
)
from shieldops.agents.security_pipeline.nodes import (
    set_toolkit,
)
from shieldops.agents.security_pipeline.tools import (
    SecurityPipelineToolkit,
)

logger = structlog.get_logger()


class SecurityPipelineRunner:
    """Runner for the Security Pipeline Agent."""

    def __init__(
        self,
        agent_registry: Any | None = None,
        finding_store: Any | None = None,
        remediation_engine: Any | None = None,
        verification_engine: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecurityPipelineToolkit(
            agent_registry=agent_registry,
            finding_store=finding_store,
            remediation_engine=remediation_engine,
            verification_engine=verification_engine,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_security_pipeline_graph()
        self._app = graph.compile()
        self._results: dict[str, SecurityPipelineState] = {}
        logger.info("security_pipeline_runner.initialized")

    async def run_pipeline(
        self,
        tenant_id: str,
    ) -> SecurityPipelineState:
        """Run the full security pipeline."""
        sid = f"pipe-{uuid4().hex[:12]}"
        initial = SecurityPipelineState(
            tenant_id=tenant_id,
            request_id=sid,
        )

        logger.info(
            "security_pipeline_runner.starting",
            session_id=sid,
            tenant_id=tenant_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "security_pipeline",
                    }
                },
            )
            final = SecurityPipelineState.model_validate(result)
            self._results[sid] = final

            logger.info(
                "security_pipeline_runner.completed",
                session_id=sid,
                findings=len(final.findings),
                resolved=final.findings_resolved,
                agents=final.agents_dispatched,
                duration_ms=(final.session_duration_ms),
            )
            return final

        except Exception as e:
            logger.error(
                "security_pipeline_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err = SecurityPipelineState(
                tenant_id=tenant_id,
                request_id=sid,
                error=str(e),
            )
            self._results[sid] = err
            return err

    def get_result(
        self,
        session_id: str,
    ) -> SecurityPipelineState | None:
        """Retrieve a stored result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all pipeline run summaries."""
        return [
            {
                "session_id": sid,
                "tenant_id": s.tenant_id,
                "findings": len(s.findings),
                "resolved": s.findings_resolved,
                "agents": s.agents_dispatched,
                "stage": s.current_stage,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]
