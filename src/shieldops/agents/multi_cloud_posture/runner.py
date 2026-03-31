"""Multi-Cloud Posture runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.multi_cloud_posture.graph import (
    create_multi_cloud_posture_graph,
)
from shieldops.agents.multi_cloud_posture.models import (
    MultiCloudPostureState,
)
from shieldops.agents.multi_cloud_posture.nodes import (
    set_toolkit,
)
from shieldops.agents.multi_cloud_posture.tools import (
    MultiCloudPostureToolkit,
)

logger = structlog.get_logger()


class MultiCloudPostureRunner:
    """Runner for the Multi-Cloud Posture Agent."""

    def __init__(
        self,
        aws_scanner: Any | None = None,
        gcp_scanner: Any | None = None,
        azure_scanner: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = MultiCloudPostureToolkit(
            aws_scanner=aws_scanner,
            gcp_scanner=gcp_scanner,
            azure_scanner=azure_scanner,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_multi_cloud_posture_graph()
        self._app = graph.compile()
        self._results: dict[str, MultiCloudPostureState] = {}
        logger.info("mcp_runner.initialized")

    async def assess(
        self,
        request_id: str,
        tenant_id: str = "",
        posture_config: dict[str, Any] | None = None,
    ) -> MultiCloudPostureState:
        """Run multi-cloud posture assessment."""
        sid = f"mcp-{uuid4().hex[:12]}"
        initial = MultiCloudPostureState(
            request_id=request_id,
            tenant_id=tenant_id,
            posture_config=posture_config or {},
        )

        logger.info(
            "mcp_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "multi_cloud_posture",
                    },
                },
            )
            final = MultiCloudPostureState.model_validate(
                result,
            )
            self._results[sid] = final

            logger.info(
                "mcp_runner.completed",
                session_id=sid,
                findings=final.total_findings,
                score=final.overall_score,
                gaps=len(final.security_gaps),
                recs=len(final.recommendations),
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "mcp_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err_state = MultiCloudPostureState(
                request_id=request_id,
                tenant_id=tenant_id,
                posture_config=posture_config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[sid] = err_state
            return err_state

    def get_result(
        self,
        session_id: str,
    ) -> MultiCloudPostureState | None:
        """Retrieve a previous posture result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all posture results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "tenant_id": s.tenant_id,
                "total_findings": s.total_findings,
                "overall_score": s.overall_score,
                "security_gaps": len(s.security_gaps),
                "critical_gaps": s.critical_gaps,
                "recommendations": len(s.recommendations),
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]
