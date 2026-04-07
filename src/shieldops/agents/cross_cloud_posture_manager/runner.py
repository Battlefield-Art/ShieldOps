"""Cross-Cloud Posture Manager runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.cross_cloud_posture_manager.graph import (
    create_cross_cloud_posture_manager_graph,
)
from shieldops.agents.cross_cloud_posture_manager.models import (
    CrossCloudPostureManagerState,
)
from shieldops.agents.cross_cloud_posture_manager.nodes import (
    set_toolkit,
)
from shieldops.agents.cross_cloud_posture_manager.tools import (
    CrossCloudPostureManagerToolkit,
)
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class CrossCloudPostureManagerRunner:
    """Runner for the Cross-Cloud Posture Manager Agent."""

    def __init__(
        self,
        aws_client: Any | None = None,
        gcp_client: Any | None = None,
        azure_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = CrossCloudPostureManagerToolkit(
            aws_client=aws_client,
            gcp_client=gcp_client,
            azure_client=azure_client,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_cross_cloud_posture_manager_graph()
        self._app = graph.compile()
        self._results: dict[str, CrossCloudPostureManagerState] = {}
        logger.info("ccpm_runner.initialized")

    @enforced("cross_cloud_posture_manager")
    async def run(
        self,
        request_id: str,
        tenant_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> CrossCloudPostureManagerState:
        """Run cross-cloud posture management workflow."""
        sid = f"ccpm-{uuid4().hex[:12]}"
        initial = CrossCloudPostureManagerState(
            request_id=request_id,
            tenant_id=tenant_id,
            config=config or {},
        )

        logger.info(
            "ccpm_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "cross_cloud_posture_manager",
                    },
                },
            )
            final = CrossCloudPostureManagerState.model_validate(result)
            self._results[sid] = final

            logger.info(
                "ccpm_runner.completed",
                session_id=sid,
                findings=len(final.findings),
                drifts=len(final.drifts),
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error("ccpm_runner.failed", session_id=sid, error=str(e))
            err_state = CrossCloudPostureManagerState(
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
    ) -> CrossCloudPostureManagerState | None:
        """Retrieve a previous result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "findings": len(s.findings),
                "drifts": len(s.drifts),
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]
