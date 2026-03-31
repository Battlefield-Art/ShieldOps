"""Cloud Drift Remediator runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.cloud_drift_remediator.graph import (
    create_cloud_drift_remediator_graph,
)
from shieldops.agents.cloud_drift_remediator.models import (
    CloudDriftRemediatorState,
)
from shieldops.agents.cloud_drift_remediator.nodes import (
    set_toolkit,
)
from shieldops.agents.cloud_drift_remediator.tools import (
    CloudDriftRemediatorToolkit,
)

logger = structlog.get_logger()


class CloudDriftRemediatorRunner:
    """Runner for the Cloud Drift Remediator Agent."""

    def __init__(
        self,
        iac_parser: Any | None = None,
        cloud_api: Any | None = None,
        drift_detector: Any | None = None,
        remediation_engine: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = CloudDriftRemediatorToolkit(
            iac_parser=iac_parser,
            cloud_api=cloud_api,
            drift_detector=drift_detector,
            remediation_engine=remediation_engine,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_cloud_drift_remediator_graph()
        self._app = graph.compile()
        self._results: dict[str, CloudDriftRemediatorState] = {}
        logger.info("cdr_runner.initialized")

    async def remediate(
        self,
        request_id: str,
        tenant_id: str = "",
        scan_config: dict[str, Any] | None = None,
    ) -> CloudDriftRemediatorState:
        """Run cloud drift remediation workflow."""
        sid = f"cdr-{uuid4().hex[:12]}"
        initial = CloudDriftRemediatorState(
            request_id=request_id,
            tenant_id=tenant_id,
            scan_config=scan_config or {},
        )

        logger.info(
            "cdr_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "cloud_drift_remediator",
                    },
                },
            )
            final = CloudDriftRemediatorState.model_validate(
                result,
            )
            self._results[sid] = final

            logger.info(
                "cdr_runner.completed",
                session_id=sid,
                resources=final.resource_count,
                drifts=final.drift_count,
                critical=final.critical_drift_count,
                plans=len(final.remediation_plans),
                executed=len(final.execution_results),
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "cdr_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err_state = CloudDriftRemediatorState(
                request_id=request_id,
                tenant_id=tenant_id,
                scan_config=scan_config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[sid] = err_state
            return err_state

    def get_result(
        self,
        session_id: str,
    ) -> CloudDriftRemediatorState | None:
        """Retrieve a previous remediation result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all remediation results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "tenant_id": s.tenant_id,
                "resources": s.resource_count,
                "drifts": s.drift_count,
                "critical": s.critical_drift_count,
                "plans": len(s.remediation_plans),
                "executed": len(s.execution_results),
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]
