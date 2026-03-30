"""Cloud Workload Inspector runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.cloud_workload_inspector.graph import (
    create_cloud_workload_inspector_graph,
)
from shieldops.agents.cloud_workload_inspector.models import (
    CloudWorkloadInspectorState,
)
from shieldops.agents.cloud_workload_inspector.nodes import (
    set_toolkit,
)
from shieldops.agents.cloud_workload_inspector.tools import (
    CloudWorkloadInspectorToolkit,
)

logger = structlog.get_logger()


class CloudWorkloadInspectorRunner:
    """Runner for the Cloud Workload Inspector Agent."""

    def __init__(
        self,
        cloud_client: Any | None = None,
        config_scanner: Any | None = None,
        compliance_engine: Any | None = None,
        risk_engine: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = CloudWorkloadInspectorToolkit(
            cloud_client=cloud_client,
            config_scanner=config_scanner,
            compliance_engine=compliance_engine,
            risk_engine=risk_engine,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_cloud_workload_inspector_graph()
        self._app = graph.compile()
        self._results: dict[str, CloudWorkloadInspectorState] = {}
        logger.info("cwi_runner.initialized")

    async def inspect(
        self,
        request_id: str,
        tenant_id: str = "",
        inspect_config: dict[str, Any] | None = None,
    ) -> CloudWorkloadInspectorState:
        """Run cloud workload inspection workflow."""
        sid = f"cwi-{uuid4().hex[:12]}"
        initial = CloudWorkloadInspectorState(
            request_id=request_id,
            tenant_id=tenant_id,
            inspect_config=inspect_config or {},
        )

        logger.info(
            "cwi_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "cloud_workload_inspector",
                    },
                },
            )
            final = CloudWorkloadInspectorState.model_validate(
                result,
            )
            self._results[sid] = final

            logger.info(
                "cwi_runner.completed",
                session_id=sid,
                workloads=len(final.discovered_workloads),
                risk=final.max_risk_score,
                compliance=final.compliance_pass_rate,
                recs=len(final.recommendations),
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "cwi_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err_state = CloudWorkloadInspectorState(
                request_id=request_id,
                tenant_id=tenant_id,
                inspect_config=inspect_config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[sid] = err_state
            return err_state

    def get_result(
        self,
        session_id: str,
    ) -> CloudWorkloadInspectorState | None:
        """Retrieve a previous inspection result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all inspection results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "tenant_id": s.tenant_id,
                "total_workloads": len(
                    s.discovered_workloads,
                ),
                "public_workloads": s.public_workload_count,
                "critical_findings": (s.critical_finding_count),
                "compliance_rate": s.compliance_pass_rate,
                "max_risk": s.max_risk_score,
                "recommendations": len(s.recommendations),
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]
