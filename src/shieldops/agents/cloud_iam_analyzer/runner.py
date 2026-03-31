"""Cloud IAM Analyzer Agent runner — entry point for
cross-cloud IAM policy analysis and optimization."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.cloud_iam_analyzer.graph import (
    create_cloud_iam_analyzer_graph,
)
from shieldops.agents.cloud_iam_analyzer.models import (
    CloudIAMAnalyzerState,
)
from shieldops.agents.cloud_iam_analyzer.nodes import (
    set_toolkit,
)
from shieldops.agents.cloud_iam_analyzer.tools import (
    CloudIAMAnalyzerToolkit,
)

logger = structlog.get_logger()


class CloudIAMAnalyzerRunner:
    """Runner for the Cloud IAM Analyzer Agent."""

    def __init__(
        self,
        aws_iam_client: Any | None = None,
        gcp_iam_client: Any | None = None,
        azure_rbac_client: Any | None = None,
        policy_store: Any | None = None,
        compliance_engine: Any | None = None,
        metrics_store: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = CloudIAMAnalyzerToolkit(
            aws_iam_client=aws_iam_client,
            gcp_iam_client=gcp_iam_client,
            azure_rbac_client=azure_rbac_client,
            policy_store=policy_store,
            compliance_engine=compliance_engine,
            metrics_store=metrics_store,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_cloud_iam_analyzer_graph()
        self._app = graph.compile()
        self._results: dict[str, CloudIAMAnalyzerState] = {}
        logger.info("cia_runner.initialized")

    async def analyze(
        self,
        target_providers: list[str] | None = None,
        scope: dict[str, Any] | None = None,
        compliance_frameworks: list[str] | None = None,
        tenant_id: str = "",
    ) -> CloudIAMAnalyzerState:
        """Run cross-cloud IAM analysis."""
        request_id = f"cia-{uuid4().hex[:12]}"

        initial_state = CloudIAMAnalyzerState(
            request_id=request_id,
            tenant_id=tenant_id,
            target_providers=target_providers or ["aws"],
            scope=scope or {},
            compliance_frameworks=compliance_frameworks or [],
        )

        logger.info(
            "cia_runner.starting",
            request_id=request_id,
            providers=target_providers or ["aws"],
            frameworks=len(compliance_frameworks or []),
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "cloud_iam_analyzer",
                    },
                },
            )
            final = CloudIAMAnalyzerState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "cia_runner.completed",
                request_id=request_id,
                total_policies=final.total_policies,
                overprivileged=final.overprivileged_count,
                critical=final.critical_risks,
                optimizations=final.optimization_count,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "cia_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = CloudIAMAnalyzerState(
                request_id=request_id,
                tenant_id=tenant_id,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> CloudIAMAnalyzerState | None:
        """Retrieve a cached analysis result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all analysis results as summaries."""
        return [
            {
                "request_id": rid,
                "providers": s.target_providers,
                "total_policies": s.total_policies,
                "overprivileged": s.overprivileged_count,
                "critical_risks": s.critical_risks,
                "optimizations": s.optimization_count,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
