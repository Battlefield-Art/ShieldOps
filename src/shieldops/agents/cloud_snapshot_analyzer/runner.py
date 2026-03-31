"""Cloud Snapshot Analyzer Agent runner — entry point
for executing snapshot security analysis."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.cloud_snapshot_analyzer.graph import (
    create_cloud_snapshot_analyzer_graph,
)
from shieldops.agents.cloud_snapshot_analyzer.models import (
    CloudProvider,
    CloudSnapshotAnalyzerState,
)
from shieldops.agents.cloud_snapshot_analyzer.nodes import (
    set_toolkit,
)
from shieldops.agents.cloud_snapshot_analyzer.tools import (
    CloudSnapshotAnalyzerToolkit,
)

logger = structlog.get_logger()


class CloudSnapshotAnalyzerRunner:
    """Runner for the Cloud Snapshot Analyzer Agent."""

    def __init__(
        self,
        aws_client: Any | None = None,
        gcp_client: Any | None = None,
        azure_client: Any | None = None,
        encryption_auditor: Any | None = None,
        exposure_scanner: Any | None = None,
        risk_engine: Any | None = None,
        cost_calculator: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = CloudSnapshotAnalyzerToolkit(
            aws_client=aws_client,
            gcp_client=gcp_client,
            azure_client=azure_client,
            encryption_auditor=encryption_auditor,
            exposure_scanner=exposure_scanner,
            risk_engine=risk_engine,
            cost_calculator=cost_calculator,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_cloud_snapshot_analyzer_graph()
        self._app = graph.compile()
        self._results: dict[str, CloudSnapshotAnalyzerState] = {}
        logger.info("csa_runner.initialized")

    async def analyze(
        self,
        cloud_provider: str = "aws",
        regions: list[str] | None = None,
        account_ids: list[str] | None = None,
        max_age_days: int = 90,
        tenant_id: str = "",
    ) -> CloudSnapshotAnalyzerState:
        """Run cloud snapshot security analysis."""
        request_id = f"csa-{uuid4().hex[:12]}"

        initial_state = CloudSnapshotAnalyzerState(
            request_id=request_id,
            tenant_id=tenant_id,
            cloud_provider=CloudProvider(cloud_provider),
            regions=regions or [],
            account_ids=account_ids or [],
            max_age_days=max_age_days,
        )

        logger.info(
            "csa_runner.starting",
            request_id=request_id,
            provider=cloud_provider,
            regions=len(regions or []),
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "cloud_snapshot_analyzer",
                    },
                },
            )
            final = CloudSnapshotAnalyzerState.model_validate(
                result,
            )
            self._results[request_id] = final

            logger.info(
                "csa_runner.completed",
                request_id=request_id,
                total_snapshots=final.total_snapshots,
                unencrypted=final.unencrypted_count,
                exposed=final.exposed_count,
                high_risk=final.high_risk_count,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "csa_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = CloudSnapshotAnalyzerState(
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
    ) -> CloudSnapshotAnalyzerState | None:
        """Retrieve a cached analysis result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all analysis results as summaries."""
        return [
            {
                "request_id": rid,
                "provider": s.cloud_provider.value,
                "total_snapshots": s.total_snapshots,
                "unencrypted": s.unencrypted_count,
                "exposed": s.exposed_count,
                "high_risk": s.high_risk_count,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
