"""Cloud Forensics Collector Agent runner — entry point
for executing cloud forensics investigations."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.cloud_forensics_collector.graph import (
    create_cloud_forensics_collector_graph,
)
from shieldops.agents.cloud_forensics_collector.models import (
    CloudForensicsCollectorState,
    CloudProvider,
)
from shieldops.agents.cloud_forensics_collector.nodes import (
    set_toolkit,
)
from shieldops.agents.cloud_forensics_collector.tools import (
    CloudForensicsCollectorToolkit,
)

logger = structlog.get_logger()


class CloudForensicsCollectorRunner:
    """Runner for the Cloud Forensics Collector Agent."""

    def __init__(
        self,
        aws_client: Any | None = None,
        gcp_client: Any | None = None,
        azure_client: Any | None = None,
        evidence_store: Any | None = None,
        custody_manager: Any | None = None,
        metrics_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = CloudForensicsCollectorToolkit(
            aws_client=aws_client,
            gcp_client=gcp_client,
            azure_client=azure_client,
            evidence_store=evidence_store,
            custody_manager=custody_manager,
            metrics_store=metrics_store,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_cloud_forensics_collector_graph()
        self._app = graph.compile()
        self._results: dict[str, CloudForensicsCollectorState] = {}
        logger.info("cfc_runner.initialized")

    async def orchestrate(
        self,
        case_name: str,
        incident_id: str = "",
        cloud_provider: str = "aws",
        target_resources: list[str] | None = None,
        time_range: dict[str, Any] | None = None,
        scope: dict[str, Any] | None = None,
        tenant_id: str = "",
    ) -> CloudForensicsCollectorState:
        """Run a cloud forensics investigation."""
        request_id = f"cfc-{uuid4().hex[:12]}"

        initial_state = CloudForensicsCollectorState(
            request_id=request_id,
            tenant_id=tenant_id,
            case_name=case_name,
            incident_id=incident_id,
            cloud_provider=CloudProvider(cloud_provider),
            target_resources=target_resources or [],
            time_range=time_range or {},
            scope=scope or {},
        )

        logger.info(
            "cfc_runner.starting",
            request_id=request_id,
            case=case_name,
            incident=incident_id,
            provider=cloud_provider,
            resources=len(initial_state.target_resources),
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "cloud_forensics_collector",
                    },
                },
            )
            final = CloudForensicsCollectorState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "cfc_runner.completed",
                request_id=request_id,
                total_evidence=final.total_evidence,
                iocs_found=final.iocs_found,
                severity=final.severity,
                custody_valid=final.chain_of_custody_valid,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "cfc_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = CloudForensicsCollectorState(
                request_id=request_id,
                tenant_id=tenant_id,
                case_name=case_name,
                incident_id=incident_id,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(self, request_id: str) -> CloudForensicsCollectorState | None:
        """Retrieve a cached investigation result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all investigation results as summaries."""
        return [
            {
                "request_id": rid,
                "case": s.case_name,
                "incident_id": s.incident_id,
                "provider": s.cloud_provider.value,
                "total_evidence": s.total_evidence,
                "iocs_found": s.iocs_found,
                "severity": s.severity,
                "custody_valid": s.chain_of_custody_valid,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
