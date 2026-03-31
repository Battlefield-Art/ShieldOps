"""Security Mesh Orchestrator Agent runner — entry point
for executing mesh security assessments."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.security_mesh_orchestrator.graph import (
    create_security_mesh_orchestrator_graph,
)
from shieldops.agents.security_mesh_orchestrator.models import (
    MeshPlatform,
    SecurityMeshOrchestratorState,
)
from shieldops.agents.security_mesh_orchestrator.nodes import (
    set_toolkit,
)
from shieldops.agents.security_mesh_orchestrator.tools import (
    SecurityMeshOrchestratorToolkit,
)

logger = structlog.get_logger()


class SecurityMeshOrchestratorRunner:
    """Runner for the Security Mesh Orchestrator Agent."""

    def __init__(
        self,
        mesh_client: Any | None = None,
        certificate_manager: Any | None = None,
        traffic_monitor: Any | None = None,
        anomaly_detector: Any | None = None,
        policy_engine: Any | None = None,
        metrics_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecurityMeshOrchestratorToolkit(
            mesh_client=mesh_client,
            certificate_manager=certificate_manager,
            traffic_monitor=traffic_monitor,
            anomaly_detector=anomaly_detector,
            policy_engine=policy_engine,
            metrics_store=metrics_store,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_security_mesh_orchestrator_graph()
        self._app = graph.compile()
        self._results: dict[str, SecurityMeshOrchestratorState] = {}
        logger.info("smo_runner.initialized")

    async def orchestrate(
        self,
        mesh_name: str,
        platform: str = "istio",
        target_namespaces: list[str] | None = None,
        scope: dict[str, Any] | None = None,
        tenant_id: str = "",
    ) -> SecurityMeshOrchestratorState:
        """Run a service mesh security assessment."""
        request_id = f"smo-{uuid4().hex[:12]}"

        initial_state = SecurityMeshOrchestratorState(
            request_id=request_id,
            tenant_id=tenant_id,
            mesh_name=mesh_name,
            platform=MeshPlatform(platform),
            target_namespaces=target_namespaces or [],
            scope=scope or {},
        )

        logger.info(
            "smo_runner.starting",
            request_id=request_id,
            mesh=mesh_name,
            platform=platform,
            namespaces=len(initial_state.target_namespaces),
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "security_mesh_orchestrator",
                    },
                },
            )
            final = SecurityMeshOrchestratorState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "smo_runner.completed",
                request_id=request_id,
                total_services=final.total_services,
                mtls_coverage=final.mtls_coverage,
                anomalies=final.anomalies_detected,
                risk_score=final.risk_score,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "smo_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = SecurityMeshOrchestratorState(
                request_id=request_id,
                tenant_id=tenant_id,
                mesh_name=mesh_name,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(self, request_id: str) -> SecurityMeshOrchestratorState | None:
        """Retrieve a cached assessment result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all assessment results as summaries."""
        return [
            {
                "request_id": rid,
                "mesh": s.mesh_name,
                "platform": s.platform.value,
                "total_services": s.total_services,
                "mtls_coverage": s.mtls_coverage,
                "anomalies": s.anomalies_detected,
                "risk_score": s.risk_score,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
