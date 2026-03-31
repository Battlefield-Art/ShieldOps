"""Kubernetes Policy Engine Agent runner — entry point
for executing K8s admission control and policy
enforcement."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.kubernetes_policy_engine.graph import (
    create_kubernetes_policy_engine_graph,
)
from shieldops.agents.kubernetes_policy_engine.models import (
    KubernetesPolicyEngineState,
    PolicyScope,
)
from shieldops.agents.kubernetes_policy_engine.nodes import (
    set_toolkit,
)
from shieldops.agents.kubernetes_policy_engine.tools import (
    KubernetesPolicyEngineToolkit,
)

logger = structlog.get_logger()


class KubernetesPolicyEngineRunner:
    """Runner for the Kubernetes Policy Engine Agent."""

    def __init__(
        self,
        k8s_client: Any | None = None,
        opa_client: Any | None = None,
        standards_checker: Any | None = None,
        violation_store: Any | None = None,
        enforcement_engine: Any | None = None,
        metrics_recorder: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = KubernetesPolicyEngineToolkit(
            k8s_client=k8s_client,
            opa_client=opa_client,
            standards_checker=standards_checker,
            violation_store=violation_store,
            enforcement_engine=enforcement_engine,
            metrics_recorder=metrics_recorder,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_kubernetes_policy_engine_graph()
        self._app = graph.compile()
        self._results: dict[str, KubernetesPolicyEngineState] = {}
        logger.info("kpe_runner.initialized")

    async def evaluate(
        self,
        cluster_name: str,
        namespaces: list[str] | None = None,
        policy_scopes: list[str] | None = None,
        config: dict[str, Any] | None = None,
        tenant_id: str = "",
    ) -> KubernetesPolicyEngineState:
        """Run K8s policy evaluation on a cluster."""
        request_id = f"kpe-{uuid4().hex[:12]}"

        scopes = [
            PolicyScope(s) for s in (policy_scopes or []) if s in PolicyScope.__members__.values()
        ]

        initial_state = KubernetesPolicyEngineState(
            request_id=request_id,
            tenant_id=tenant_id,
            cluster_name=cluster_name,
            namespaces=namespaces or [],
            policy_scopes=scopes,
            config=config or {},
        )

        logger.info(
            "kpe_runner.starting",
            request_id=request_id,
            cluster=cluster_name,
            namespaces=len(namespaces or []),
            scopes=len(scopes),
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "kubernetes_policy_engine",
                    },
                },
            )
            final = KubernetesPolicyEngineState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "kpe_runner.completed",
                request_id=request_id,
                total_resources=final.total_resources,
                violations=final.total_violations,
                critical=final.critical_violations,
                compliance=final.compliance_score,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "kpe_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = KubernetesPolicyEngineState(
                request_id=request_id,
                tenant_id=tenant_id,
                cluster_name=cluster_name,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> KubernetesPolicyEngineState | None:
        """Retrieve a cached evaluation result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all evaluation results as summaries."""
        return [
            {
                "request_id": rid,
                "cluster": s.cluster_name,
                "total_resources": s.total_resources,
                "violations": s.total_violations,
                "critical": s.critical_violations,
                "compliance": s.compliance_score,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
