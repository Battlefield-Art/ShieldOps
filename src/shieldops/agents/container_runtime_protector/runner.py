"""Container Runtime Protector runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.container_runtime_protector.graph import (
    create_container_runtime_protector_graph,
)
from shieldops.agents.container_runtime_protector.models import (
    ContainerRuntimeProtectorState,
)
from shieldops.agents.container_runtime_protector.nodes import (
    set_toolkit,
)
from shieldops.agents.container_runtime_protector.tools import (
    ContainerRuntimeProtectorToolkit,
)

logger = structlog.get_logger()


class ContainerRuntimeProtectorRunner:
    """Runner for the Container Runtime Protector Agent."""

    def __init__(
        self,
        k8s_client: Any | None = None,
        runtime_monitor: Any | None = None,
        image_scanner: Any | None = None,
        policy_engine: Any | None = None,
        alert_manager: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ContainerRuntimeProtectorToolkit(
            k8s_client=k8s_client,
            runtime_monitor=runtime_monitor,
            image_scanner=image_scanner,
            policy_engine=policy_engine,
            alert_manager=alert_manager,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_container_runtime_protector_graph()
        self._app = graph.compile()
        self._results: dict[str, ContainerRuntimeProtectorState] = {}
        logger.info("crp_runner.initialized")

    async def protect(
        self,
        request_id: str,
        tenant_id: str = "",
        protection_config: dict[str, Any] | None = None,
    ) -> ContainerRuntimeProtectorState:
        """Run container runtime protection workflow."""
        sid = f"crp-{uuid4().hex[:12]}"
        initial = ContainerRuntimeProtectorState(
            request_id=request_id,
            tenant_id=tenant_id,
            protection_config=protection_config or {},
        )

        logger.info(
            "crp_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": ("container_runtime_protector"),
                    },
                },
            )
            final = ContainerRuntimeProtectorState.model_validate(result)
            self._results[sid] = final

            logger.info(
                "crp_runner.completed",
                session_id=sid,
                workloads=len(final.workload_profiles),
                drifts=len(final.drift_detections),
                risk=final.max_risk_score,
                blocked=final.blocked_count,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "crp_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err_state = ContainerRuntimeProtectorState(
                request_id=request_id,
                tenant_id=tenant_id,
                protection_config=protection_config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[sid] = err_state
            return err_state

    def get_result(
        self,
        session_id: str,
    ) -> ContainerRuntimeProtectorState | None:
        """Retrieve a previous protection result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all protection results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "tenant_id": s.tenant_id,
                "workloads": len(s.workload_profiles),
                "privileged": s.privileged_count,
                "anomalous_events": (s.anomalous_event_count),
                "drifts": len(s.drift_detections),
                "max_risk": s.max_risk_score,
                "blocked": s.blocked_count,
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]
