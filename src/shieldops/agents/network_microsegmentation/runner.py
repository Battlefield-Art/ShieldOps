"""Network Microsegmentation Agent runner — entry point
for executing segmentation workflows."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.network_microsegmentation.graph import (
    create_network_microsegmentation_graph,
)
from shieldops.agents.network_microsegmentation.models import (
    NetworkMicrosegmentationState,
    SegmentationType,
)
from shieldops.agents.network_microsegmentation.nodes import (
    set_toolkit,
)
from shieldops.agents.network_microsegmentation.tools import (
    NetworkMicrosegmentationToolkit,
)

logger = structlog.get_logger()


class NetworkMicrosegmentationRunner:
    """Runner for the Network Microsegmentation Agent."""

    def __init__(
        self,
        topology_scanner: Any | None = None,
        flow_analyzer: Any | None = None,
        policy_engine: Any | None = None,
        deployment_manager: Any | None = None,
        metrics_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = NetworkMicrosegmentationToolkit(
            topology_scanner=topology_scanner,
            flow_analyzer=flow_analyzer,
            policy_engine=policy_engine,
            deployment_manager=deployment_manager,
            metrics_store=metrics_store,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_network_microsegmentation_graph()
        self._app = graph.compile()
        self._results: dict[str, NetworkMicrosegmentationState] = {}
        logger.info("nms_runner.initialized")

    async def segment(
        self,
        network_scope: str,
        segmentation_type: str = "zero_trust",
        target_zones: list[str] | None = None,
        enforcement_mode: str = "monitor",
        tenant_id: str = "",
    ) -> NetworkMicrosegmentationState:
        """Run a network microsegmentation workflow."""
        request_id = f"nms-{uuid4().hex[:12]}"

        initial_state = NetworkMicrosegmentationState(
            request_id=request_id,
            tenant_id=tenant_id,
            network_scope=network_scope,
            segmentation_type=SegmentationType(segmentation_type),
            target_zones=target_zones or [],
            enforcement_mode=enforcement_mode,
        )

        logger.info(
            "nms_runner.starting",
            request_id=request_id,
            scope=network_scope,
            type=segmentation_type,
            zones=len(target_zones or []),
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": ("network_microsegmentation"),
                    },
                },
            )
            final = NetworkMicrosegmentationState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "nms_runner.completed",
                request_id=request_id,
                nodes=final.total_nodes,
                flows=final.total_flows,
                policies=final.policies_generated,
                deployed=final.policies_deployed,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "nms_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = NetworkMicrosegmentationState(
                request_id=request_id,
                tenant_id=tenant_id,
                network_scope=network_scope,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> NetworkMicrosegmentationState | None:
        """Retrieve a cached segmentation result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all segmentation results as summaries."""
        return [
            {
                "request_id": rid,
                "scope": s.network_scope,
                "type": s.segmentation_type.value,
                "nodes": s.total_nodes,
                "flows": s.total_flows,
                "policies": s.policies_generated,
                "deployed": s.policies_deployed,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
