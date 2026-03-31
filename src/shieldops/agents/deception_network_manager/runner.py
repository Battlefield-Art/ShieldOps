"""Deception Network Manager Agent runner — entry point
for executing deception campaigns."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.deception_network_manager.graph import (
    create_deception_network_manager_graph,
)
from shieldops.agents.deception_network_manager.models import (
    DeceptionNetworkManagerState,
    DecoyType,
)
from shieldops.agents.deception_network_manager.nodes import (
    set_toolkit,
)
from shieldops.agents.deception_network_manager.tools import (
    DeceptionNetworkManagerToolkit,
)

logger = structlog.get_logger()


class DeceptionNetworkManagerRunner:
    """Runner for the Deception Network Manager Agent."""

    def __init__(
        self,
        deception_platform: Any | None = None,
        threat_intel: Any | None = None,
        network_monitor: Any | None = None,
        ioc_store: Any | None = None,
        mitre_mapper: Any | None = None,
        metrics_collector: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = DeceptionNetworkManagerToolkit(
            deception_platform=deception_platform,
            threat_intel=threat_intel,
            network_monitor=network_monitor,
            ioc_store=ioc_store,
            mitre_mapper=mitre_mapper,
            metrics_collector=metrics_collector,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_deception_network_manager_graph()
        self._app = graph.compile()
        self._results: dict[str, DeceptionNetworkManagerState] = {}
        logger.info("dnm_runner.initialized")

    async def orchestrate(
        self,
        network_segments: list[str] | None = None,
        decoy_types: list[str] | None = None,
        scope: dict[str, Any] | None = None,
        tenant_id: str = "",
    ) -> DeceptionNetworkManagerState:
        """Run a deception network management campaign."""
        request_id = f"dnm-{uuid4().hex[:12]}"

        types = [DecoyType(t) for t in (decoy_types or []) if t in DecoyType.__members__.values()]

        initial_state = DeceptionNetworkManagerState(
            request_id=request_id,
            tenant_id=tenant_id,
            network_segments=network_segments or [],
            decoy_types=types,
            scope=scope or {},
        )

        logger.info(
            "dnm_runner.starting",
            request_id=request_id,
            segments=len(initial_state.network_segments),
            types=len(types),
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "deception_network_manager",
                    },
                },
            )
            final = DeceptionNetworkManagerState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "dnm_runner.completed",
                request_id=request_id,
                interactions=final.total_interactions,
                attackers=final.unique_attackers,
                high_risk=final.high_risk_count,
                iocs=final.iocs_generated,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "dnm_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = DeceptionNetworkManagerState(
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
    ) -> DeceptionNetworkManagerState | None:
        """Retrieve a cached campaign result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all campaign results as summaries."""
        return [
            {
                "request_id": rid,
                "interactions": s.total_interactions,
                "attackers": s.unique_attackers,
                "high_risk": s.high_risk_count,
                "iocs": s.iocs_generated,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
