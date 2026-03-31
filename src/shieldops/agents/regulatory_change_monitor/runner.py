"""Regulatory Change Monitor Agent runner — entry point
for executing regulatory change tracking scans."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.regulatory_change_monitor.graph import (
    create_regulatory_change_monitor_graph,
)
from shieldops.agents.regulatory_change_monitor.models import (
    RegulatoryChangeMonitorState,
    RegulatoryFramework,
)
from shieldops.agents.regulatory_change_monitor.nodes import (
    set_toolkit,
)
from shieldops.agents.regulatory_change_monitor.tools import (
    RegulatoryChangeMonitorToolkit,
)

logger = structlog.get_logger()


class RegulatoryChangeMonitorRunner:
    """Runner for the Regulatory Change Monitor Agent."""

    def __init__(
        self,
        feed_client: Any | None = None,
        compliance_db: Any | None = None,
        control_catalog: Any | None = None,
        grc_platform: Any | None = None,
        action_tracker: Any | None = None,
        metrics_store: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = RegulatoryChangeMonitorToolkit(
            feed_client=feed_client,
            compliance_db=compliance_db,
            control_catalog=control_catalog,
            grc_platform=grc_platform,
            action_tracker=action_tracker,
            metrics_store=metrics_store,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_regulatory_change_monitor_graph()
        self._app = graph.compile()
        self._results: dict[str, RegulatoryChangeMonitorState] = {}
        logger.info("rcm_runner.initialized")

    async def monitor(
        self,
        scan_name: str,
        frameworks: list[str] | None = None,
        scope: dict[str, Any] | None = None,
        sources: list[str] | None = None,
        tenant_id: str = "",
    ) -> RegulatoryChangeMonitorState:
        """Run a regulatory change monitoring scan."""
        request_id = f"rcm-{uuid4().hex[:12]}"

        fw_list = [
            RegulatoryFramework(f)
            for f in (frameworks or [])
            if f in RegulatoryFramework.__members__.values()
        ]

        initial_state = RegulatoryChangeMonitorState(
            request_id=request_id,
            tenant_id=tenant_id,
            scan_name=scan_name,
            frameworks=fw_list,
            scope=scope or {},
            sources=sources or [],
        )

        logger.info(
            "rcm_runner.starting",
            request_id=request_id,
            scan_name=scan_name,
            frameworks=len(fw_list),
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": ("regulatory_change_monitor"),
                    },
                },
            )
            final = RegulatoryChangeMonitorState.model_validate(
                result,
            )
            self._results[request_id] = final

            logger.info(
                "rcm_runner.completed",
                request_id=request_id,
                total_changes=final.total_changes,
                critical=final.critical_changes,
                gaps=final.compliance_gaps,
                actions=final.actions_generated,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "rcm_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = RegulatoryChangeMonitorState(
                request_id=request_id,
                tenant_id=tenant_id,
                scan_name=scan_name,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> RegulatoryChangeMonitorState | None:
        """Retrieve a cached monitoring result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all monitoring results as summaries."""
        return [
            {
                "request_id": rid,
                "scan_name": s.scan_name,
                "total_changes": s.total_changes,
                "critical": s.critical_changes,
                "gaps": s.compliance_gaps,
                "actions": s.actions_generated,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
