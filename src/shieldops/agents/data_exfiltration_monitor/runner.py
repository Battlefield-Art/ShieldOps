"""Data Exfiltration Monitor runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.data_exfiltration_monitor.graph import (
    create_data_exfiltration_monitor_graph,
)
from shieldops.agents.data_exfiltration_monitor.models import (
    DataExfiltrationMonitorState,
)
from shieldops.agents.data_exfiltration_monitor.nodes import (
    set_toolkit,
)
from shieldops.agents.data_exfiltration_monitor.tools import (
    DataExfiltrationMonitorToolkit,
)

logger = structlog.get_logger()


class DataExfiltrationMonitorRunner:
    """Runner for the Data Exfiltration Monitor Agent."""

    def __init__(
        self,
        network_monitor: Any | None = None,
        usb_monitor: Any | None = None,
        cloud_monitor: Any | None = None,
        dlp_engine: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = DataExfiltrationMonitorToolkit(
            network_monitor=network_monitor,
            usb_monitor=usb_monitor,
            cloud_monitor=cloud_monitor,
            dlp_engine=dlp_engine,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_data_exfiltration_monitor_graph()
        self._app = graph.compile()
        self._results: dict[str, DataExfiltrationMonitorState] = {}
        logger.info("dem_runner.initialized")

    async def scan(
        self,
        request_id: str,
        tenant_id: str = "",
        monitor_config: dict[str, Any] | None = None,
    ) -> DataExfiltrationMonitorState:
        """Run data exfiltration monitoring workflow."""
        sid = f"dem-{uuid4().hex[:12]}"
        initial = DataExfiltrationMonitorState(
            request_id=request_id,
            tenant_id=tenant_id,
            monitor_config=monitor_config or {},
        )

        logger.info(
            "dem_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "data_exfiltration_monitor",
                    },
                },
            )
            final = DataExfiltrationMonitorState.model_validate(
                result,
            )
            self._results[sid] = final

            logger.info(
                "dem_runner.completed",
                session_id=sid,
                flows=len(final.data_flows),
                detections=final.exfil_count,
                blocked=final.blocked_count,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "dem_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err_state = DataExfiltrationMonitorState(
                request_id=request_id,
                tenant_id=tenant_id,
                monitor_config=monitor_config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[sid] = err_state
            return err_state

    def get_result(
        self,
        session_id: str,
    ) -> DataExfiltrationMonitorState | None:
        """Retrieve a previous scan result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all scan results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "tenant_id": s.tenant_id,
                "total_flows": len(s.data_flows),
                "channels": s.channel_count,
                "detections": s.exfil_count,
                "sensitive": s.sensitive_count,
                "blocked": s.blocked_count,
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]
