"""Privilege Access Monitor Agent runner — entry point
for executing PAM audits and JIT enforcement."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.privilege_access_monitor.graph import (
    create_privilege_access_monitor_graph,
)
from shieldops.agents.privilege_access_monitor.models import (
    PrivilegeAccessMonitorState,
)
from shieldops.agents.privilege_access_monitor.nodes import (
    set_toolkit,
)
from shieldops.agents.privilege_access_monitor.tools import (
    PrivilegeAccessMonitorToolkit,
)

logger = structlog.get_logger()


class PrivilegeAccessMonitorRunner:
    """Runner for the Privilege Access Monitor Agent."""

    def __init__(
        self,
        pam_connector: Any | None = None,
        session_recorder: Any | None = None,
        identity_provider: Any | None = None,
        jit_engine: Any | None = None,
        risk_scorer: Any | None = None,
        metrics_recorder: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = PrivilegeAccessMonitorToolkit(
            pam_connector=pam_connector,
            session_recorder=session_recorder,
            identity_provider=identity_provider,
            jit_engine=jit_engine,
            risk_scorer=risk_scorer,
            metrics_recorder=metrics_recorder,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_privilege_access_monitor_graph()
        self._app = graph.compile()
        self._results: dict[str, PrivilegeAccessMonitorState] = {}
        logger.info("pam_runner.initialized")

    async def monitor(
        self,
        target_platforms: list[str] | None = None,
        scope: dict[str, Any] | None = None,
        audit_window_hours: int = 24,
        tenant_id: str = "",
    ) -> PrivilegeAccessMonitorState:
        """Run a privileged access monitoring audit."""
        request_id = f"pam-{uuid4().hex[:12]}"

        initial_state = PrivilegeAccessMonitorState(
            request_id=request_id,
            tenant_id=tenant_id,
            target_platforms=target_platforms or [],
            scope=scope or {},
            audit_window_hours=audit_window_hours,
        )

        logger.info(
            "pam_runner.starting",
            request_id=request_id,
            platforms=len(initial_state.target_platforms),
            window_hours=audit_window_hours,
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": ("privilege_access_monitor"),
                    },
                },
            )
            final = PrivilegeAccessMonitorState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "pam_runner.completed",
                request_id=request_id,
                total_accounts=final.total_accounts,
                abuse_detected=final.abuse_detected,
                high_risk=final.high_risk_count,
                jit_enforced=final.jit_enforced,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "pam_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = PrivilegeAccessMonitorState(
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
    ) -> PrivilegeAccessMonitorState | None:
        """Retrieve a cached monitoring result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all monitoring results as summaries."""
        return [
            {
                "request_id": rid,
                "total_accounts": s.total_accounts,
                "abuse_detected": s.abuse_detected,
                "high_risk": s.high_risk_count,
                "jit_enforced": s.jit_enforced,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
