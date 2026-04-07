"""Compliance Drift Monitor runner — entry point for execution."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.compliance_drift_monitor.graph import (
    create_compliance_drift_monitor_graph,
)
from shieldops.agents.compliance_drift_monitor.models import (
    ComplianceDriftMonitorState,
)
from shieldops.agents.compliance_drift_monitor.nodes import (
    set_toolkit,
)
from shieldops.agents.compliance_drift_monitor.tools import (
    ComplianceDriftMonitorToolkit,
)
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class ComplianceDriftMonitorRunner:
    """Runner for the Compliance Drift Monitor Agent."""

    def __init__(
        self,
        compliance_client: Any | None = None,
        scanner_client: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ComplianceDriftMonitorToolkit(
            compliance_client=compliance_client,
            scanner_client=scanner_client,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_compliance_drift_monitor_graph()
        self._app = graph.compile()
        self._results: dict[str, ComplianceDriftMonitorState] = {}
        logger.info("cdm_runner.initialized")

    @enforced("compliance_drift_monitor")
    async def run(
        self,
        request_id: str,
        tenant_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> ComplianceDriftMonitorState:
        """Run compliance drift monitor workflow."""
        sid = f"cdm-{uuid4().hex[:12]}"
        initial = ComplianceDriftMonitorState(
            request_id=request_id,
            tenant_id=tenant_id,
            config=config or {},
        )

        logger.info(
            "cdm_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "compliance_drift_monitor",
                    },
                },
            )
            final = ComplianceDriftMonitorState.model_validate(result)
            self._results[sid] = final

            logger.info(
                "cdm_runner.completed",
                session_id=sid,
                baselines=len(final.baselines),
                drifts=len(final.drift_findings),
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "cdm_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err_state = ComplianceDriftMonitorState(
                request_id=request_id,
                tenant_id=tenant_id,
                config=config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[sid] = err_state
            return err_state

    def get_result(
        self,
        session_id: str,
    ) -> ComplianceDriftMonitorState | None:
        """Retrieve a previous result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "baselines": len(s.baselines),
                "drifts": len(s.drift_findings),
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]
