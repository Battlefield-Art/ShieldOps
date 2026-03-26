"""Agentic MDR runner — entry point for machine-speed MDR."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.agentic_mdr.graph import (
    create_agentic_mdr_graph,
)
from shieldops.agents.agentic_mdr.models import (
    AgenticMDRState,
)
from shieldops.agents.agentic_mdr.nodes import (
    set_toolkit,
)
from shieldops.agents.agentic_mdr.tools import (
    AgenticMDRToolkit,
)

logger = structlog.get_logger()


class AgenticMDRRunner:
    """Runner for the Agentic MDR Agent.

    Provides a high-level ``respond()`` method that
    accepts raw alerts from any vendor and drives
    the full ingest -> triage -> investigate -> respond
    -> validate -> report pipeline at machine speed.
    """

    def __init__(
        self,
        crowdstrike_client: Any | None = None,
        defender_client: Any | None = None,
        wiz_client: Any | None = None,
        splunk_client: Any | None = None,
        elastic_client: Any | None = None,
        threat_intel: Any | None = None,
        policy_engine: Any | None = None,
        metrics_recorder: Any | None = None,
        learning_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = AgenticMDRToolkit(
            crowdstrike_client=crowdstrike_client,
            defender_client=defender_client,
            wiz_client=wiz_client,
            splunk_client=splunk_client,
            elastic_client=elastic_client,
            threat_intel=threat_intel,
            policy_engine=policy_engine,
            metrics_recorder=metrics_recorder,
            learning_store=learning_store,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_agentic_mdr_graph()
        self._app = graph.compile()
        self._results: dict[str, AgenticMDRState] = {}
        logger.info("agentic_mdr_runner.initialized")

    async def respond(
        self,
        tenant_id: str,
        alerts: list[dict[str, Any]],
        vendors: list[str] | None = None,
        time_range_minutes: int = 60,
    ) -> AgenticMDRState:
        """Run the full MDR pipeline on incoming alerts.

        Args:
            tenant_id: Tenant identifier.
            alerts: Raw alert dicts from any vendor.
            vendors: Vendor sources to poll (if alerts
                is empty, will pull from these vendors).
            time_range_minutes: Lookback window for
                vendor polling.

        Returns:
            Final AgenticMDRState with report, metrics,
            and closed-loop improvements.
        """
        session_id = f"mdr-{uuid4().hex[:12]}"
        initial = AgenticMDRState(
            tenant_id=tenant_id,
            session_id=session_id,
            raw_alerts=alerts,
            vendor_sources=vendors
            or [
                "crowdstrike",
                "defender",
                "wiz",
                "splunk",
                "elastic",
            ],
        )

        logger.info(
            "agentic_mdr_runner.respond",
            session_id=session_id,
            tenant_id=tenant_id,
            alert_count=len(alerts),
        )

        return await self._run(session_id, initial)

    async def sweep(
        self,
        tenant_id: str,
        vendors: list[str] | None = None,
        time_range_minutes: int = 60,
    ) -> AgenticMDRState:
        """Scheduled cross-vendor sweep (no pre-supplied alerts)."""
        session_id = f"mdr-{uuid4().hex[:12]}"
        initial = AgenticMDRState(
            tenant_id=tenant_id,
            session_id=session_id,
            vendor_sources=vendors
            or [
                "crowdstrike",
                "defender",
                "wiz",
                "splunk",
                "elastic",
            ],
        )

        logger.info(
            "agentic_mdr_runner.sweep",
            session_id=session_id,
            tenant_id=tenant_id,
        )

        return await self._run(session_id, initial)

    async def get_feedback(
        self,
    ) -> list[dict[str, Any]]:
        """Return closed-loop feedback ledger."""
        return self._toolkit.get_feedback_ledger()

    async def _run(
        self,
        session_id: str,
        initial: AgenticMDRState,
    ) -> AgenticMDRState:
        """Execute the Agentic MDR graph workflow."""
        try:
            result_dict = await self._app.ainvoke(
                initial.model_dump(),
                config={
                    "metadata": {
                        "session_id": session_id,
                        "agent": "agentic_mdr",
                    }
                },
            )
            final = AgenticMDRState.model_validate(result_dict)
            self._results[session_id] = final

            logger.info(
                "agentic_mdr_runner.completed",
                session_id=session_id,
                alerts=final.alert_count,
                findings=len(final.findings),
                actions=len(final.response_actions),
                mttr=final.mean_time_to_respond_seconds,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "agentic_mdr_runner.failed",
                session_id=session_id,
                error=str(e),
            )
            error_state = AgenticMDRState(
                tenant_id=initial.tenant_id,
                session_id=session_id,
                vendor_sources=initial.vendor_sources,
                error=str(e),
                current_stage="failed",
            )
            self._results[session_id] = error_state
            return error_state

    def get_result(self, session_id: str) -> AgenticMDRState | None:
        """Retrieve a previous run result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all run results."""
        return [
            {
                "session_id": sid,
                "tenant_id": s.tenant_id,
                "alert_count": s.alert_count,
                "findings": len(s.findings),
                "actions": len(s.response_actions),
                "mttr": s.mean_time_to_respond_seconds,
                "current_stage": s.current_stage,
                "duration_ms": s.session_duration_ms,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]
