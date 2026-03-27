"""Phishing Simulator Agent runner — entry point."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.phishing_simulator.graph import (
    build_graph,
)
from shieldops.agents.phishing_simulator.models import (
    PhishingSimulatorState,
)
from shieldops.agents.phishing_simulator.tools import (
    PhishingSimulatorToolkit,
)

logger = structlog.get_logger()


class PhishingSimulatorRunner:
    """Runner for the Phishing Simulator Agent."""

    def __init__(
        self,
        email_client: Any | None = None,
        hr_directory: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = PhishingSimulatorToolkit(
            email_client=email_client,
            hr_directory=hr_directory,
            policy_engine=policy_engine,
            repository=repository,
        )
        graph = build_graph(self._toolkit)
        self._app = graph.compile()
        self._results: dict[str, PhishingSimulatorState] = {}
        logger.info("phishing_simulator_runner.initialized")

    async def simulate(
        self,
        tenant_id: str,
        campaign_type: str = "credential_harvest",
        target_departments: list[str] | None = None,
        target_roles: list[str] | None = None,
    ) -> PhishingSimulatorState:
        """Run a phishing simulation campaign."""
        session_id = f"phs-{uuid4().hex[:12]}"

        initial = PhishingSimulatorState(
            request_id=session_id,
            tenant_id=tenant_id,
            campaign_type=campaign_type,
            target_departments=(target_departments or ["engineering"]),
            target_roles=target_roles or [],
        )

        logger.info(
            "phishing_simulator_runner.starting",
            session_id=session_id,
            tenant_id=tenant_id,
            campaign_type=campaign_type,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),
                config={
                    "metadata": {
                        "session_id": session_id,
                        "agent": "phishing_simulator",
                    }
                },
            )
            final = PhishingSimulatorState.model_validate(result)
            self._results[session_id] = final
            logger.info(
                "phishing_simulator_runner.completed",
                session_id=session_id,
                click_rate=final.click_rate,
                report_rate=final.report_rate,
                targets=len(final.targets_selected),
            )
            return final

        except Exception as e:
            logger.error(
                "phishing_simulator_runner.failed",
                session_id=session_id,
                error=str(e),
            )
            err = PhishingSimulatorState(
                request_id=session_id,
                tenant_id=tenant_id,
                error=str(e),
            )
            self._results[session_id] = err
            return err

    def get_result(self, session_id: str) -> PhishingSimulatorState | None:
        """Get a previous simulation result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all simulation results."""
        return [
            {
                "session_id": sid,
                "tenant_id": s.tenant_id,
                "type": s.campaign_type,
                "click_rate": s.click_rate,
                "report_rate": s.report_rate,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]
