"""Security Posture Manager Agent — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import SecurityPostureToolkit

logger = structlog.get_logger()


class SecurityPostureRunner:
    """Runs the Security Posture Manager agent workflow."""

    def __init__(
        self,
        rba_client: Any | None = None,
        compliance_store: Any | None = None,
        vuln_scanner: Any | None = None,
        threat_intel: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecurityPostureToolkit(
            rba_client=rba_client,
            compliance_store=compliance_store,
            vuln_scanner=vuln_scanner,
            threat_intel=threat_intel,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("security_posture_runner.init")

    async def run(
        self,
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute the full security posture assessment workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "reasoning_chain": [],
        }

        logger.info(
            "security_posture_runner.run",
            request_id=request_id,
        )
        try:
            result = await self._app.ainvoke(initial_state)
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("security_posture_runner.run.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist security posture results."""
        if self._repository:
            await self._repository.save_posture_assessment(result)
