"""Threat Response Agent — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import ThreatResponseToolkit

logger = structlog.get_logger()


class ThreatResponseRunner:
    """Runs the Threat Response agent workflow."""

    def __init__(
        self,
        soar_client: Any | None = None,
        edr_client: Any | None = None,
        firewall_client: Any | None = None,
        identity_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ThreatResponseToolkit(
            soar_client=soar_client,
            edr_client=edr_client,
            firewall_client=firewall_client,
            identity_client=identity_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("threat_response_runner.init")

    async def respond(
        self,
        tenant_id: str,
        threat_indicators: list[dict[str, Any]] | None = None,
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute the full threat response workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "threat_indicators": threat_indicators or [],
            "reasoning_chain": [],
        }

        logger.info(
            "threat_response_runner.respond",
            request_id=request_id,
            tenant_id=tenant_id,
            indicator_count=len(threat_indicators or []),
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("threat_response_runner.respond.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist threat response results."""
        if self._repository:
            await self._repository.save_threat_response(result)
