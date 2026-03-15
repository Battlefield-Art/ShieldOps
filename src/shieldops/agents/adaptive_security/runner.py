"""Adaptive Security Agent — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .models import ThreatContext
from .tools import AdaptiveSecurityToolkit

logger = structlog.get_logger()


class AdaptiveSecurityRunner:
    """Runs the Adaptive Security agent workflow."""

    def __init__(
        self,
        siem_client: Any | None = None,
        metrics_store: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = AdaptiveSecurityToolkit(
            siem_client=siem_client,
            metrics_store=metrics_store,
            policy_engine=policy_engine,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("adaptive_security_runner.init")

    async def run(
        self,
        threat_context: ThreatContext | str = ThreatContext.NORMAL,
        window_hours: int = 24,
    ) -> dict[str, Any]:
        """Execute the full adaptive security workflow."""
        if isinstance(threat_context, str):
            threat_context = ThreatContext(threat_context)

        initial_state: dict[str, Any] = {
            "request_id": "",
            "threat_context": threat_context.value,
            "window_hours": window_hours,
            "reasoning_chain": [],
        }

        logger.info(
            "adaptive_security_runner.run",
            threat_context=threat_context.value,
            window_hours=window_hours,
        )
        try:
            result = await self._app.ainvoke(initial_state)
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("adaptive_security_runner.run.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist adaptive security results."""
        if self._repository:
            await self._repository.save_adaptive_security_run(result)
