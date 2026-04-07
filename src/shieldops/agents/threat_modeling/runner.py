"""Threat Modeling Agent — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from shieldops.licensing.enforce import enforced

from .graph import build_graph
from .tools import ThreatModelingToolkit

logger = structlog.get_logger()


class ThreatModelingRunner:
    """Runs the Threat Modeling agent workflow."""

    def __init__(
        self,
        rba_client: Any | None = None,
        architecture_registry: Any | None = None,
        threat_intel: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ThreatModelingToolkit(
            rba_client=rba_client,
            architecture_registry=architecture_registry,
            threat_intel=threat_intel,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("threat_modeling_runner.init")

    @enforced("threat_modeling")
    async def run(
        self,
        request_id: str = "",
        target_service: str = "default",
    ) -> dict[str, Any]:
        """Execute the full threat modeling workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "target_service": target_service,
            "reasoning_chain": [],
        }

        logger.info(
            "threat_modeling_runner.run",
            request_id=request_id,
            target_service=target_service,
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("threat_modeling_runner.run.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist threat modeling results."""
        if self._repository:
            await self._repository.save_threat_model(result)
