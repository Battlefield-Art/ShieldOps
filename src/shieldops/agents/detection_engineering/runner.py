"""Detection Engineering Agent — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import DetectionEngineeringToolkit

logger = structlog.get_logger()


class DetectionEngineeringRunner:
    """Runs the Detection Engineering agent workflow."""

    def __init__(
        self,
        siem_client: Any | None = None,
        mitre_client: Any | None = None,
        rule_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = DetectionEngineeringToolkit(
            siem_client=siem_client,
            mitre_client=mitre_client,
            rule_store=rule_store,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("detection_engineering_runner.init")

    async def run(
        self,
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute the full detection engineering workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "reasoning_chain": [],
        }

        logger.info(
            "detection_engineering_runner.run",
            request_id=request_id,
        )
        try:
            result = await self._app.ainvoke(initial_state)
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("detection_engineering_runner.run.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist detection engineering results."""
        if self._repository:
            await self._repository.save_detection_engineering_run(result)
