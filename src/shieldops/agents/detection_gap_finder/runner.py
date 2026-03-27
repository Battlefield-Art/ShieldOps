"""Detection Gap Finder Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import DetectionGapFinderToolkit

logger = structlog.get_logger()


class DetectionGapFinderRunner:
    """Runs the Detection Gap Finder agent workflow."""

    def __init__(
        self,
        siem_client: Any | None = None,
        simulation_engine: Any | None = None,
        detection_monitor: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = DetectionGapFinderToolkit(
            siem_client=siem_client,
            simulation_engine=simulation_engine,
            detection_monitor=detection_monitor,
            repository=repository,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info(
            "detection_gap_finder_runner.init",
        )

    async def find_gaps(
        self,
        tenant_id: str,
        request_id: str = "",
    ) -> dict[str, Any]:
        """Run detection gap finding for a tenant."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "detection_gap_finder_runner.find_gaps",
            request_id=request_id,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial_state,
            )  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception(
                "detection_gap_finder_runner.error",
            )
            raise

    async def _persist(
        self,
        result: dict[str, Any],
    ) -> None:
        """Persist gap finding results."""
        if self._repository:
            await self._repository.save(result)
