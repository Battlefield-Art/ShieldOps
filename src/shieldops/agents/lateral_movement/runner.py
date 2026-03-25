"""Lateral Movement Detector Agent — Entry point and lifecycle management."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from .graph import build_graph
from .tools import LateralMovementToolkit

logger = structlog.get_logger()


class LateralMovementRunner:
    """Runs the Lateral Movement Detector workflow."""

    def __init__(
        self,
        identity_store: Any | None = None,
        cloud_connectors: dict[str, Any] | None = None,
        response_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = LateralMovementToolkit(
            identity_store=identity_store,
            cloud_connectors=cloud_connectors,
            response_engine=response_engine,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("lateral_movement_runner.init")

    async def detect(
        self,
        tenant_id: str,
        time_window_hours: int = 24,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute the full lateral movement detection workflow.

        Args:
            tenant_id: The tenant to scan for lateral movement.
            time_window_hours: How many hours back to analyze (default 24).
            context: Optional additional context for the detection run.

        Returns:
            Final state dict with detected paths, assessments, and actions.
        """
        context = context or {}
        request_id = context.get("request_id", str(uuid.uuid4()))

        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "time_window_hours": time_window_hours,
            "reasoning_chain": [],
        }

        logger.info(
            "lateral_movement_runner.detect",
            tenant_id=tenant_id,
            time_window_hours=time_window_hours,
            request_id=request_id,
        )
        start = time.time()
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            duration_ms = (time.time() - start) * 1000
            if isinstance(result, dict):
                result["session_duration_ms"] = round(duration_ms, 2)
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("lateral_movement_runner.detect.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist detection results."""
        if self._repository:
            await self._repository.save_detection_run(result)
