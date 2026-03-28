"""Privilege Escalation Detector Agent — Entry point and lifecycle management."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from .graph import build_graph
from .tools import PrivilegeEscalationToolkit

logger = structlog.get_logger()


class PrivilegeEscalationDetectorRunner:
    """Runs the Privilege Escalation Detector workflow."""

    def __init__(
        self,
        identity_store: Any | None = None,
        cloud_connectors: dict[str, Any] | None = None,
        response_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = PrivilegeEscalationToolkit(
            identity_store=identity_store,
            cloud_connectors=cloud_connectors,
            response_engine=response_engine,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("privilege_escalation_detector_runner.init")

    async def detect(
        self,
        tenant_id: str,
        time_window_hours: int = 24,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute the full privilege escalation detection workflow.

        Args:
            tenant_id: The tenant to scan.
            time_window_hours: Hours back to analyze.
            context: Optional additional context.

        Returns:
            Final state dict with findings, assessments, actions.
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
            "privilege_escalation_detector_runner.detect",
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
            logger.exception("privilege_escalation_detector_runner.detect.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist detection results."""
        if self._repository:
            await self._repository.save_detection_run(result)
