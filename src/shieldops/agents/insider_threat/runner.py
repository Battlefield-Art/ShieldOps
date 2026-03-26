"""Insider Threat Detection Agent — Entry point and lifecycle management."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from .graph import build_graph
from .tools import InsiderThreatToolkit

logger = structlog.get_logger()


class InsiderThreatRunner:
    """Runs the Insider Threat Detection workflow."""

    def __init__(
        self,
        identity_provider: Any | None = None,
        hr_system: Any | None = None,
        dlp_engine: Any | None = None,
        code_repo_connector: Any | None = None,
        ai_tool_monitor: Any | None = None,
        access_log_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = InsiderThreatToolkit(
            identity_provider=identity_provider,
            hr_system=hr_system,
            dlp_engine=dlp_engine,
            code_repo_connector=code_repo_connector,
            ai_tool_monitor=ai_tool_monitor,
            access_log_store=access_log_store,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("insider_threat_runner.init")

    async def detect(
        self,
        tenant_id: str,
        time_window_hours: int = 24,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute the full insider threat detection workflow.

        Args:
            tenant_id: The tenant to scan.
            time_window_hours: Hours back to analyze.
            context: Optional additional context.

        Returns:
            Final state dict with deviations, scores,
            and investigations.
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
            "insider_threat_runner.detect",
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
            logger.exception("insider_threat_runner.detect.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist detection results."""
        if self._repository:
            await self._repository.save_detection_run(result)
