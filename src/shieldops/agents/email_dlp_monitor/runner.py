"""Email DLP Monitor Agent — Entry point and lifecycle."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from .graph import build_graph
from .tools import EmailDLPMonitorToolkit

logger = structlog.get_logger()


class EmailDLPMonitorRunner:
    """Runs the Email DLP Monitor agent workflow."""

    def __init__(
        self,
        dlp_client: Any | None = None,
        policy_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = EmailDLPMonitorToolkit(
            dlp_client=dlp_client,
            policy_client=policy_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("email_dlp_monitor_runner.init")

    async def analyze(
        self,
        tenant_id: str,
    ) -> dict[str, Any]:
        """Execute the email DLP monitoring workflow."""
        request_id = str(uuid.uuid4())[:12]

        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "email_dlp_monitor_runner.analyze",
            request_id=request_id,
            tenant_id=tenant_id,
        )
        start = time.time()
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            result["session_duration_ms"] = (time.time() - start) * 1000
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception(
                "email_dlp_monitor_runner.error",
                request_id=request_id,
            )
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        if self._repository:
            await self._repository.save_analysis_run(result)
