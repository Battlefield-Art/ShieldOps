"""Spam Filter Manager Agent — Entry point and lifecycle."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from .graph import build_graph
from .tools import SpamFilterManagerToolkit

logger = structlog.get_logger()


class SpamFilterManagerRunner:
    """Runs the Spam Filter Manager agent workflow."""

    def __init__(
        self,
        filter_client: Any | None = None,
        quarantine_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SpamFilterManagerToolkit(
            filter_client=filter_client,
            quarantine_client=quarantine_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("spam_filter_manager_runner.init")

    async def analyze(
        self,
        tenant_id: str,
    ) -> dict[str, Any]:
        """Execute the spam filter management workflow."""
        request_id = str(uuid.uuid4())[:12]

        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "spam_filter_manager_runner.analyze",
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
                "spam_filter_manager_runner.error",
                request_id=request_id,
            )
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        if self._repository:
            await self._repository.save_analysis_run(result)
