"""DAST Runner Agent — Entry point and lifecycle management."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from .graph import build_graph
from .tools import DASTRunnerToolkit

logger = structlog.get_logger()


class DASTRunnerRunner:
    """Runs the DAST Runner agent workflow."""

    def __init__(
        self,
        http_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = DASTRunnerToolkit(http_client=http_client)
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("dast_runner_runner.init")

    async def scan(
        self,
        tenant_id: str,
        target_url: str = "",
        scan_scope: str = "full",
    ) -> dict[str, Any]:
        """Execute the full DAST scanning workflow."""
        request_id = str(uuid.uuid4())[:12]
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "target_url": target_url,
            "scan_scope": scan_scope,
            "reasoning_chain": [],
        }
        logger.info(
            "dast_runner_runner.scan",
            request_id=request_id,
            target_url=target_url,
        )
        start = time.time()
        try:
            result = await self._app.ainvoke(initial_state)
            result["session_duration_ms"] = (time.time() - start) * 1000
            if self._repository:
                await self._repository.save_scan_run(result)
            return result
        except Exception:
            logger.exception("dast_runner_runner.scan.error")
            raise
