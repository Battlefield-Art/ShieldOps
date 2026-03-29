"""Secrets in Code Detector Agent — Entry point and lifecycle management."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from .graph import build_graph
from .tools import SecretsInCodeDetectorToolkit

logger = structlog.get_logger()


class SecretsInCodeDetectorRunner:
    """Runs the Secrets in Code Detector agent workflow."""

    def __init__(
        self,
        git_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecretsInCodeDetectorToolkit(
            git_client=git_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("secrets_detector_runner.init")

    async def scan(
        self,
        tenant_id: str,
        scan_targets: list[str] | None = None,
    ) -> dict[str, Any]:
        """Execute the full secrets detection workflow."""
        targets = scan_targets or []
        request_id = str(uuid.uuid4())[:12]
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "scan_targets": targets,
            "reasoning_chain": [],
        }
        logger.info(
            "secrets_detector_runner.scan",
            request_id=request_id,
            target_count=len(targets),
        )
        start = time.time()
        try:
            result = await self._app.ainvoke(initial_state)
            result["session_duration_ms"] = (time.time() - start) * 1000
            if self._repository:
                await self._repository.save_scan_run(result)
            return result
        except Exception:
            logger.exception("secrets_detector_runner.scan.error")
            raise
