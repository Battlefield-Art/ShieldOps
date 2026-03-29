"""Container Image Scanner Agent — Entry point and lifecycle management."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from .graph import build_graph
from .tools import ContainerImageScannerToolkit

logger = structlog.get_logger()


class ContainerImageScannerRunner:
    """Runs the Container Image Scanner agent workflow."""

    def __init__(
        self,
        registry_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ContainerImageScannerToolkit(
            registry_client=registry_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("container_scanner_runner.init")

    async def scan(
        self,
        tenant_id: str,
        image_refs: list[str] | None = None,
    ) -> dict[str, Any]:
        """Execute the full container image scanning workflow."""
        refs = image_refs or []
        request_id = str(uuid.uuid4())[:12]
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "image_refs": refs,
            "reasoning_chain": [],
        }
        logger.info(
            "container_scanner_runner.scan",
            request_id=request_id,
            image_count=len(refs),
        )
        start = time.time()
        try:
            result = await self._app.ainvoke(initial_state)
            result["session_duration_ms"] = (time.time() - start) * 1000
            if self._repository:
                await self._repository.save_scan_run(result)
            return result
        except Exception:
            logger.exception("container_scanner_runner.scan.error")
            raise
