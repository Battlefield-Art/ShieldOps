"""Cloud Storage Scanner Agent — Entry point and lifecycle."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from .graph import build_graph
from .tools import CloudStorageScannerToolkit

logger = structlog.get_logger()


class CloudStorageScannerRunner:
    """Runs the Cloud Storage Scanner agent workflow."""

    def __init__(
        self,
        cloud_clients: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = CloudStorageScannerToolkit(
            cloud_clients=cloud_clients,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("cloud_storage_scanner_runner.init")

    async def scan(
        self,
        tenant_id: str,
        providers: list[str] | None = None,
    ) -> dict[str, Any]:
        """Execute the full storage security scan."""
        if providers is None:
            providers = ["s3", "gcs", "azure_blob"]

        request_id = str(uuid.uuid4())[:8]
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "providers": providers,
            "reasoning_chain": [],
            "session_start": time.time(),
        }

        logger.info(
            "cloud_storage_scanner_runner.scan",
            request_id=request_id,
            tenant_id=tenant_id,
        )

        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._repository.save(result)
            return result
        except Exception:
            logger.exception("cloud_storage_scanner_runner.error")
            raise
