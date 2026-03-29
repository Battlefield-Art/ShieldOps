"""Cloud Audit Logger Agent — Entry point and lifecycle management."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from .graph import build_graph
from .tools import CloudAuditLoggerToolkit

logger = structlog.get_logger()


class CloudAuditLoggerRunner:
    """Runs the Cloud Audit Logger agent workflow."""

    def __init__(
        self,
        log_clients: Any | None = None,
        siem_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = CloudAuditLoggerToolkit(
            log_clients=log_clients,
            siem_client=siem_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("cloud_audit_logger_runner.init")

    async def analyze(
        self,
        tenant_id: str,
        sources: list[str] | None = None,
        time_range_hours: int = 24,
    ) -> dict[str, Any]:
        """Execute the full audit log analysis workflow."""
        if sources is None:
            sources = ["cloudtrail", "gcp_audit", "azure_activity"]

        request_id = str(uuid.uuid4())[:8]
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "sources": sources,
            "time_range_hours": time_range_hours,
            "reasoning_chain": [],
            "session_start": time.time(),
        }

        logger.info(
            "cloud_audit_logger_runner.analyze",
            request_id=request_id,
            tenant_id=tenant_id,
            sources=sources,
        )

        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._repository.save(result)
            return result
        except Exception:
            logger.exception("cloud_audit_logger_runner.analyze.error")
            raise
