"""Serverless Security Agent — Entry point and lifecycle management."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from .graph import build_graph
from .tools import ServerlessSecurityToolkit

logger = structlog.get_logger()


class ServerlessSecurityRunner:
    """Runs the Serverless Security agent workflow."""

    def __init__(
        self,
        cloud_clients: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ServerlessSecurityToolkit(
            cloud_clients=cloud_clients,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("serverless_security_runner.init")

    async def scan(
        self,
        tenant_id: str,
        platforms: list[str] | None = None,
    ) -> dict[str, Any]:
        """Execute the full serverless security scan."""
        if platforms is None:
            platforms = [
                "aws_lambda",
                "gcp_cloud_functions",
                "azure_functions",
            ]

        request_id = str(uuid.uuid4())[:8]
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "platforms": platforms,
            "reasoning_chain": [],
            "session_start": time.time(),
        }

        logger.info(
            "serverless_security_runner.scan",
            request_id=request_id,
            tenant_id=tenant_id,
            platforms=platforms,
        )

        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._repository.save(result)
            return result
        except Exception:
            logger.exception("serverless_security_runner.scan.error")
            raise
