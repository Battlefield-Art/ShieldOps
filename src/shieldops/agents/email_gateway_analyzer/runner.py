"""Email Gateway Analyzer Agent — Entry point and lifecycle."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from .graph import build_graph
from .tools import EmailGatewayAnalyzerToolkit

logger = structlog.get_logger()


class EmailGatewayAnalyzerRunner:
    """Runs the Email Gateway Analyzer agent workflow."""

    def __init__(
        self,
        dns_client: Any | None = None,
        reputation_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = EmailGatewayAnalyzerToolkit(
            dns_client=dns_client,
            reputation_client=reputation_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("email_gateway_analyzer_runner.init")

    async def analyze(
        self,
        tenant_id: str,
        domains: list[str] | None = None,
    ) -> dict[str, Any]:
        """Execute the email gateway analysis workflow."""
        domains = domains or []
        request_id = str(uuid.uuid4())[:12]

        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "domains": domains,
            "reasoning_chain": [],
        }

        logger.info(
            "email_gateway_analyzer_runner.analyze",
            request_id=request_id,
            tenant_id=tenant_id,
            domain_count=len(domains),
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
                "email_gateway_analyzer_runner.error",
                request_id=request_id,
            )
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        if self._repository:
            await self._repository.save_analysis_run(result)
