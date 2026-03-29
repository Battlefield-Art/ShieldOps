"""Phishing Email Analyzer Agent — Entry point and lifecycle."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from .graph import build_graph
from .tools import PhishingEmailAnalyzerToolkit

logger = structlog.get_logger()


class PhishingEmailAnalyzerRunner:
    """Runs the Phishing Email Analyzer agent workflow."""

    def __init__(
        self,
        url_scanner: Any | None = None,
        reputation_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = PhishingEmailAnalyzerToolkit(
            url_scanner=url_scanner,
            reputation_client=reputation_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("phishing_email_analyzer_runner.init")

    async def analyze(
        self,
        tenant_id: str,
        emails: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Execute the phishing analysis workflow."""
        emails = emails or []
        request_id = str(uuid.uuid4())[:12]

        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "emails": emails,
            "reasoning_chain": [],
        }

        logger.info(
            "phishing_email_analyzer_runner.analyze",
            request_id=request_id,
            tenant_id=tenant_id,
            email_count=len(emails),
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
                "phishing_email_analyzer_runner.error",
                request_id=request_id,
            )
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        if self._repository:
            await self._repository.save_analysis_run(result)
