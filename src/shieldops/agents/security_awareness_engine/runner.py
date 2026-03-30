"""Security Awareness Engine Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import SecurityAwarenessEngineToolkit

logger = structlog.get_logger()


class SecurityAwarenessEngineRunner:
    """Runs the Security Awareness Engine agent workflow."""

    def __init__(
        self,
        lms_client: Any | None = None,
        phishing_client: Any | None = None,
        hr_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecurityAwarenessEngineToolkit(
            lms_client=lms_client,
            phishing_client=phishing_client,
            hr_client=hr_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("security_awareness_engine_runner.init")

    async def run(
        self,
        tenant_id: str,
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute the full awareness engine workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "security_awareness_engine_runner.run",
            request_id=request_id,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(initial_state)
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("security_awareness_engine_runner.run.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        if self._repository:
            await self._repository.save_awareness_report(result)
