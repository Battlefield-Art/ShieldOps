"""Automated Security Testing Agent — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import SecurityTestingToolkit

logger = structlog.get_logger()


class SecurityTestingRunner:
    """Runs the Automated Security Testing agent workflow."""

    def __init__(
        self,
        scanner_client: Any | None = None,
        config_client: Any | None = None,
        credential_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecurityTestingToolkit(
            scanner_client=scanner_client,
            config_client=config_client,
            credential_store=credential_store,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("security_testing_runner.init")

    async def run(
        self,
        request_id: str = "",
        targets: list[str] | None = None,
        categories: list[str] | None = None,
        exclusions: list[str] | None = None,
    ) -> dict[str, Any]:
        """Execute the full security testing workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "reasoning_chain": [],
        }
        if targets:
            initial_state["targets"] = targets
        if categories:
            initial_state["categories"] = categories
        if exclusions:
            initial_state["exclusions"] = exclusions

        logger.info(
            "security_testing_runner.run",
            request_id=request_id,
        )
        try:
            result = await self._app.ainvoke(initial_state)
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("security_testing_runner.run.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist security testing results."""
        if self._repository:
            await self._repository.save_security_testing_run(result)
