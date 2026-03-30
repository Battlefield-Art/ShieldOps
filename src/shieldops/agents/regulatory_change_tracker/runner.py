"""Regulatory Change Tracker Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .nodes import set_toolkit
from .tools import RegulatoryChangeTrackerToolkit

logger = structlog.get_logger()


class RegulatoryChangeTrackerRunner:
    """Runs the Regulatory Change Tracker workflow."""

    def __init__(
        self,
        reg_feed: Any | None = None,
        control_store: Any | None = None,
        notifier: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = RegulatoryChangeTrackerToolkit(
            reg_feed=reg_feed,
            control_store=control_store,
            notifier=notifier,
        )
        set_toolkit(self._toolkit)
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("rct_runner.init")

    async def execute(
        self,
        regulations: list[str] | None = None,
        tenant_id: str = "default",
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute regulatory change tracking."""
        if regulations is None:
            regulations = [
                "gdpr",
                "ccpa",
                "hipaa",
                "pci_dss",
                "sox",
                "nist",
            ]

        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "regulations": regulations,
            "reasoning_chain": [],
        }

        logger.info(
            "rct_runner.execute",
            regulations=regulations,
        )
        try:
            result = await self._app.ainvoke(
                initial_state,
            )
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("rct_runner.execute.error")
            raise

    async def get_result(
        self,
        request_id: str,
    ) -> dict[str, Any] | None:
        """Retrieve a stored result by request ID."""
        if self._repository:
            return await self._repository.get(
                request_id,
            )
        return None

    async def list_results(
        self,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """List recent tracking results."""
        if self._repository:
            return await self._repository.list(
                limit=limit,
            )
        return []

    async def _persist(
        self,
        result: dict[str, Any],
    ) -> None:
        if self._repository:
            await self._repository.save(result)
