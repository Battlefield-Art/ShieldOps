"""Data Retention Enforcer Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .nodes import set_toolkit
from .tools import DataRetentionEnforcerToolkit

logger = structlog.get_logger()


class DataRetentionEnforcerRunner:
    """Runs the Data Retention Enforcer workflow."""

    def __init__(
        self,
        data_catalog: Any | None = None,
        deletion_api: Any | None = None,
        legal_hold_api: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = DataRetentionEnforcerToolkit(
            data_catalog=data_catalog,
            deletion_api=deletion_api,
            legal_hold_api=legal_hold_api,
        )
        set_toolkit(self._toolkit)
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("dre_runner.init")

    async def execute(
        self,
        tenant_id: str = "default",
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute data retention enforcement."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "dre_runner.execute",
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial_state,
            )
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("dre_runner.execute.error")
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
        """List recent enforcement results."""
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
