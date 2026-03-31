"""Security Change Manager Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import SecurityChangeManagerToolkit

logger = structlog.get_logger()


class SecurityChangeManagerRunner:
    """Runs the Security Change Manager workflow."""

    def __init__(
        self,
        change_source: Any | None = None,
        approval_api: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecurityChangeManagerToolkit(
            change_source=change_source,
            approval_api=approval_api,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        self._results: dict[str, dict[str, Any]] = {}
        logger.info("scm_runner.init")

    async def execute(
        self,
        tenant_id: str = "default",
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute security change management workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "scm_runner.execute",
            request_id=request_id,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial_state,  # type: ignore[arg-type]
            )
            self._results[request_id] = result
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("scm_runner.execute.error")
            raise

    def get_result(
        self,
        request_id: str,
    ) -> dict[str, Any] | None:
        """Retrieve a cached result by request ID."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all cached results."""
        return [
            {
                "request_id": rid,
                "tenant_id": r.get("tenant_id", ""),
                "changes": r.get(
                    "total_changes_processed",
                    0,
                ),
                "approved": r.get(
                    "changes_approved",
                    0,
                ),
                "error": r.get("error", ""),
            }
            for rid, r in self._results.items()
        ]

    async def _persist(
        self,
        result: dict[str, Any],
    ) -> None:
        if self._repository:
            await self._repository.save(result)
