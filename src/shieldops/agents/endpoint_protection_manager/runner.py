"""Endpoint Protection Manager Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import EndpointProtectionManagerToolkit

logger = structlog.get_logger()


class EndpointProtectionManagerRunner:
    """Runs the Endpoint Protection Manager workflow."""

    def __init__(
        self,
        edr_api: Any | None = None,
        cmdb_api: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = EndpointProtectionManagerToolkit(
            edr_api=edr_api,
            cmdb_api=cmdb_api,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        self._results: dict[str, dict[str, Any]] = {}
        logger.info("epm_runner.init")

    async def execute(
        self,
        tenant_id: str = "default",
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute endpoint protection workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "epm_runner.execute",
            request_id=request_id,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial_state,
            )  # type: ignore[arg-type]
            self._results[request_id] = result
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("epm_runner.execute.error")
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
                "total_endpoints": r.get(
                    "total_endpoints",
                    0,
                ),
                "protected": r.get(
                    "protected_count",
                    0,
                ),
                "at_risk": r.get(
                    "at_risk_count",
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
