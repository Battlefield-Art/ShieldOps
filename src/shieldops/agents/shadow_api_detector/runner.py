"""Shadow API Detector Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import ShadowAPIDetectorToolkit

logger = structlog.get_logger()


class ShadowAPIDetectorRunner:
    """Runs the Shadow API Detector workflow."""

    def __init__(
        self,
        traffic_source: Any | None = None,
        api_registry: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ShadowAPIDetectorToolkit(
            traffic_source=traffic_source,
            api_registry=api_registry,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        self._results: dict[str, dict[str, Any]] = {}
        logger.info("sad_runner.init")

    async def execute(
        self,
        tenant_id: str = "default",
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute shadow API detection workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "sad_runner.execute",
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
            logger.exception("sad_runner.execute.error")
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
                "shadow_apis": r.get(
                    "shadow_apis_found",
                    0,
                ),
                "endpoints": r.get(
                    "total_endpoints_scanned",
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
