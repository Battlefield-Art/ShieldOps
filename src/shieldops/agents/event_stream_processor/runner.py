"""Event Stream Processor Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import EventStreamProcessorToolkit

logger = structlog.get_logger()


class EventStreamProcessorRunner:
    """Runs the Event Stream Processor workflow."""

    def __init__(
        self,
        kafka_client: Any | None = None,
        threat_intel_api: Any | None = None,
        siem_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = EventStreamProcessorToolkit(
            kafka_client=kafka_client,
            threat_intel_api=threat_intel_api,
            siem_client=siem_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        self._results: dict[str, dict[str, Any]] = {}
        logger.info("esp_runner.init")

    async def execute(
        self,
        tenant_id: str = "default",
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute the event stream processing workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "esp_runner.execute",
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
            logger.exception("esp_runner.execute.error")
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
                "events_processed": r.get(
                    "total_events_processed",
                    0,
                ),
                "correlations_fired": r.get(
                    "correlations_fired",
                    0,
                ),
                "routes_created": len(r.get("route_decisions", [])),
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
