"""Incident Timeline Builder Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from shieldops.licensing.enforce import enforced

from .graph import build_graph
from .tools import IncidentTimelineBuilderToolkit

logger = structlog.get_logger()


class IncidentTimelineBuilderRunner:
    """Runs the Incident Timeline Builder workflow."""

    def __init__(
        self,
        siem_client: Any | None = None,
        edr_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = IncidentTimelineBuilderToolkit(
            siem_client=siem_client,
            edr_client=edr_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        self._results: dict[str, dict[str, Any]] = {}
        logger.info("itb_runner.init")

    @enforced("incident_timeline_builder")
    async def execute(
        self,
        incident_id: str = "INC-001",
        tenant_id: str = "default",
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute timeline reconstruction workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "incident_id": incident_id,
            "reasoning_chain": [],
        }

        logger.info(
            "itb_runner.execute",
            request_id=request_id,
            incident_id=incident_id,
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
            logger.exception(
                "itb_runner.execute.error",
            )
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
                "incident_id": r.get(
                    "incident_id",
                    "",
                ),
                "total_events": r.get(
                    "total_events",
                    0,
                ),
                "timeline_span": r.get(
                    "timeline_span_minutes",
                    0.0,
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
