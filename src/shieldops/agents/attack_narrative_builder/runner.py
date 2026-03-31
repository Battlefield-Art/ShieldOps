"""Attack Narrative Builder Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import AttackNarrativeBuilderToolkit

logger = structlog.get_logger()


class AttackNarrativeBuilderRunner:
    """Runs the Attack Narrative Builder workflow."""

    def __init__(
        self,
        siem_source: Any | None = None,
        mitre_api: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = AttackNarrativeBuilderToolkit(
            siem_source=siem_source,
            mitre_api=mitre_api,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        self._results: dict[str, dict[str, Any]] = {}
        logger.info("anb_runner.init")

    async def execute(
        self,
        tenant_id: str = "default",
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute attack narrative builder workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "anb_runner.execute",
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
            logger.exception("anb_runner.execute.error")
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
                "events": r.get(
                    "total_events_collected",
                    0,
                ),
                "phases": r.get(
                    "attack_phases_identified",
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
