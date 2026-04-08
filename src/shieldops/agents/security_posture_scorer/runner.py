"""Security Posture Scorer Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from shieldops.licensing.enforce import enforced

from .graph import build_graph
from .tools import SecurityPostureScorerToolkit

logger = structlog.get_logger()


class SecurityPostureScorerRunner:
    """Runs the Security Posture Scorer workflow."""

    def __init__(
        self,
        signal_sources: Any | None = None,
        benchmark_api: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecurityPostureScorerToolkit(
            signal_sources=signal_sources,
            benchmark_api=benchmark_api,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        self._results: dict[str, dict[str, Any]] = {}
        logger.info("sps_runner.init")

    @enforced("security_posture_scorer")
    async def execute(
        self,
        tenant_id: str = "default",
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute security posture scoring workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "sps_runner.execute",
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
            logger.exception("sps_runner.execute.error")
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
                "overall_score": r.get(
                    "overall_score",
                    0.0,
                ),
                "tier": r.get(
                    "overall_tier",
                    "",
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
