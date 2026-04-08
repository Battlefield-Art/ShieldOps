"""FinOps Forecaster Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from shieldops.licensing.enforce import enforced

from .graph import build_graph
from .tools import FinopsForecasterToolkit

logger = structlog.get_logger()


class FinopsForecasterRunner:
    """Runs the FinOps Forecaster workflow."""

    def __init__(
        self,
        billing_api: Any | None = None,
        cloud_provider: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = FinopsForecasterToolkit(
            billing_api=billing_api,
            cloud_provider=cloud_provider,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        self._results: dict[str, dict[str, Any]] = {}
        logger.info("ff_runner.init")

    @enforced("finops_forecaster")
    async def execute(
        self,
        tenant_id: str = "default",
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute the forecasting workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "ff_runner.execute",
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
            logger.exception(
                "ff_runner.execute.error",
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
                "tenant_id": r.get(
                    "tenant_id",
                    "",
                ),
                "forecasted_spend": r.get(
                    "total_forecasted_spend",
                    0.0,
                ),
                "potential_savings": r.get(
                    "total_potential_savings",
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
