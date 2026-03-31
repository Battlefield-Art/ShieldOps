"""SaaS Security Posture Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import SaaSSecurityPostureToolkit

logger = structlog.get_logger()


class SaaSSecurityPostureRunner:
    """Runs the SaaS Security Posture workflow."""

    def __init__(
        self,
        saas_api: Any | None = None,
        identity_provider: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SaaSSecurityPostureToolkit(
            saas_api=saas_api,
            identity_provider=identity_provider,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        self._results: dict[str, dict[str, Any]] = {}
        logger.info("ssp_runner.init")

    async def execute(
        self,
        tenant_id: str = "default",
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute SaaS security posture workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "ssp_runner.execute",
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
            logger.exception("ssp_runner.execute.error")
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
                "total_apps": r.get("total_apps", 0),
                "misconfigs_found": r.get(
                    "misconfigs_found",
                    0,
                ),
                "high_risk_apps": r.get(
                    "high_risk_apps",
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
