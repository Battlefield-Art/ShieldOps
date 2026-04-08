"""Cloud Storage Scanner Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from shieldops.licensing.enforce import enforced

from .graph import build_graph
from .tools import CloudStorageScannerToolkit

logger = structlog.get_logger()


class CloudStorageScannerRunner:
    """Runs the Cloud Storage Scanner workflow."""

    def __init__(
        self,
        cloud_api: Any | None = None,
        scanner_api: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = CloudStorageScannerToolkit(
            cloud_api=cloud_api,
            scanner_api=scanner_api,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        self._results: dict[str, dict[str, Any]] = {}
        logger.info("css_runner.init")

    @enforced("cloud_storage_scanner")
    async def execute(
        self,
        tenant_id: str = "default",
        request_id: str = "",
        providers: list[str] | None = None,
    ) -> dict[str, Any]:
        """Execute storage scanning workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "target_providers": providers or [],
            "reasoning_chain": [],
        }

        logger.info(
            "css_runner.execute",
            request_id=request_id,
            tenant_id=tenant_id,
            providers=providers,
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
                "css_runner.execute.error",
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
                "total_buckets": r.get(
                    "total_buckets",
                    0,
                ),
                "total_findings": r.get(
                    "total_findings",
                    0,
                ),
                "critical_findings": r.get(
                    "critical_findings",
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
