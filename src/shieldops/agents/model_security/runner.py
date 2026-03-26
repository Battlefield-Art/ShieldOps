"""Model Security Agent — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import ModelSecurityToolkit

logger = structlog.get_logger()


class ModelSecurityRunner:
    """Runs the Model Security agent workflow."""

    def __init__(
        self,
        model_registry_client: Any | None = None,
        provenance_service: Any | None = None,
        scanning_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ModelSecurityToolkit(
            model_registry_client=model_registry_client,
            provenance_service=provenance_service,
            scanning_engine=scanning_engine,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("model_security_runner.init")

    async def scan(
        self,
        tenant_id: str = "",
        request_id: str = "",
        target_models: list[str] | None = None,
    ) -> dict[str, Any]:
        """Execute the full model security scan workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "target_models": target_models or [],
            "reasoning_chain": [],
        }

        logger.info(
            "model_security_runner.scan",
            tenant_id=tenant_id,
            request_id=request_id,
            target_count=len(target_models or []),
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("model_security_runner.scan.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist model security scan results."""
        if self._repository:
            await self._repository.save_model_security_scan(result)
