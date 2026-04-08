"""Secret Rotation Manager Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from shieldops.licensing.enforce import enforced

from .graph import build_graph
from .tools import SecretRotationManagerToolkit

logger = structlog.get_logger()


class SecretRotationManagerRunner:
    """Runs the Secret Rotation Manager workflow."""

    def __init__(
        self,
        vault_client: Any | None = None,
        cloud_provider: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecretRotationManagerToolkit(
            vault_client=vault_client,
            cloud_provider=cloud_provider,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        self._results: dict[str, dict[str, Any]] = {}
        logger.info("srm_runner.init")

    @enforced("secret_rotation_manager")
    async def execute(
        self,
        tenant_id: str = "default",
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute secret rotation workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "srm_runner.execute",
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
            logger.exception("srm_runner.execute.error")
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
                "total_secrets": r.get(
                    "total_secrets",
                    0,
                ),
                "rotated": r.get("secrets_rotated", 0),
                "failed": r.get("secrets_failed", 0),
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
