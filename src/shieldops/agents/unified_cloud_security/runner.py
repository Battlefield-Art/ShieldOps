"""Unified Cloud Security Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import UnifiedCloudSecurityToolkit

logger = structlog.get_logger()


class UnifiedCloudSecurityRunner:
    """Runs the Unified Cloud Security workflow."""

    def __init__(
        self,
        aws_client: Any | None = None,
        gcp_client: Any | None = None,
        azure_client: Any | None = None,
        k8s_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = UnifiedCloudSecurityToolkit(
            aws_client=aws_client,
            gcp_client=gcp_client,
            azure_client=azure_client,
            k8s_client=k8s_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("cloud_sec_runner.init")

    async def secure(
        self,
        tenant_id: str = "default",
        providers: list[str] | None = None,
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute unified cloud security workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "providers": providers or ["aws"],
            "reasoning_chain": [],
        }

        logger.info(
            "cloud_sec_runner.secure",
            request_id=request_id,
            tenant_id=tenant_id,
            providers=providers,
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("cloud_sec_runner.secure.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        if self._repository:
            await self._repository.save_security(result)
