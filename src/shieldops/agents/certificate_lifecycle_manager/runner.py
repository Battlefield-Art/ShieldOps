"""Certificate Lifecycle Manager Agent — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import CertificateLifecycleManagerToolkit

logger = structlog.get_logger()


class CertificateLifecycleManagerRunner:
    """Runs the Certificate Lifecycle Manager agent workflow."""

    def __init__(
        self,
        acme_client: Any | None = None,
        scanner_client: Any | None = None,
        vault_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = CertificateLifecycleManagerToolkit(
            acme_client=acme_client,
            scanner_client=scanner_client,
            vault_client=vault_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("cert_lifecycle_manager_runner.init")

    async def manage(
        self,
        tenant_id: str,
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute the full certificate lifecycle workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "cert_lifecycle_manager_runner.manage",
            request_id=request_id,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("cert_lifecycle_manager_runner.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist certificate lifecycle results."""
        if self._repository:
            await self._repository.save_cert_report(result)
