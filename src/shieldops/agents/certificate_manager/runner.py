"""Certificate Manager Agent — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import CertificateManagerToolkit

logger = structlog.get_logger()


class CertificateManagerRunner:
    """Runs the Certificate Manager agent workflow."""

    def __init__(
        self,
        cert_store: Any | None = None,
        acme_client: Any | None = None,
        dns_client: Any | None = None,
        notification_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = CertificateManagerToolkit(
            cert_store=cert_store,
            acme_client=acme_client,
            dns_client=dns_client,
            notification_client=notification_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("certificate_manager_runner.init")

    async def manage(
        self,
        tenant_id: str,
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute the full certificate management workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "certificate_manager_runner.manage",
            request_id=request_id,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("certificate_manager_runner.manage.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist certificate management results."""
        if self._repository:
            await self._repository.save_cert_report(result)
