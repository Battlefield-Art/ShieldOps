"""Crypto Agility Manager Agent — Entry point and lifecycle management."""

from __future__ import annotations

import uuid
from typing import Any

import structlog

from .graph import build_graph
from .tools import CryptoAgilityManagerToolkit

logger = structlog.get_logger()


class CryptoAgilityManagerRunner:
    """Runs the Crypto Agility Manager agent workflow."""

    def __init__(
        self,
        crypto_store: Any | None = None,
        pqc_test_client: Any | None = None,
        config_client: Any | None = None,
        notification_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = CryptoAgilityManagerToolkit(
            crypto_store=crypto_store,
            pqc_test_client=pqc_test_client,
            config_client=config_client,
            notification_client=notification_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("crypto_agility_manager_runner.init")

    async def manage(
        self,
        tenant_id: str,
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute the full crypto agility management workflow."""
        if not request_id:
            request_id = f"cam-{uuid.uuid4().hex[:12]}"

        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "crypto_agility_manager_runner.manage",
            request_id=request_id,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("crypto_agility_manager_runner.manage.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist crypto agility management results."""
        if self._repository:
            await self._repository.save_crypto_agility_report(result)
