"""Privacy Consent Manager Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from shieldops.licensing.enforce import enforced

from .graph import build_graph
from .nodes import set_toolkit
from .tools import PrivacyConsentManagerToolkit

logger = structlog.get_logger()


class PrivacyConsentManagerRunner:
    """Runs the Privacy Consent Manager workflow."""

    def __init__(
        self,
        consent_store: Any | None = None,
        preference_api: Any | None = None,
        audit_logger: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = PrivacyConsentManagerToolkit(
            consent_store=consent_store,
            preference_api=preference_api,
            audit_logger=audit_logger,
        )
        set_toolkit(self._toolkit)
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("pcm_runner.init")

    @enforced("privacy_consent_manager")
    async def execute(
        self,
        tenant_id: str = "default",
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute consent management workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "pcm_runner.execute",
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(
                initial_state,
            )
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("pcm_runner.execute.error")
            raise

    async def get_result(
        self,
        request_id: str,
    ) -> dict[str, Any] | None:
        """Retrieve a stored result by request ID."""
        if self._repository:
            return await self._repository.get(
                request_id,
            )
        return None

    async def list_results(
        self,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """List recent consent management results."""
        if self._repository:
            return await self._repository.list(
                limit=limit,
            )
        return []

    async def _persist(
        self,
        result: dict[str, Any],
    ) -> None:
        if self._repository:
            await self._repository.save(result)
