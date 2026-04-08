"""Vendor Compliance Assessor Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from shieldops.licensing.enforce import enforced

from .graph import build_graph
from .nodes import set_toolkit
from .tools import VendorComplianceAssessorToolkit

logger = structlog.get_logger()


class VendorComplianceAssessorRunner:
    """Runs the Vendor Compliance Assessor workflow."""

    def __init__(
        self,
        vendor_db: Any | None = None,
        questionnaire_api: Any | None = None,
        risk_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = VendorComplianceAssessorToolkit(
            vendor_db=vendor_db,
            questionnaire_api=questionnaire_api,
            risk_engine=risk_engine,
        )
        set_toolkit(self._toolkit)
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("vca_runner.init")

    @enforced("vendor_compliance_assessor")
    async def execute(
        self,
        tenant_id: str = "default",
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute vendor compliance assessment."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "vca_runner.execute",
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
            logger.exception("vca_runner.execute.error")
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
        """List recent assessment results."""
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
