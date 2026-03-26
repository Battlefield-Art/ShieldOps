"""AI Compliance Agent — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import AIComplianceToolkit

logger = structlog.get_logger()


class AIComplianceRunner:
    """Runs the AI Compliance agent workflow."""

    def __init__(
        self,
        inventory_client: Any | None = None,
        policy_client: Any | None = None,
        evidence_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = AIComplianceToolkit(
            inventory_client=inventory_client,
            policy_client=policy_client,
            evidence_store=evidence_store,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("ai_compliance_runner.init")

    async def assess(
        self,
        tenant_id: str = "default",
        frameworks: list[str] | None = None,
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute the full AI compliance assessment workflow.

        Args:
            tenant_id: Tenant identifier for inventory lookup.
            frameworks: List of frameworks to assess against.
                Defaults to EU AI Act, NIST AI RMF, and ISO 42001.
            request_id: Optional request identifier for tracing.

        Returns:
            Final state dict with systems, classifications, assessments,
            evidence, compliance scores, and reasoning chain.
        """
        if frameworks is None:
            frameworks = ["eu_ai_act", "nist_ai_rmf", "iso_42001"]

        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "frameworks": frameworks,
            "reasoning_chain": [],
        }

        logger.info(
            "ai_compliance_runner.assess",
            request_id=request_id,
            tenant_id=tenant_id,
            frameworks=frameworks,
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("ai_compliance_runner.assess.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist compliance assessment results."""
        if self._repository:
            await self._repository.save_compliance_assessment(result)
