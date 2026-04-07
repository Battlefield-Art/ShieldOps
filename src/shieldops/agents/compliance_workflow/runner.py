"""Compliance Workflow Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from shieldops.licensing.enforce import enforced

from .graph import create_compliance_workflow_graph
from .tools import ComplianceWorkflowToolkit

logger = structlog.get_logger()


class ComplianceWorkflowRunner:
    """Runs the Compliance Workflow agent workflow."""

    def __init__(
        self,
        compliance_backend: Any | None = None,
        evidence_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ComplianceWorkflowToolkit(
            compliance_backend=compliance_backend,
            evidence_store=evidence_store,
        )
        self._repository = repository
        self._graph = create_compliance_workflow_graph(
            compliance_backend=compliance_backend,
            evidence_store=evidence_store,
        )
        self._app = self._graph.compile()
        logger.info("compliance_workflow_runner.init")

    @enforced("compliance_workflow")
    async def run(
        self,
        tenant_id: str = "default",
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute the full compliance workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "compliance_workflow_runner.run",
            tenant_id=tenant_id,
            request_id=request_id,
        )
        try:
            result = await self._app.ainvoke(
                initial_state,
            )  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception(
                "compliance_workflow_runner.error",
            )
            raise

    async def _persist(
        self,
        result: dict[str, Any],
    ) -> None:
        """Persist compliance workflow results."""
        if self._repository:
            await self._repository.save_compliance_workflow(
                result,
            )
