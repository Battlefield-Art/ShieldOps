"""Compliance Auditor Agent — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import create_compliance_auditor_graph
from .tools import ComplianceAuditorToolkit

logger = structlog.get_logger()


class ComplianceAuditorRunner:
    """Runs the Compliance Auditor agent workflow."""

    def __init__(
        self,
        compliance_backend: Any | None = None,
        evidence_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ComplianceAuditorToolkit(
            compliance_backend=compliance_backend,
            evidence_store=evidence_store,
        )
        self._repository = repository
        self._graph = create_compliance_auditor_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("compliance_auditor_runner.init")

    async def run(
        self,
        frameworks: list[str] | None = None,
    ) -> dict[str, Any]:
        """Execute the full compliance audit workflow."""
        if frameworks is None:
            frameworks = ["soc2"]

        initial_state: dict[str, Any] = {
            "request_id": "",
            "frameworks": frameworks,
            "reasoning_chain": [],
        }

        logger.info(
            "compliance_auditor_runner.run",
            frameworks=frameworks,
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("compliance_auditor_runner.run.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist compliance audit results."""
        if self._repository:
            await self._repository.save_compliance_audit_run(result)
