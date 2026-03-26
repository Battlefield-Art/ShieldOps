"""Compliance Scanner Agent — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import ComplianceScannerToolkit

logger = structlog.get_logger()


class ComplianceScannerRunner:
    """Runs the Compliance Scanner agent workflow."""

    def __init__(
        self,
        policy_client: Any | None = None,
        config_client: Any | None = None,
        evidence_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ComplianceScannerToolkit(
            policy_client=policy_client,
            config_client=config_client,
            evidence_store=evidence_store,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("compliance_scanner_runner.init")

    async def scan(
        self,
        tenant_id: str,
        frameworks: list[str] | None = None,
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute the full compliance scanning workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "frameworks": frameworks or [],
            "reasoning_chain": [],
        }

        logger.info(
            "compliance_scanner_runner.scan",
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
            logger.exception("compliance_scanner_runner.scan.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist compliance scan results."""
        if self._repository:
            await self._repository.save_compliance_report(result)
