"""Compliance Reporter Agent — Entry point and lifecycle management."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from .graph import create_compliance_reporter_graph

logger = structlog.get_logger()


class ComplianceReporterRunner:
    """Runs the Compliance Reporter agent workflow."""

    def __init__(
        self,
        evidence_store: Any | None = None,
        policy_engine: Any | None = None,
        delivery_service: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._repository = repository
        self._graph = create_compliance_reporter_graph(
            evidence_store=evidence_store,
            policy_engine=policy_engine,
            delivery_service=delivery_service,
        )
        self._app = self._graph.compile()
        logger.info("compliance_reporter_runner.init")

    async def report(
        self,
        framework: str = "soc2_type2",
        period_start: str | None = None,
        period_end: str | None = None,
        recipients: list[str] | None = None,
    ) -> dict[str, Any]:
        """Execute the full compliance reporting workflow.

        Args:
            framework: Compliance framework to report on (e.g. soc2_type2, pci_dss_4).
            period_start: Report period start date (ISO format).
            period_end: Report period end date (ISO format).
            recipients: List of delivery recipients (emails, Slack channels, S3 URIs).

        Returns:
            Final agent state dict with report, artifacts, and delivery results.
        """
        now = time.time()
        if period_start is None:
            period_start = "2025-01-01"
        if period_end is None:
            period_end = "2025-12-31"
        if recipients is None:
            recipients = ["compliance-team@company.com"]

        initial_state: dict[str, Any] = {
            "request_id": f"cr-{uuid.uuid4().hex[:12]}",
            "framework": framework,
            "period_start": period_start,
            "period_end": period_end,
            "reasoning_chain": [],
            "session_start": now,
        }

        logger.info(
            "compliance_reporter_runner.report",
            framework=framework,
            period_start=period_start,
            period_end=period_end,
            recipients=recipients,
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("compliance_reporter_runner.report.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist compliance report results."""
        if self._repository:
            await self._repository.save_compliance_report_run(result)
