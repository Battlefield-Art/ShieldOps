"""Patch Compliance Checker Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from shieldops.licensing.enforce import enforced

from .graph import build_graph
from .tools import PatchComplianceCheckerToolkit

logger = structlog.get_logger()


class PatchComplianceCheckerRunner:
    """Runs the Patch Compliance Checker agent workflow."""

    def __init__(
        self,
        wsus_client: Any | None = None,
        vuln_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = PatchComplianceCheckerToolkit(
            wsus_client=wsus_client,
            vuln_client=vuln_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("patch_compliance_checker_runner.init")

    @enforced("patch_compliance_checker")
    async def run(
        self,
        tenant_id: str,
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute the patch compliance checker workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }
        logger.info(
            "patch_compliance_checker_runner.run",
            request_id=request_id,
        )
        try:
            result = await self._app.ainvoke(initial_state)
            if self._repository:
                await self._repository.save(result)
            return result
        except Exception:
            logger.exception("patch_compliance_checker_runner.error")
            raise
