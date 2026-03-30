"""Evidence Automation Engine Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .nodes import set_toolkit
from .tools import EvidenceAutomationEngineToolkit

logger = structlog.get_logger()


class EvidenceAutomationEngineRunner:
    """Runs the Evidence Automation Engine workflow."""

    def __init__(
        self,
        evidence_store: Any | None = None,
        scanner: Any | None = None,
        attestation_api: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = EvidenceAutomationEngineToolkit(
            evidence_store=evidence_store,
            scanner=scanner,
            attestation_api=attestation_api,
        )
        set_toolkit(self._toolkit)
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("eae_runner.init")

    async def execute(
        self,
        frameworks: list[str] | None = None,
        tenant_id: str = "default",
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute evidence collection workflow."""
        if frameworks is None:
            frameworks = ["soc2", "hipaa", "pci_dss"]

        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "frameworks": frameworks,
            "reasoning_chain": [],
        }

        logger.info(
            "eae_runner.execute",
            frameworks=frameworks,
        )
        try:
            result = await self._app.ainvoke(
                initial_state,
            )
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("eae_runner.execute.error")
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
        """List recent evidence collection results."""
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
