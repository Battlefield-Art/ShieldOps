"""PCI Scanner Agent — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from shieldops.licensing.enforce import enforced

from .graph import create_pci_scanner_graph
from .tools import PCIScannerToolkit

logger = structlog.get_logger()


class PCIScannerRunner:
    """Runs the PCI Scanner agent workflow."""

    def __init__(
        self,
        pci_backend: Any | None = None,
        scan_service: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = PCIScannerToolkit(
            pci_backend=pci_backend,
            scan_service=scan_service,
        )
        self._repository = repository
        self._graph = create_pci_scanner_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("pci_scanner_runner.init")

    @enforced("pci_scanner")
    async def run(
        self,
        tenant_id: str = "",
    ) -> dict[str, Any]:
        """Execute the PCI DSS scanning workflow."""
        initial_state: dict[str, Any] = {
            "request_id": "",
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "pci_scanner_runner.run",
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(initial_state)
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("pci_scanner_runner.run.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist PCI scanning results."""
        if self._repository:
            await self._repository.save_pci_run(result)
