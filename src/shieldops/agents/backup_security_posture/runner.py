"""Backup Security Posture Agent — Entry point and lifecycle."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import BackupSecurityPostureToolkit

logger = structlog.get_logger()


class BackupSecurityPostureRunner:
    """Runs the Backup Security Posture workflow."""

    def __init__(
        self,
        backup_api: Any | None = None,
        vuln_scanner: Any | None = None,
        dr_tester: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = BackupSecurityPostureToolkit(
            backup_api=backup_api,
            vuln_scanner=vuln_scanner,
            dr_tester=dr_tester,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("backup_posture_runner.init")

    async def assess(
        self,
        tenant_id: str = "default",
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute backup security posture assessment."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "backup_posture_runner.assess",
            request_id=request_id,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("backup_posture_runner.assess.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        if self._repository:
            await self._repository.save_posture(result)
