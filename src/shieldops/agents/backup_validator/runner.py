"""Backup Validator Agent — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import BackupValidatorToolkit

logger = structlog.get_logger()


class BackupValidatorRunner:
    """Runs the Backup Validator agent workflow."""

    def __init__(
        self,
        backup_client: Any | None = None,
        storage_client: Any | None = None,
        recovery_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = BackupValidatorToolkit(
            backup_client=backup_client,
            storage_client=storage_client,
            recovery_client=recovery_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("backup_validator_runner.init")

    async def validate(
        self,
        tenant_id: str,
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute the full backup validation workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "backup_validator_runner.validate",
            request_id=request_id,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("backup_validator_runner.validate.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist backup validation results."""
        if self._repository:
            await self._repository.save_backup_report(result)
