"""Backup Integrity Verifier Agent runner — entry point
for executing backup verification campaigns."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.backup_integrity_verifier.graph import (
    create_backup_integrity_verifier_graph,
)
from shieldops.agents.backup_integrity_verifier.models import (
    BackupIntegrityVerifierState,
)
from shieldops.agents.backup_integrity_verifier.nodes import (
    set_toolkit,
)
from shieldops.agents.backup_integrity_verifier.tools import (
    BackupIntegrityVerifierToolkit,
)

logger = structlog.get_logger()


class BackupIntegrityVerifierRunner:
    """Runner for the Backup Integrity Verifier Agent."""

    def __init__(
        self,
        backup_manager: Any | None = None,
        storage_scanner: Any | None = None,
        integrity_checker: Any | None = None,
        encryption_validator: Any | None = None,
        restore_tester: Any | None = None,
        metrics_collector: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = BackupIntegrityVerifierToolkit(
            backup_manager=backup_manager,
            storage_scanner=storage_scanner,
            integrity_checker=integrity_checker,
            encryption_validator=encryption_validator,
            restore_tester=restore_tester,
            metrics_collector=metrics_collector,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_backup_integrity_verifier_graph()
        self._app = graph.compile()
        self._results: dict[str, BackupIntegrityVerifierState] = {}
        logger.info("biv_runner.initialized")

    async def verify(
        self,
        target_systems: list[str] | None = None,
        storage_locations: list[str] | None = None,
        scope: dict[str, Any] | None = None,
        tenant_id: str = "",
    ) -> BackupIntegrityVerifierState:
        """Run a backup integrity verification campaign."""
        request_id = f"biv-{uuid4().hex[:12]}"

        initial_state = BackupIntegrityVerifierState(
            request_id=request_id,
            tenant_id=tenant_id,
            target_systems=target_systems or [],
            storage_locations=storage_locations or [],
            scope=scope or {},
        )

        logger.info(
            "biv_runner.starting",
            request_id=request_id,
            systems=len(initial_state.target_systems),
            locations=len(initial_state.storage_locations),
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "backup_integrity_verifier",
                    },
                },
            )
            final = BackupIntegrityVerifierState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "biv_runner.completed",
                request_id=request_id,
                total=final.total_backups,
                passed=final.passed_integrity,
                failed=final.failed_integrity,
                restore_rate=final.restore_success_rate,
                coverage=final.coverage_pct,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "biv_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = BackupIntegrityVerifierState(
                request_id=request_id,
                tenant_id=tenant_id,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> BackupIntegrityVerifierState | None:
        """Retrieve a cached verification result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all verification results as summaries."""
        return [
            {
                "request_id": rid,
                "total_backups": s.total_backups,
                "passed": s.passed_integrity,
                "failed": s.failed_integrity,
                "restore_rate": s.restore_success_rate,
                "coverage": s.coverage_pct,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
