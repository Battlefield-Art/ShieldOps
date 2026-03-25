"""Secrets Scanner Agent — Entry point and lifecycle management."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from .graph import build_graph
from .tools import SecretsScannerToolkit

logger = structlog.get_logger()


class SecretsScannerRunner:
    """Runs the Secrets Scanner agent workflow."""

    def __init__(
        self,
        git_client: Any | None = None,
        vault_client: Any | None = None,
        registry_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecretsScannerToolkit(
            git_client=git_client,
            vault_client=vault_client,
            registry_client=registry_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("secrets_scanner_runner.init")

    async def scan(
        self,
        tenant_id: str,
        scan_targets: list[str] | None = None,
    ) -> dict[str, Any]:
        """Execute the full secrets scanning workflow.

        Args:
            tenant_id: Tenant identifier for multi-tenant isolation.
            scan_targets: List of file paths, repo URLs, or image refs to scan.

        Returns:
            Final state dict with findings, assessments, actions, and stats.
        """
        scan_targets = scan_targets or []
        request_id = str(uuid.uuid4())[:12]

        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "scan_targets": scan_targets,
            "reasoning_chain": [],
        }

        logger.info(
            "secrets_scanner_runner.scan",
            request_id=request_id,
            tenant_id=tenant_id,
            target_count=len(scan_targets),
        )
        start = time.time()
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            result["session_duration_ms"] = (time.time() - start) * 1000
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception(
                "secrets_scanner_runner.scan.error",
                request_id=request_id,
            )
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist scan results to the repository."""
        if self._repository:
            await self._repository.save_scan_run(result)
