"""Code Security Scanner Agent — Entry point and lifecycle management."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from .graph import build_graph
from .tools import CodeSecurityScannerToolkit

logger = structlog.get_logger()


class CodeSecurityScannerRunner:
    """Runs the Code Security Scanner agent workflow."""

    def __init__(
        self,
        git_client: Any | None = None,
        registry_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = CodeSecurityScannerToolkit(
            git_client=git_client,
            registry_client=registry_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("code_security_scanner_runner.init")

    async def scan(
        self,
        tenant_id: str,
        repos: list[str] | None = None,
        scan_targets: list[str] | None = None,
    ) -> dict[str, Any]:
        """Execute the full code security scanning workflow.

        Args:
            tenant_id: Tenant identifier for isolation.
            repos: List of repo URLs or paths to scan.
            scan_targets: List of specific file paths.

        Returns:
            Final state dict with all findings and stats.
        """
        targets = scan_targets or repos or []
        request_id = str(uuid.uuid4())[:12]

        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "scan_targets": targets,
            "reasoning_chain": [],
        }

        logger.info(
            "code_security_scanner_runner.scan",
            request_id=request_id,
            tenant_id=tenant_id,
            target_count=len(targets),
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
                "code_security_scanner_runner.scan.error",
                request_id=request_id,
            )
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist scan results to the repository."""
        if self._repository:
            await self._repository.save_scan_run(result)
