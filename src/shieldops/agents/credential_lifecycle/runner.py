"""Credential Lifecycle Agent — Entry point and lifecycle management."""

from __future__ import annotations

import time
from typing import Any

import structlog

from .graph import build_graph
from .tools import CredentialLifecycleToolkit

logger = structlog.get_logger()


class CredentialLifecycleRunner:
    """Runs the Credential Lifecycle agent workflow."""

    def __init__(
        self,
        vault_client: Any | None = None,
        iam_client: Any | None = None,
        secret_scanner: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = CredentialLifecycleToolkit(
            vault_client=vault_client,
            iam_client=iam_client,
            secret_scanner=secret_scanner,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("credential_lifecycle_runner.init")

    async def manage(
        self,
        tenant_id: str,
        scan_scope: list[str] | None = None,
    ) -> dict[str, Any]:
        """Execute the full credential lifecycle management workflow."""
        initial_state: dict[str, Any] = {
            "request_id": f"cred-{int(time.time())}",
            "tenant_id": tenant_id,
            "scan_scope": scan_scope or ["cloud_iam", "vault", "k8s", "env"],
            "session_start": time.time(),
            "reasoning_chain": [],
        }

        logger.info(
            "credential_lifecycle_runner.manage",
            tenant_id=tenant_id,
            scan_scope=initial_state["scan_scope"],
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("credential_lifecycle_runner.manage.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist lifecycle results."""
        if self._repository:
            await self._repository.save_scan_result(result)
