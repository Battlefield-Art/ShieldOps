"""Firewall Rule Auditor Agent — Entry point and lifecycle management."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from .graph import build_graph
from .models import FirewallProvider
from .tools import FirewallAuditToolkit

logger = structlog.get_logger()


class FirewallRuleAuditorRunner:
    """Runs the Firewall Rule Auditor agent workflow."""

    def __init__(
        self,
        cloud_clients: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = FirewallAuditToolkit(
            cloud_clients=cloud_clients,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("firewall_rule_auditor_runner.init")

    async def audit(
        self,
        tenant_id: str,
        providers: list[str] | None = None,
    ) -> dict[str, Any]:
        """Execute the full firewall rule audit workflow.

        Args:
            tenant_id: Tenant identifier for multi-tenant isolation.
            providers: Firewall providers to audit. Defaults to all.

        Returns:
            Final agent state with audit score, violations, findings,
            and summary statistics.
        """
        if providers is None:
            providers = [p.value for p in FirewallProvider]

        request_id = str(uuid.uuid4())[:8]
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "providers": providers,
            "reasoning_chain": [],
            "session_start": time.time(),
        }

        logger.info(
            "firewall_rule_auditor_runner.audit",
            request_id=request_id,
            tenant_id=tenant_id,
            providers=providers,
        )

        try:
            result = await self._app.ainvoke(
                initial_state,
            )  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("firewall_rule_auditor_runner.audit.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist firewall audit results."""
        if self._repository:
            await self._repository.save_firewall_audit(result)
