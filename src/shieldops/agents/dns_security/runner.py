"""DNS Security Agent — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import DNSSecurityToolkit

logger = structlog.get_logger()


class DNSSecurityRunner:
    """Runs the DNS Security agent workflow."""

    def __init__(
        self,
        dns_log_client: Any | None = None,
        threat_intel_client: Any | None = None,
        firewall_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = DNSSecurityToolkit(
            dns_log_client=dns_log_client,
            threat_intel_client=threat_intel_client,
            firewall_client=firewall_client,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("dns_security_runner.init")

    async def monitor(
        self,
        tenant_id: str,
        request_id: str = "",
    ) -> dict[str, Any]:
        """Execute the full DNS security monitoring workflow."""
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "dns_security_runner.monitor",
            request_id=request_id,
            tenant_id=tenant_id,
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("dns_security_runner.monitor.error")
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist DNS security results."""
        if self._repository:
            await self._repository.save_dns_report(result)
