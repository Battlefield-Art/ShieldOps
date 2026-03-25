"""API Security Agent — Entry point and lifecycle management."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from .graph import build_graph
from .tools import APISecurityToolkit

logger = structlog.get_logger()


class APISecurityRunner:
    """Runs the API Security scanning workflow."""

    def __init__(
        self,
        api_gateway: Any | None = None,
        waf_client: Any | None = None,
        traffic_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = APISecurityToolkit(
            api_gateway=api_gateway,
            waf_client=waf_client,
            traffic_store=traffic_store,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("api_security_runner.init")

    async def scan(
        self,
        tenant_id: str,
        scan_scope: list[str] | None = None,
    ) -> dict[str, Any]:
        """Execute a full API security scan.

        Args:
            tenant_id: The tenant to scan.
            scan_scope: Optional list of service names to limit the scan.
                Defaults to all services.

        Returns:
            Dict with discovered endpoints, vulnerabilities, abuse
            incidents, policy enforcements, stats, and reasoning chain.
        """
        request_id = uuid.uuid4().hex[:16]
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "scan_scope": scan_scope or [],
            "reasoning_chain": [],
        }

        logger.info(
            "api_security_runner.scan",
            tenant_id=tenant_id,
            scope=scan_scope,
            request_id=request_id,
        )
        start = time.time()

        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            duration_ms = (time.time() - start) * 1000
            result["session_duration_ms"] = round(duration_ms, 1)

            if self._repository:
                await self._persist(result)

            logger.info(
                "api_security_runner.scan.done",
                request_id=request_id,
                duration_ms=round(duration_ms, 1),
                vulns=len(result.get("vulnerabilities", [])),
                abuse=len(result.get("abuse_incidents", [])),
            )
            return result
        except Exception:
            logger.exception(
                "api_security_runner.scan.error",
                request_id=request_id,
            )
            raise

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist scan results to the repository."""
        if self._repository:
            await self._repository.save_api_security_scan(result)
