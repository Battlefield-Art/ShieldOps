"""API Gateway Security Agent — Entry point and lifecycle."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from .graph import build_graph
from .tools import APIGatewaySecurityToolkit

logger = structlog.get_logger()


class APIGatewaySecurityRunner:
    """Runs the API Gateway Security scanning workflow."""

    def __init__(
        self,
        gateway_client: Any | None = None,
        waf_client: Any | None = None,
        traffic_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = APIGatewaySecurityToolkit(
            gateway_client=gateway_client,
            waf_client=waf_client,
            traffic_store=traffic_store,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("api_gateway_security_runner.init")

    async def scan(
        self,
        tenant_id: str,
        gateway_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        """Execute a full API gateway security scan.

        Args:
            tenant_id: The tenant to scan.
            gateway_ids: Optional list of gateway IDs to
                scope the scan. Defaults to all gateways.

        Returns:
            Dict with discovered endpoints, auth analyses,
            endpoint scans, abuse detections, policy
            enforcements, stats, and reasoning chain.
        """
        request_id = uuid.uuid4().hex[:16]
        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "gateway_ids": gateway_ids or [],
            "reasoning_chain": [],
        }

        logger.info(
            "api_gateway_security_runner.scan",
            tenant_id=tenant_id,
            gateway_ids=gateway_ids,
            request_id=request_id,
        )
        start = time.time()

        try:
            result = await self._app.ainvoke(
                initial_state,
            )  # type: ignore[arg-type]
            duration_ms = (time.time() - start) * 1000
            result["session_duration_ms"] = round(
                duration_ms,
                1,
            )

            if self._repository:
                await self._persist(result)

            logger.info(
                "api_gateway_security_runner.scan.done",
                request_id=request_id,
                duration_ms=round(duration_ms, 1),
                endpoints=len(
                    result.get("discovered_endpoints", []),
                ),
                abuse=len(
                    result.get("abuse_detections", []),
                ),
                enforcements=len(
                    result.get("policy_enforcements", []),
                ),
            )
            return result
        except Exception:
            logger.exception(
                "api_gateway_security_runner.scan.error",
                request_id=request_id,
            )
            raise

    async def _persist(
        self,
        result: dict[str, Any],
    ) -> None:
        """Persist scan results to the repository."""
        if self._repository:
            await self._repository.save_gateway_security_scan(
                result,
            )
