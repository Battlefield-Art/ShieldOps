"""API Rate Limiter — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import APIRateLimiterToolkit

logger = structlog.get_logger()


class APIRateLimiterRunner:
    """Runs the API Rate Limiter workflow."""

    def __init__(
        self,
        redis_client: Any | None = None,
        alert_sink: Any | None = None,
        geo_service: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = APIRateLimiterToolkit(
            redis_client=redis_client,
            alert_sink=alert_sink,
            geo_service=geo_service,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("api_rate_limiter_runner.init")

    async def analyze(
        self,
        requests: list[dict[str, Any]],
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute the full rate limiting analysis workflow."""
        context = context or {}
        window = context.get("time_window_minutes", 5)

        initial_state: dict[str, Any] = {
            "request_id": context.get("request_id", ""),
            "tenant_id": context.get("tenant_id", ""),
            "time_window_minutes": window,
            "raw_requests": requests,
            "reasoning_chain": [],
        }

        logger.info(
            "api_rate_limiter_runner.analyze",
            request_count=len(requests),
            window_minutes=window,
        )
        try:
            result = await self._app.ainvoke(
                initial_state,
            )  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("api_rate_limiter_runner.analyze.error")
            raise

    async def check_client(
        self,
        client_id: str,
        ip_address: str = "",
        endpoint: str = "/",
    ) -> dict[str, Any]:
        """Quick check if a client is currently rate-limited."""
        logger.info(
            "api_rate_limiter_runner.check_client",
            client_id=client_id,
        )
        summary = await self._toolkit.get_enforcement_summary()
        is_blocked = client_id in summary["blocked_clients"]
        is_throttled = client_id in summary["throttled_clients"]

        action = "allow"
        if is_blocked:
            action = "block"
        elif is_throttled:
            action = "throttle"

        return {
            "client_id": client_id,
            "ip_address": ip_address,
            "endpoint": endpoint,
            "action": action,
            "blocked": is_blocked,
            "throttled": is_throttled,
        }

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist rate limiting results."""
        if self._repository:
            await self._repository.save_rate_limit_run(result)
