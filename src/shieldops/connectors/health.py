"""Connector health check framework with caching and pre-execution validation.

Provides a protocol for connector health checks, a registry for tracking
connectors, TTL-based caching, and a pre-execution hook for agents.
"""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()

# Default cache TTL in seconds
_DEFAULT_CACHE_TTL: float = 30.0


class ConnectorStatus(StrEnum):
    """Health status of a connector."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


class ConnectorHealthStatus(BaseModel):
    """Health check result for a connector."""

    status: ConnectorStatus
    latency_ms: float = 0.0
    last_checked: datetime = Field(default_factory=lambda: datetime.now(UTC))
    message: str = ""


@runtime_checkable
class ConnectorHealthCheck(Protocol):
    """Protocol for connectors that support health checks."""

    async def check_health(self) -> ConnectorHealthStatus: ...


class AllConnectorsUnavailableError(Exception):
    """Raised when all required connectors are unavailable."""

    def __init__(self, connector_names: list[str]) -> None:
        self.connector_names = connector_names
        super().__init__(f"All required connectors are unavailable: {', '.join(connector_names)}")


class _CachedResult:
    """Internal cache entry with TTL tracking."""

    __slots__ = ("result", "cached_at")

    def __init__(self, result: ConnectorHealthStatus) -> None:
        self.result = result
        self.cached_at = time.monotonic()

    def is_valid(self, ttl: float) -> bool:
        return (time.monotonic() - self.cached_at) < ttl


class HealthCheckRegistry:
    """Singleton registry that tracks connectors and their health.

    Maintains a mapping of connector name -> health check callable,
    caches results with a configurable TTL, and provides parallel
    health checking for pre-execution validation.
    """

    _instance: HealthCheckRegistry | None = None

    def __new__(cls) -> HealthCheckRegistry:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._connectors = {}
            cls._instance._cache = {}
            cls._instance._cache_ttl = _DEFAULT_CACHE_TTL
        return cls._instance

    def __init__(self) -> None:
        # Avoid re-initializing on subsequent calls to __new__
        if not hasattr(self, "_connectors"):
            self._connectors: dict[str, ConnectorHealthCheck] = {}
            self._cache: dict[str, _CachedResult] = {}
            self._cache_ttl: float = _DEFAULT_CACHE_TTL

    @classmethod
    def reset(cls) -> None:
        """Reset the singleton (for testing)."""
        cls._instance = None

    def register(self, name: str, connector: ConnectorHealthCheck) -> None:
        """Register a connector for health monitoring."""
        self._connectors[name] = connector
        logger.info("connector_health_registered", connector=name)

    def unregister(self, name: str) -> None:
        """Remove a connector from health monitoring."""
        self._connectors.pop(name, None)
        self._cache.pop(name, None)

    @property
    def registered_connectors(self) -> list[str]:
        """List names of all registered connectors."""
        return list(self._connectors.keys())

    @property
    def cache_ttl(self) -> float:
        """Current cache TTL in seconds."""
        return self._cache_ttl

    @cache_ttl.setter
    def cache_ttl(self, value: float) -> None:
        """Set cache TTL in seconds."""
        self._cache_ttl = max(0.0, value)

    async def check(self, name: str) -> ConnectorHealthStatus:
        """Run a health check for a single connector, using cache if valid.

        Args:
            name: Connector name.

        Returns:
            ConnectorHealthStatus with current status.

        Raises:
            KeyError: If connector is not registered.
        """
        if name not in self._connectors:
            raise KeyError(f"Connector '{name}' is not registered")

        # Check cache
        cached = self._cache.get(name)
        if cached is not None and cached.is_valid(self._cache_ttl):
            return cached.result

        # Run fresh check
        connector = self._connectors[name]
        start = time.monotonic()
        try:
            result = await connector.check_health()
        except Exception as e:
            elapsed_ms = (time.monotonic() - start) * 1000
            logger.error("connector_health_check_failed", connector=name, error=str(e))
            result = ConnectorHealthStatus(
                status=ConnectorStatus.UNAVAILABLE,
                latency_ms=elapsed_ms,
                last_checked=datetime.now(UTC),
                message=f"Health check error: {e}",
            )

        # Cache result
        self._cache[name] = _CachedResult(result)
        return result

    async def check_all(self) -> dict[str, ConnectorHealthStatus]:
        """Run health checks for all registered connectors in parallel.

        Returns:
            Mapping of connector name -> health status.
        """
        if not self._connectors:
            return {}

        names = list(self._connectors.keys())
        results = await asyncio.gather(
            *(self.check(name) for name in names),
            return_exceptions=True,
        )

        statuses: dict[str, ConnectorHealthStatus] = {}
        for name, result in zip(names, results, strict=True):
            if isinstance(result, Exception):
                statuses[name] = ConnectorHealthStatus(
                    status=ConnectorStatus.UNAVAILABLE,
                    last_checked=datetime.now(UTC),
                    message=str(result),
                )
            else:
                statuses[name] = result
        return statuses

    def invalidate(self, name: str) -> None:
        """Invalidate cached health status for a connector."""
        self._cache.pop(name, None)

    def invalidate_all(self) -> None:
        """Invalidate all cached health statuses."""
        self._cache.clear()


async def check_agent_connectors(
    agent_name: str,
    required_connectors: list[str],
) -> dict[str, ConnectorHealthStatus]:
    """Pre-execution hook: check health of all connectors an agent needs.

    Runs health checks in parallel for all required connectors. If ALL are
    unavailable, raises AllConnectorsUnavailableError. If some are unavailable,
    logs a warning and returns partial status for the agent to decide.

    Args:
        agent_name: Name of the agent requesting the check.
        required_connectors: List of connector names the agent needs.

    Returns:
        Mapping of connector name -> health status.

    Raises:
        AllConnectorsUnavailableError: If every required connector is unavailable.
    """
    registry = HealthCheckRegistry()

    if not required_connectors:
        return {}

    # Run checks in parallel
    names = list(required_connectors)
    results = await asyncio.gather(
        *(registry.check(name) for name in names),
        return_exceptions=True,
    )

    statuses: dict[str, ConnectorHealthStatus] = {}
    for name, result in zip(names, results, strict=True):
        if isinstance(result, KeyError):
            statuses[name] = ConnectorHealthStatus(
                status=ConnectorStatus.UNAVAILABLE,
                last_checked=datetime.now(UTC),
                message=f"Connector '{name}' is not registered",
            )
        elif isinstance(result, Exception):
            statuses[name] = ConnectorHealthStatus(
                status=ConnectorStatus.UNAVAILABLE,
                last_checked=datetime.now(UTC),
                message=str(result),
            )
        else:
            statuses[name] = result

    # Check if all unavailable
    unavailable = [name for name, s in statuses.items() if s.status == ConnectorStatus.UNAVAILABLE]
    if len(unavailable) == len(required_connectors):
        logger.error(
            "all_connectors_unavailable",
            agent=agent_name,
            connectors=unavailable,
        )
        raise AllConnectorsUnavailableError(unavailable)

    # Log warning for partial unavailability
    if unavailable:
        logger.warning(
            "some_connectors_unavailable",
            agent=agent_name,
            unavailable=unavailable,
            available=[n for n in names if n not in unavailable],
        )

    return statuses


# ---------------------------------------------------------------------------
# Health check implementations for launch connectors
# ---------------------------------------------------------------------------


class AWSHealthCheck:
    """Health check for AWS connector via STS get-caller-identity."""

    def __init__(self, connector: Any) -> None:
        self._connector = connector

    async def check_health(self) -> ConnectorHealthStatus:
        start = time.monotonic()
        try:
            self._connector._ensure_clients()
            import boto3

            sts = boto3.client("sts", region_name=self._connector._region)
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, sts.get_caller_identity)
            elapsed_ms = (time.monotonic() - start) * 1000
            return ConnectorHealthStatus(
                status=ConnectorStatus.HEALTHY,
                latency_ms=elapsed_ms,
                last_checked=datetime.now(UTC),
                message="STS get-caller-identity succeeded",
            )
        except Exception as e:
            elapsed_ms = (time.monotonic() - start) * 1000
            logger.error("aws_health_check_failed", error=str(e))
            return ConnectorHealthStatus(
                status=ConnectorStatus.UNAVAILABLE,
                latency_ms=elapsed_ms,
                last_checked=datetime.now(UTC),
                message=f"STS error: {e}",
            )


class CrowdStrikeHealthCheck:
    """Health check for CrowdStrike via OAuth2 token refresh."""

    def __init__(self, connector: Any) -> None:
        self._connector = connector

    async def check_health(self) -> ConnectorHealthStatus:
        start = time.monotonic()
        try:
            await self._connector._ensure_auth()
            elapsed_ms = (time.monotonic() - start) * 1000
            return ConnectorHealthStatus(
                status=ConnectorStatus.HEALTHY,
                latency_ms=elapsed_ms,
                last_checked=datetime.now(UTC),
                message="OAuth2 token refresh succeeded",
            )
        except Exception as e:
            elapsed_ms = (time.monotonic() - start) * 1000
            logger.error("crowdstrike_health_check_failed", error=str(e))
            return ConnectorHealthStatus(
                status=ConnectorStatus.UNAVAILABLE,
                latency_ms=elapsed_ms,
                last_checked=datetime.now(UTC),
                message=f"OAuth2 error: {e}",
            )


class SplunkHealthCheck:
    """Health check for Splunk via GET /services/server/info."""

    def __init__(self, connector: Any) -> None:
        self._connector = connector

    async def check_health(self) -> ConnectorHealthStatus:
        start = time.monotonic()
        try:
            data = await self._connector._api_request("GET", "/services/server/info")
            elapsed_ms = (time.monotonic() - start) * 1000
            entries = data.get("entry", [])
            if entries:
                version = entries[0].get("content", {}).get("version", "unknown")
                msg = f"Splunk v{version} reachable"
            else:
                msg = "Splunk server info returned empty"
            return ConnectorHealthStatus(
                status=ConnectorStatus.HEALTHY,
                latency_ms=elapsed_ms,
                last_checked=datetime.now(UTC),
                message=msg,
            )
        except Exception as e:
            elapsed_ms = (time.monotonic() - start) * 1000
            logger.error("splunk_health_check_failed", error=str(e))
            return ConnectorHealthStatus(
                status=ConnectorStatus.UNAVAILABLE,
                latency_ms=elapsed_ms,
                last_checked=datetime.now(UTC),
                message=f"Splunk error: {e}",
            )


class PagerDutyHealthCheck:
    """Health check for PagerDuty via GET /abilities."""

    def __init__(self, connector: Any) -> None:
        self._connector = connector

    async def check_health(self) -> ConnectorHealthStatus:
        start = time.monotonic()
        try:
            await self._connector._api_request("GET", "/abilities")
            elapsed_ms = (time.monotonic() - start) * 1000
            return ConnectorHealthStatus(
                status=ConnectorStatus.HEALTHY,
                latency_ms=elapsed_ms,
                last_checked=datetime.now(UTC),
                message="PagerDuty API reachable",
            )
        except Exception as e:
            elapsed_ms = (time.monotonic() - start) * 1000
            logger.error("pagerduty_health_check_failed", error=str(e))
            return ConnectorHealthStatus(
                status=ConnectorStatus.UNAVAILABLE,
                latency_ms=elapsed_ms,
                last_checked=datetime.now(UTC),
                message=f"PagerDuty error: {e}",
            )


class SlackHealthCheck:
    """Health check for Slack via auth.test API call."""

    def __init__(self, bot_token: str) -> None:
        self._bot_token = bot_token

    async def check_health(self) -> ConnectorHealthStatus:
        start = time.monotonic()
        try:
            import httpx

            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    "https://slack.com/api/auth.test",
                    headers={"Authorization": f"Bearer {self._bot_token}"},
                )
                resp.raise_for_status()
                data = resp.json()

            elapsed_ms = (time.monotonic() - start) * 1000
            if data.get("ok"):
                return ConnectorHealthStatus(
                    status=ConnectorStatus.HEALTHY,
                    latency_ms=elapsed_ms,
                    last_checked=datetime.now(UTC),
                    message=f"Slack bot authenticated as {data.get('user', 'unknown')}",
                )
            return ConnectorHealthStatus(
                status=ConnectorStatus.UNAVAILABLE,
                latency_ms=elapsed_ms,
                last_checked=datetime.now(UTC),
                message=f"Slack auth.test failed: {data.get('error', 'unknown')}",
            )
        except Exception as e:
            elapsed_ms = (time.monotonic() - start) * 1000
            logger.error("slack_health_check_failed", error=str(e))
            return ConnectorHealthStatus(
                status=ConnectorStatus.UNAVAILABLE,
                latency_ms=elapsed_ms,
                last_checked=datetime.now(UTC),
                message=f"Slack error: {e}",
            )


class ServiceNowHealthCheck:
    """Health check for ServiceNow via GET /api/now/table/sys_user?sysparm_limit=1."""

    def __init__(self, connector: Any) -> None:
        self._connector = connector

    async def check_health(self) -> ConnectorHealthStatus:
        start = time.monotonic()
        try:
            await self._connector._api_request(
                "GET",
                "/api/now/table/sys_user",
                params={"sysparm_limit": "1"},
            )
            elapsed_ms = (time.monotonic() - start) * 1000
            return ConnectorHealthStatus(
                status=ConnectorStatus.HEALTHY,
                latency_ms=elapsed_ms,
                last_checked=datetime.now(UTC),
                message="ServiceNow API reachable",
            )
        except Exception as e:
            elapsed_ms = (time.monotonic() - start) * 1000
            logger.error("servicenow_health_check_failed", error=str(e))
            return ConnectorHealthStatus(
                status=ConnectorStatus.UNAVAILABLE,
                latency_ms=elapsed_ms,
                last_checked=datetime.now(UTC),
                message=f"ServiceNow error: {e}",
            )
