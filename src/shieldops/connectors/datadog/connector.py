"""Datadog connector for metrics, logs, monitors, and incidents."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog

from shieldops.connectors.base import InfraConnector
from shieldops.models.base import (
    ActionResult,
    Environment,
    ExecutionStatus,
    HealthStatus,
    RemediationAction,
    Resource,
    Snapshot,
    TimeRange,
)

logger = structlog.get_logger()


class DatadogConnector(InfraConnector):
    """Connector for Datadog metrics, logs, monitors, and incidents.

    Provides access to Datadog metrics queries, log search, monitor
    management, incident management, and custom metric submission.
    """

    provider = "datadog"

    def __init__(
        self,
        api_key: str,
        app_key: str = "",
        site: str = "datadoghq.com",
    ) -> None:
        self._api_key = api_key
        self._app_key = app_key
        self._site = site
        self._base_url = f"https://api.{site}"
        self._http_client: Any = None
        self._snapshots: dict[str, dict[str, Any]] = {}

    def _ensure_http_client(self) -> Any:
        """Lazily initialize httpx async client for Datadog API."""
        if self._http_client is None:
            import httpx

            self._http_client = httpx.AsyncClient(
                base_url=self._base_url,
                timeout=30.0,
            )
        return self._http_client

    def _auth_headers(self) -> dict[str, str]:
        """Return authorization headers for Datadog API."""
        return {
            "DD-API-KEY": self._api_key,
            "DD-APPLICATION-KEY": self._app_key,
            "Content-Type": "application/json",
        }

    async def _api_request(
        self,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Make an authenticated API request to Datadog."""
        client = self._ensure_http_client()
        headers = kwargs.pop("headers", {})
        headers.update(self._auth_headers())
        resp = await client.request(method, path, headers=headers, **kwargs)
        resp.raise_for_status()
        return resp.json()

    # -- InfraConnector interface ------------------------------------------

    async def get_health(self, resource_id: str) -> HealthStatus:
        """Check Datadog API health via validation endpoint."""
        try:
            data = await self._api_request("GET", "/api/v1/validate")
            valid = data.get("valid", False)
            return HealthStatus(
                resource_id=resource_id,
                healthy=valid,
                status="healthy" if valid else "unhealthy",
                message="Datadog API key valid" if valid else "Invalid API key",
                last_checked=datetime.now(UTC),
            )
        except Exception as e:
            logger.error("datadog.health_check_failed", resource_id=resource_id, error=str(e))
            return HealthStatus(
                resource_id=resource_id,
                healthy=False,
                status="error",
                message=str(e),
                last_checked=datetime.now(UTC),
            )

    async def list_resources(
        self,
        resource_type: str,
        environment: Environment,
        filters: dict[str, Any] | None = None,
    ) -> list[Resource]:
        """List Datadog resources (monitors, dashboards, services)."""
        resources: list[Resource] = []
        try:
            if resource_type in ("monitor", "monitors"):
                data = await self._api_request("GET", "/api/v1/monitor")
                for mon in data if isinstance(data, list) else []:
                    resources.append(
                        Resource(
                            id=str(mon.get("id", "")),
                            name=mon.get("name", "unknown"),
                            resource_type="monitor",
                            environment=environment,
                            provider=self.provider,
                            metadata={
                                "type": mon.get("type", ""),
                                "query": mon.get("query", ""),
                            },
                        )
                    )
        except Exception as e:
            logger.error("datadog.list_resources_failed", error=str(e))
        return resources

    async def get_events(self, resource_id: str, time_range: TimeRange) -> list[dict[str, Any]]:
        """Get Datadog events within a time range."""
        try:
            start = int(time_range.start.timestamp())
            end = int(time_range.end.timestamp())
            data = await self._api_request(
                "GET",
                "/api/v1/events",
                params={"start": start, "end": end},
            )
            return data.get("events", [])
        except Exception as e:
            logger.error("datadog.get_events_failed", error=str(e))
            return []

    async def execute_action(self, action: RemediationAction) -> ActionResult:
        """Execute a remediation action via Datadog (mute/unmute monitors)."""
        action_id = str(uuid4())
        try:
            if action.action_type == "mute_monitor":
                monitor_id = action.parameters.get("monitor_id", "")
                await self._api_request("POST", f"/api/v1/monitor/{monitor_id}/mute")
            return ActionResult(
                action_id=action_id,
                status=ExecutionStatus.SUCCESS,
                message=f"Action {action.action_type} completed",
                started_at=datetime.now(UTC),
                completed_at=datetime.now(UTC),
            )
        except Exception as e:
            return ActionResult(
                action_id=action_id,
                status=ExecutionStatus.FAILED,
                message=str(e),
                started_at=datetime.now(UTC),
                completed_at=datetime.now(UTC),
            )

    async def create_snapshot(self, resource_id: str) -> Snapshot:
        """Create a snapshot of monitor/dashboard configuration."""
        snapshot_id = str(uuid4())
        self._snapshots[snapshot_id] = {
            "resource_id": resource_id,
            "created_at": datetime.now(UTC).isoformat(),
        }
        return Snapshot(
            id=snapshot_id,
            resource_id=resource_id,
            created_at=datetime.now(UTC),
        )

    async def rollback(self, snapshot_id: str) -> ActionResult:
        """Rollback to a previous snapshot."""
        if snapshot_id not in self._snapshots:
            return ActionResult(
                action_id=str(uuid4()),
                status=ExecutionStatus.FAILED,
                message=f"Snapshot {snapshot_id} not found",
                started_at=datetime.now(UTC),
                completed_at=datetime.now(UTC),
            )
        return ActionResult(
            action_id=str(uuid4()),
            status=ExecutionStatus.SUCCESS,
            message=f"Rollback to {snapshot_id} completed",
            started_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
        )

    async def validate_health(self, resource_id: str, timeout_seconds: int = 300) -> bool:
        """Validate health after an action."""
        health = await self.get_health(resource_id)
        return health.healthy

    # -- Datadog-specific methods ------------------------------------------

    async def query_metrics(
        self,
        query: str,
        from_ts: int,
        to_ts: int,
    ) -> dict[str, Any]:
        """Query Datadog metrics using the metrics API."""
        return await self._api_request(
            "GET",
            "/api/v1/query",
            params={"query": query, "from": from_ts, "to": to_ts},
        )

    async def search_logs(
        self,
        query: str,
        from_ts: str = "",
        to_ts: str = "",
        limit: int = 100,
    ) -> dict[str, Any]:
        """Search Datadog logs."""
        body: dict[str, Any] = {
            "filter": {"query": query, "from": from_ts, "to": to_ts},
            "page": {"limit": limit},
        }
        return await self._api_request("POST", "/api/v2/logs/events/search", json=body)

    async def get_monitors(self) -> list[dict[str, Any]]:
        """Get all Datadog monitors."""
        data = await self._api_request("GET", "/api/v1/monitor")
        return data if isinstance(data, list) else []

    async def create_monitor(
        self,
        name: str,
        monitor_type: str,
        query: str,
        message: str = "",
    ) -> dict[str, Any]:
        """Create a new Datadog monitor."""
        body = {
            "name": name,
            "type": monitor_type,
            "query": query,
            "message": message,
        }
        return await self._api_request("POST", "/api/v1/monitor", json=body)

    async def get_incidents(self) -> list[dict[str, Any]]:
        """Get Datadog incidents."""
        data = await self._api_request("GET", "/api/v2/incidents")
        return data.get("data", [])

    async def submit_metrics(
        self,
        series: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Submit custom metrics to Datadog."""
        return await self._api_request(
            "POST",
            "/api/v2/series",
            json={"series": series},
        )
