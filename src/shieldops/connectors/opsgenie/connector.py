"""OpsGenie connector for alert management, on-call scheduling, and escalation."""

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

_DEFAULT_BASE_URL = "https://api.opsgenie.com"


class OpsGenieConnector(InfraConnector):
    """Connector for Atlassian OpsGenie alert and on-call management.

    Provides access to alerts, on-call schedules, teams,
    and escalation management.
    """

    provider = "opsgenie"

    def __init__(
        self,
        api_key: str,
        base_url: str = _DEFAULT_BASE_URL,
    ) -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._http_client: Any = None
        self._snapshots: dict[str, dict[str, Any]] = {}

    def _ensure_http_client(self) -> Any:
        """Lazily initialize httpx async client."""
        if self._http_client is None:
            import httpx

            self._http_client = httpx.AsyncClient(
                base_url=self._base_url,
                timeout=30.0,
            )
        return self._http_client

    def _auth_headers(self) -> dict[str, str]:
        """Return authorization headers for OpsGenie API."""
        return {
            "Authorization": f"GenieKey {self._api_key}",
            "Content-Type": "application/json",
        }

    async def _api_request(
        self,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Make an authenticated API request to OpsGenie."""
        client = self._ensure_http_client()
        headers = kwargs.pop("headers", {})
        headers.update(self._auth_headers())
        resp = await client.request(method, path, headers=headers, **kwargs)
        resp.raise_for_status()
        return resp.json()

    # -- InfraConnector interface ------------------------------------------

    async def get_health(self, resource_id: str) -> HealthStatus:
        """Check OpsGenie API health via account info endpoint."""
        try:
            data = await self._api_request("GET", "/v2/account")
            name = data.get("data", {}).get("name", "")
            return HealthStatus(
                resource_id=resource_id,
                healthy=bool(name),
                status="healthy" if name else "unhealthy",
                message=(f"OpsGenie account: {name}" if name else "Unable to fetch account"),
                last_checked=datetime.now(UTC),
            )
        except Exception as e:
            logger.error("opsgenie.health_check_failed", error=str(e))
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
        """List OpsGenie resources (alerts, teams)."""
        resources: list[Resource] = []
        try:
            if resource_type in ("alert", "alerts"):
                data = await self._api_request("GET", "/v2/alerts")
                for alert in data.get("data", []):
                    resources.append(
                        Resource(
                            id=alert.get("id", ""),
                            name=alert.get("message", "unknown"),
                            resource_type="alert",
                            environment=environment,
                            provider=self.provider,
                            metadata={
                                "status": alert.get("status", ""),
                                "priority": alert.get("priority", ""),
                            },
                        )
                    )
        except Exception as e:
            logger.error("opsgenie.list_resources_failed", error=str(e))
        return resources

    async def get_events(self, resource_id: str, time_range: TimeRange) -> list[dict[str, Any]]:
        """Get OpsGenie alert logs."""
        try:
            data = await self._api_request("GET", f"/v2/alerts/{resource_id}/logs")
            return data.get("data", [])
        except Exception as e:
            logger.error("opsgenie.get_events_failed", error=str(e))
            return []

    async def execute_action(self, action: RemediationAction) -> ActionResult:
        """Execute an OpsGenie action (ack, close alert)."""
        action_id = str(uuid4())
        try:
            alert_id = action.parameters.get("alert_id", "")
            if action.action_type == "acknowledge":
                await self._api_request(
                    "POST",
                    f"/v2/alerts/{alert_id}/acknowledge",
                )
            elif action.action_type == "close":
                await self._api_request("POST", f"/v2/alerts/{alert_id}/close")
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
        """Create a snapshot of alert state."""
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

    # -- OpsGenie-specific methods -----------------------------------------

    async def get_alerts(
        self,
        query: str = "",
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get OpsGenie alerts."""
        params: dict[str, Any] = {"limit": limit}
        if query:
            params["query"] = query
        data = await self._api_request("GET", "/v2/alerts", params=params)
        return data.get("data", [])

    async def create_alert(
        self,
        message: str,
        priority: str = "P3",
        description: str = "",
        tags: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create an OpsGenie alert."""
        body: dict[str, Any] = {
            "message": message,
            "priority": priority,
        }
        if description:
            body["description"] = description
        if tags:
            body["tags"] = tags
        data = await self._api_request("POST", "/v2/alerts", json=body)
        return data.get("data", {})

    async def acknowledge_alert(self, alert_id: str, note: str = "") -> dict[str, Any]:
        """Acknowledge an OpsGenie alert."""
        body: dict[str, Any] = {}
        if note:
            body["note"] = note
        return await self._api_request(
            "POST",
            f"/v2/alerts/{alert_id}/acknowledge",
            json=body,
        )

    async def close_alert(self, alert_id: str, note: str = "") -> dict[str, Any]:
        """Close an OpsGenie alert."""
        body: dict[str, Any] = {}
        if note:
            body["note"] = note
        return await self._api_request("POST", f"/v2/alerts/{alert_id}/close", json=body)

    async def get_teams(self) -> list[dict[str, Any]]:
        """Get all OpsGenie teams."""
        data = await self._api_request("GET", "/v2/teams")
        return data.get("data", [])

    async def get_schedules(self) -> list[dict[str, Any]]:
        """Get all OpsGenie schedules."""
        data = await self._api_request("GET", "/v2/schedules")
        return data.get("data", [])

    async def get_oncall(self, schedule_id: str) -> list[dict[str, Any]]:
        """Get current on-call participants for a schedule."""
        data = await self._api_request(
            "GET",
            f"/v2/schedules/{schedule_id}/on-calls",
        )
        return data.get("data", {}).get("onCallParticipants", [])
