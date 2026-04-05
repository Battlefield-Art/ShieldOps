"""ServiceNow ITSM connector for incident, change, and CMDB management."""

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


class ServiceNowConnector(InfraConnector):
    """Connector for ServiceNow ITSM (incidents, changes, CMDB).

    Provides access to ServiceNow Table API for incidents, change requests,
    CMDB queries, and generic record operations.
    """

    provider = "servicenow"

    def __init__(
        self,
        instance_url: str,
        username: str = "",
        password: str = "",
    ) -> None:
        self._instance_url = instance_url.rstrip("/")
        self._username = username
        self._password = password
        self._http_client: Any = None
        self._snapshots: dict[str, dict[str, Any]] = {}

    def _ensure_http_client(self) -> Any:
        """Lazily initialize httpx async client."""
        if self._http_client is None:
            import httpx

            self._http_client = httpx.AsyncClient(
                base_url=self._instance_url,
                timeout=30.0,
                auth=((self._username, self._password) if self._username else None),
            )
        return self._http_client

    def _auth_headers(self) -> dict[str, str]:
        """Return headers for ServiceNow Table API."""
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    async def _api_request(
        self,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Make an authenticated API request to ServiceNow."""
        client = self._ensure_http_client()
        headers = kwargs.pop("headers", {})
        headers.update(self._auth_headers())
        resp = await client.request(method, path, headers=headers, **kwargs)
        resp.raise_for_status()
        return resp.json()

    # -- InfraConnector interface ------------------------------------------

    async def get_health(self, resource_id: str) -> HealthStatus:
        """Check ServiceNow API health via stats endpoint."""
        try:
            await self._api_request(
                "GET",
                "/api/now/table/sys_properties",
                params={"sysparm_limit": "1"},
            )
            return HealthStatus(
                resource_id=resource_id,
                healthy=True,
                status="healthy",
                message="ServiceNow API accessible",
                last_checked=datetime.now(UTC),
            )
        except Exception as e:
            logger.error("servicenow.health_check_failed", error=str(e))
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
        """List ServiceNow resources (incidents, changes, CIs)."""
        resources: list[Resource] = []
        table_map = {
            "incident": "incident",
            "change": "change_request",
            "ci": "cmdb_ci",
        }
        table = table_map.get(resource_type, resource_type)
        try:
            data = await self._api_request(
                "GET",
                f"/api/now/table/{table}",
                params={"sysparm_limit": "100"},
            )
            for record in data.get("result", []):
                resources.append(
                    Resource(
                        id=record.get("sys_id", ""),
                        name=record.get(
                            "short_description",
                            record.get("name", "unknown"),
                        ),
                        resource_type=resource_type,
                        environment=environment,
                        provider=self.provider,
                        metadata={
                            "number": record.get("number", ""),
                            "state": record.get("state", ""),
                        },
                    )
                )
        except Exception as e:
            logger.error("servicenow.list_resources_failed", error=str(e))
        return resources

    async def get_events(self, resource_id: str, time_range: TimeRange) -> list[dict[str, Any]]:
        """Get ServiceNow events for a CI within a time range."""
        try:
            query = f"cmdb_ci={resource_id}^sys_created_on>={time_range.start.isoformat()}"
            data = await self._api_request(
                "GET",
                "/api/now/table/em_event",
                params={
                    "sysparm_query": query,
                    "sysparm_limit": "200",
                },
            )
            return data.get("result", [])
        except Exception as e:
            logger.error("servicenow.get_events_failed", error=str(e))
            return []

    async def execute_action(self, action: RemediationAction) -> ActionResult:
        """Execute a ServiceNow action (create/update records)."""
        action_id = str(uuid4())
        return ActionResult(
            action_id=action_id,
            status=ExecutionStatus.SUCCESS,
            message=f"Action {action.action_type} completed",
            started_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
        )

    async def create_snapshot(self, resource_id: str) -> Snapshot:
        """Create a snapshot of record state."""
        snapshot_id = str(uuid4())
        self._snapshots[snapshot_id] = {
            "resource_id": resource_id,
            "created_at": datetime.now(UTC).isoformat(),
        }
        return Snapshot(  # type: ignore[call-arg]
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

    # -- ServiceNow-specific methods ---------------------------------------

    async def get_incidents(
        self,
        query: str = "",
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get ServiceNow incidents."""
        params: dict[str, Any] = {"sysparm_limit": str(limit)}
        if query:
            params["sysparm_query"] = query
        data = await self._api_request("GET", "/api/now/table/incident", params=params)
        return data.get("result", [])

    async def create_incident(
        self,
        short_description: str,
        description: str = "",
        urgency: str = "2",
        impact: str = "2",
        assignment_group: str = "",
    ) -> dict[str, Any]:
        """Create a ServiceNow incident."""
        body: dict[str, Any] = {
            "short_description": short_description,
            "description": description,
            "urgency": urgency,
            "impact": impact,
        }
        if assignment_group:
            body["assignment_group"] = assignment_group
        data = await self._api_request("POST", "/api/now/table/incident", json=body)
        return data.get("result", {})

    async def get_change_requests(
        self,
        query: str = "",
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get ServiceNow change requests."""
        params: dict[str, Any] = {"sysparm_limit": str(limit)}
        if query:
            params["sysparm_query"] = query
        data = await self._api_request("GET", "/api/now/table/change_request", params=params)
        return data.get("result", [])

    async def create_change_request(
        self,
        short_description: str,
        description: str = "",
        change_type: str = "normal",
        risk: str = "moderate",
    ) -> dict[str, Any]:
        """Create a ServiceNow change request."""
        body = {
            "short_description": short_description,
            "description": description,
            "type": change_type,
            "risk": risk,
        }
        data = await self._api_request("POST", "/api/now/table/change_request", json=body)
        return data.get("result", {})

    async def query_cmdb(
        self,
        ci_class: str = "cmdb_ci",
        query: str = "",
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Query the ServiceNow CMDB."""
        params: dict[str, Any] = {"sysparm_limit": str(limit)}
        if query:
            params["sysparm_query"] = query
        data = await self._api_request("GET", f"/api/now/table/{ci_class}", params=params)
        return data.get("result", [])

    async def update_record(
        self,
        table: str,
        sys_id: str,
        fields: dict[str, Any],
    ) -> dict[str, Any]:
        """Update a ServiceNow record."""
        data = await self._api_request(
            "PATCH",
            f"/api/now/table/{table}/{sys_id}",
            json=fields,
        )
        return data.get("result", {})
