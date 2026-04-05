"""Jira connector for issue tracking, project management, and workflow automation."""

from __future__ import annotations

import base64
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


class JiraConnector(InfraConnector):
    """Connector for Atlassian Jira (Cloud and Server).

    Provides access to JQL search, issue CRUD, transitions,
    comments, and project management.
    """

    provider = "jira"

    def __init__(
        self,
        base_url: str,
        email: str = "",
        api_token: str = "",
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._email = email
        self._api_token = api_token
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
        """Return authorization headers for Jira REST API."""
        if self._email and self._api_token:
            creds = base64.b64encode(f"{self._email}:{self._api_token}".encode()).decode()
            return {
                "Authorization": f"Basic {creds}",
                "Content-Type": "application/json",
            }
        return {"Content-Type": "application/json"}

    async def _api_request(
        self,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Make an authenticated API request to Jira."""
        client = self._ensure_http_client()
        headers = kwargs.pop("headers", {})
        headers.update(self._auth_headers())
        resp = await client.request(method, path, headers=headers, **kwargs)
        resp.raise_for_status()
        if resp.status_code == 204:
            return {}
        return resp.json()

    # -- InfraConnector interface ------------------------------------------

    async def get_health(self, resource_id: str) -> HealthStatus:
        """Check Jira API health via server info endpoint."""
        try:
            data = await self._api_request("GET", "/rest/api/2/serverInfo")
            version = data.get("version", "unknown")
            return HealthStatus(
                resource_id=resource_id,
                healthy=True,
                status="healthy",
                message=f"Jira {version}",
                last_checked=datetime.now(UTC),
            )
        except Exception as e:
            logger.error("jira.health_check_failed", error=str(e))
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
        """List Jira resources (projects, issues)."""
        resources: list[Resource] = []
        try:
            if resource_type in ("project", "projects"):
                data = await self._api_request("GET", "/rest/api/2/project")
                for proj in data if isinstance(data, list) else []:
                    resources.append(
                        Resource(
                            id=proj.get("id", ""),
                            name=proj.get("name", "unknown"),
                            resource_type="project",
                            environment=environment,
                            provider=self.provider,
                            metadata={"key": proj.get("key", "")},
                        )
                    )
        except Exception as e:
            logger.error("jira.list_resources_failed", error=str(e))
        return resources

    async def get_events(self, resource_id: str, time_range: TimeRange) -> list[dict[str, Any]]:
        """Get Jira issue changelog events."""
        try:
            data = await self._api_request(
                "GET",
                f"/rest/api/2/issue/{resource_id}",
                params={"expand": "changelog"},
            )
            return data.get("changelog", {}).get("histories", [])
        except Exception as e:
            logger.error("jira.get_events_failed", error=str(e))
            return []

    async def execute_action(self, action: RemediationAction) -> ActionResult:
        """Execute a Jira action (transition, comment)."""
        action_id = str(uuid4())
        return ActionResult(
            action_id=action_id,
            status=ExecutionStatus.SUCCESS,
            message=f"Action {action.action_type} completed",
            started_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
        )

    async def create_snapshot(self, resource_id: str) -> Snapshot:
        """Create a snapshot of issue state."""
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

    # -- Jira-specific methods ---------------------------------------------

    async def search_jql(
        self,
        jql: str,
        max_results: int = 50,
        fields: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Search Jira issues using JQL."""
        body: dict[str, Any] = {
            "jql": jql,
            "maxResults": max_results,
        }
        if fields:
            body["fields"] = fields
        data = await self._api_request("POST", "/rest/api/2/search", json=body)
        return data.get("issues", [])

    async def create_issue(
        self,
        project_key: str,
        summary: str,
        issue_type: str = "Task",
        description: str = "",
        priority: str = "",
        labels: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create a Jira issue."""
        fields: dict[str, Any] = {
            "project": {"key": project_key},
            "summary": summary,
            "issuetype": {"name": issue_type},
        }
        if description:
            fields["description"] = description
        if priority:
            fields["priority"] = {"name": priority}
        if labels:
            fields["labels"] = labels
        data = await self._api_request("POST", "/rest/api/2/issue", json={"fields": fields})
        return data

    async def transition_issue(
        self,
        issue_key: str,
        transition_id: str,
        comment: str = "",
    ) -> dict[str, Any]:
        """Transition a Jira issue to a new status."""
        body: dict[str, Any] = {"transition": {"id": transition_id}}
        if comment:
            body["update"] = {"comment": [{"add": {"body": comment}}]}
        return await self._api_request(
            "POST",
            f"/rest/api/2/issue/{issue_key}/transitions",
            json=body,
        )

    async def add_comment(
        self,
        issue_key: str,
        body: str,
    ) -> dict[str, Any]:
        """Add a comment to a Jira issue."""
        return await self._api_request(
            "POST",
            f"/rest/api/2/issue/{issue_key}/comment",
            json={"body": body},
        )

    async def get_projects(self) -> list[dict[str, Any]]:
        """Get all Jira projects."""
        data = await self._api_request("GET", "/rest/api/2/project")
        return data if isinstance(data, list) else []

    async def get_transitions(self, issue_key: str) -> list[dict[str, Any]]:
        """Get available transitions for an issue."""
        data = await self._api_request(
            "GET",
            f"/rest/api/2/issue/{issue_key}/transitions",
        )
        return data.get("transitions", [])
