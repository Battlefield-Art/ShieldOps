"""Wiz cloud security connector for issues, vulnerabilities, attack paths, and graph queries."""

from __future__ import annotations

import asyncio
import time
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

_WIZ_AUTH_URL = "https://auth.app.wiz.io/oauth/token"


class WizConnector(InfraConnector):
    """Connector for Wiz cloud security platform.

    Provides access to cloud resource inventory, security issues,
    vulnerability findings, attack paths, and the Wiz Security Graph.
    All queries use the Wiz GraphQL API.
    """

    provider = "wiz"

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        api_url: str = "https://api.us1.app.wiz.io",
    ) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        self._api_url = api_url.rstrip("/")
        self._access_token: str | None = None
        self._token_expires_at: float = 0.0
        self._http_client: Any = None
        self._snapshots: dict[str, dict[str, Any]] = {}

    def _ensure_http_client(self) -> Any:
        """Lazily initialize httpx async client."""
        if self._http_client is None:
            import httpx

            self._http_client = httpx.AsyncClient(timeout=30.0)
        return self._http_client

    async def _ensure_auth(self) -> None:
        """Obtain or refresh Wiz OAuth2 token via client credentials."""
        if self._access_token and time.time() < self._token_expires_at - 60:
            return

        client = self._ensure_http_client()
        resp = await client.post(
            _WIZ_AUTH_URL,
            json={
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "audience": "wiz-api",
                "grant_type": "client_credentials",
            },
        )
        resp.raise_for_status()
        data = resp.json()
        self._access_token = data["access_token"]
        self._token_expires_at = time.time() + data.get("expires_in", 3599)
        logger.info("wiz.auth_refreshed", expires_in=data.get("expires_in"))

    async def _graphql_request(
        self,
        query: str,
        variables: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute a GraphQL request against the Wiz API."""
        await self._ensure_auth()
        client = self._ensure_http_client()
        resp = await client.post(
            f"{self._api_url}/graphql",
            json={"query": query, "variables": variables or {}},
            headers={
                "Authorization": f"Bearer {self._access_token}",
                "Content-Type": "application/json",
            },
        )
        resp.raise_for_status()
        result = resp.json()
        if "errors" in result:
            logger.error("wiz.graphql_error", errors=result["errors"])
        return result.get("data", {})

    # -- InfraConnector interface ------------------------------------------

    async def get_health(self, resource_id: str) -> HealthStatus:
        """Get health status of a Wiz-tracked cloud resource."""
        try:
            query = """
            query GetResource($id: String!) {
                cloudResource(id: $id) {
                    id name type status nativeType region
                    subscriptionExternalId
                    issues(first: 5) { nodes { id severity status } }
                }
            }
            """
            data = await self._graphql_request(query, {"id": resource_id})
            resource = data.get("cloudResource", {})
            if not resource:
                return HealthStatus(
                    resource_id=resource_id,
                    healthy=False,
                    status="not_found",
                    message="Resource not found in Wiz",
                    last_checked=datetime.now(UTC),
                )
            issues = resource.get("issues", {}).get("nodes", [])
            critical_count = sum(1 for i in issues if i.get("severity") in ("CRITICAL", "HIGH"))
            healthy = critical_count == 0
            return HealthStatus(
                resource_id=resource_id,
                healthy=healthy,
                status=resource.get("status", "unknown"),
                message=f"{critical_count} critical/high issues" if critical_count else "Clean",
                last_checked=datetime.now(UTC),
                metrics={
                    "open_issues": float(len(issues)),
                    "critical_high_issues": float(critical_count),
                },
            )
        except Exception as e:
            logger.error("wiz.health_check_failed", resource_id=resource_id, error=str(e))
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
        """List cloud resources from Wiz inventory."""
        resources: list[Resource] = []
        try:
            graph_filter = filters.get("graph_filter", {}) if filters else {}
            query = """
            query ListResources($type: [String!], $first: Int) {
                cloudResources(filterBy: {type: $type}, first: $first) {
                    nodes {
                        id name type status nativeType region
                        subscriptionExternalId cloudPlatform
                    }
                }
            }
            """
            data = await self._graphql_request(
                query,
                {"type": [resource_type], "first": graph_filter.get("limit", 100)},
            )
            for r in data.get("cloudResources", {}).get("nodes", []):
                resources.append(
                    Resource(
                        id=r.get("id", ""),
                        name=r.get("name", "unknown"),
                        resource_type=r.get("type", resource_type),
                        environment=environment,
                        provider=self.provider,
                        labels={
                            "cloud_platform": r.get("cloudPlatform", ""),
                            "region": r.get("region", ""),
                            "native_type": r.get("nativeType", ""),
                        },
                        metadata={
                            "status": r.get("status"),
                            "subscription": r.get("subscriptionExternalId"),
                        },
                    )
                )
        except Exception as e:
            logger.error(
                "wiz.list_resources_failed",
                resource_type=resource_type,
                error=str(e),
            )
        return resources

    async def get_events(self, resource_id: str, time_range: TimeRange) -> list[dict[str, Any]]:
        """Get security findings/issues for a resource within a time range."""
        query = """
        query GetIssues($resourceId: String!, $after: DateTime, $before: DateTime) {
            issues(
                filterBy: {
                    relatedEntity: {id: $resourceId}
                    createdAt: {after: $after, before: $before}
                }
                first: 200
            ) {
                nodes {
                    id title severity status type
                    createdAt updatedAt
                    entitySnapshot { id name type }
                }
            }
        }
        """
        try:
            data = await self._graphql_request(
                query,
                {
                    "resourceId": resource_id,
                    "after": time_range.start.isoformat(),
                    "before": time_range.end.isoformat(),
                },
            )
            return data.get("issues", {}).get("nodes", [])
        except Exception as e:
            logger.error("wiz.get_events_failed", resource_id=resource_id, error=str(e))
            return []

    async def execute_action(self, action: RemediationAction) -> ActionResult:
        """Execute a remediation action through Wiz Actions."""
        started = datetime.now(UTC)
        try:
            if action.action_type == "resolve_issue":
                mutation = """
                mutation UpdateIssue($id: ID!, $patch: UpdateIssuePatch!) {
                    updateIssue(input: {id: $id, patch: $patch}) { issue { id status } }
                }
                """
                await self._graphql_request(
                    mutation,
                    {
                        "id": action.parameters.get("issue_id", action.target_resource),
                        "patch": {"status": "RESOLVED", "resolution": "REMEDIATED"},
                    },
                )
                return ActionResult(
                    action_id=action.id,
                    status=ExecutionStatus.SUCCESS,
                    message="Issue resolved in Wiz",
                    started_at=started,
                    completed_at=datetime.now(UTC),
                )
            elif action.action_type == "create_ticket":
                mutation = """
                mutation CreateTicket($issueId: ID!, $project: String!) {
                    createServiceTicket(input: {issueId: $issueId, project: $project}) {
                        ticket { id url }
                    }
                }
                """
                await self._graphql_request(
                    mutation,
                    {
                        "issueId": action.target_resource,
                        "project": action.parameters.get("project", "default"),
                    },
                )
                return ActionResult(
                    action_id=action.id,
                    status=ExecutionStatus.SUCCESS,
                    message="Service ticket created",
                    started_at=started,
                    completed_at=datetime.now(UTC),
                )
            else:
                return ActionResult(
                    action_id=action.id,
                    status=ExecutionStatus.FAILED,
                    message=f"Unsupported action type: {action.action_type}",
                    started_at=started,
                    completed_at=datetime.now(UTC),
                )
        except Exception as e:
            logger.error("wiz.execute_action_failed", action_id=action.id, error=str(e))
            return ActionResult(
                action_id=action.id,
                status=ExecutionStatus.FAILED,
                message=str(e),
                started_at=started,
                completed_at=datetime.now(UTC),
                error=str(e),
            )

    async def create_snapshot(self, resource_id: str) -> Snapshot:
        """Capture current issue state for a resource."""
        query = """
        query SnapshotIssues($resourceId: String!) {
            issues(filterBy: {relatedEntity: {id: $resourceId}}, first: 500) {
                nodes { id title severity status type createdAt }
            }
        }
        """
        data = await self._graphql_request(query, {"resourceId": resource_id})
        snapshot_id = str(uuid4())
        state = {
            "issues": data.get("issues", {}).get("nodes", []),
            "captured_at": datetime.now(UTC).isoformat(),
        }
        self._snapshots[snapshot_id] = state
        logger.info("wiz.snapshot_created", snapshot_id=snapshot_id)
        return Snapshot(
            id=snapshot_id,
            resource_id=resource_id,
            snapshot_type="wiz_issues",
            state=state,
            created_at=datetime.now(UTC),
        )

    async def rollback(self, snapshot_id: str) -> ActionResult:
        """Restore issue statuses from a snapshot (reopen resolved issues)."""
        started = datetime.now(UTC)
        state = self._snapshots.get(snapshot_id)
        if not state:
            return ActionResult(
                action_id=snapshot_id,
                status=ExecutionStatus.FAILED,
                message=f"Snapshot {snapshot_id} not found",
                started_at=started,
                completed_at=datetime.now(UTC),
            )
        try:
            mutation = """
            mutation UpdateIssue($id: ID!, $patch: UpdateIssuePatch!) {
                updateIssue(input: {id: $id, patch: $patch}) { issue { id status } }
            }
            """
            for issue in state.get("issues", []):
                await self._graphql_request(
                    mutation,
                    {"id": issue["id"], "patch": {"status": issue.get("status", "OPEN")}},
                )
            logger.info("wiz.rollback_completed", snapshot_id=snapshot_id)
            return ActionResult(
                action_id=snapshot_id,
                status=ExecutionStatus.SUCCESS,
                message="Issue statuses restored from snapshot",
                started_at=started,
                completed_at=datetime.now(UTC),
                snapshot_id=snapshot_id,
            )
        except Exception as e:
            logger.error("wiz.rollback_failed", snapshot_id=snapshot_id, error=str(e))
            return ActionResult(
                action_id=snapshot_id,
                status=ExecutionStatus.FAILED,
                message=str(e),
                started_at=started,
                completed_at=datetime.now(UTC),
                error=str(e),
            )

    async def validate_health(self, resource_id: str, timeout_seconds: int = 300) -> bool:
        """Verify resource health after remediation with polling."""
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            health = await self.get_health(resource_id)
            if health.healthy:
                logger.info("wiz.health_validated", resource_id=resource_id)
                return True
            await asyncio.sleep(10)
        logger.warning(
            "wiz.health_validation_timeout",
            resource_id=resource_id,
            timeout=timeout_seconds,
        )
        return False

    # -- Wiz-specific methods ----------------------------------------------

    async def get_issues(
        self,
        severity: str = "",
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get security issues filtered by severity."""
        filter_by = {}
        if severity:
            filter_by["severity"] = [severity.upper()]
        query = """
        query GetIssues($filterBy: IssueFilters, $first: Int) {
            issues(filterBy: $filterBy, first: $first) {
                nodes {
                    id title severity status type
                    createdAt updatedAt
                    entitySnapshot { id name type }
                    remediation { description steps }
                }
            }
        }
        """
        data = await self._graphql_request(
            query,
            {"filterBy": filter_by, "first": limit},
        )
        return data.get("issues", {}).get("nodes", [])

    async def get_cloud_config_findings(self, limit: int = 100) -> list[dict[str, Any]]:
        """Get cloud configuration findings (misconfigurations)."""
        query = """
        query ConfigFindings($first: Int) {
            configurationFindings(first: $first) {
                nodes {
                    id title severity status
                    rule { id name description }
                    resource { id name type cloudPlatform }
                }
            }
        }
        """
        data = await self._graphql_request(query, {"first": limit})
        return data.get("configurationFindings", {}).get("nodes", [])

    async def get_vulnerability_findings(self, limit: int = 100) -> list[dict[str, Any]]:
        """Get vulnerability findings from Wiz."""
        query = """
        query VulnFindings($first: Int) {
            vulnerabilityFindings(first: $first) {
                nodes {
                    id name severity
                    CVEDescription CVSSSeverity
                    hasFix fixedVersion
                    detailedName version
                    vulnerableAsset { id name type }
                }
            }
        }
        """
        data = await self._graphql_request(query, {"first": limit})
        return data.get("vulnerabilityFindings", {}).get("nodes", [])

    async def get_attack_paths(self, limit: int = 50) -> list[dict[str, Any]]:
        """Get attack paths identified by Wiz Security Graph."""
        query = """
        query AttackPaths($first: Int) {
            attackPaths(first: $first) {
                nodes {
                    id name severity
                    sourceResource { id name type }
                    targetResource { id name type }
                    pathNodes { id name type }
                    mitigations { description }
                }
            }
        }
        """
        data = await self._graphql_request(query, {"first": limit})
        return data.get("attackPaths", {}).get("nodes", [])

    async def run_graph_query(self, graph_query: str) -> list[dict[str, Any]]:
        """Run a raw Wiz Security Graph query."""
        query = """
        query RunGraphQuery($query: String!) {
            graphSearch(query: $query, first: 200) {
                nodes { entities { id name type properties } }
            }
        }
        """
        data = await self._graphql_request(query, {"query": graph_query})
        return data.get("graphSearch", {}).get("nodes", [])

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None
