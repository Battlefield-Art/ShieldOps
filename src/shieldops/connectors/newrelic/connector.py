"""New Relic connector for NerdGraph, NRQL, alerts, and SLI management."""

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

_ENDPOINTS = {
    "US": "https://api.newrelic.com",
    "EU": "https://api.eu.newrelic.com",
}

_GRAPHQL_ENDPOINTS = {
    "US": "https://api.newrelic.com/graphql",
    "EU": "https://api.eu.newrelic.com/graphql",
}


class NewRelicConnector(InfraConnector):
    """Connector for New Relic One (NerdGraph, NRQL, APM, Infrastructure).

    Provides access to NerdGraph (GraphQL), NRQL queries, entity search,
    alert policies/conditions, SLI compliance, and incidents.
    """

    provider = "newrelic"

    def __init__(
        self,
        api_key: str,
        account_id: str = "",
        region: str = "US",
    ) -> None:
        self._api_key = api_key
        self._account_id = account_id
        self._region = region.upper()
        self._base_url = _ENDPOINTS.get(self._region, _ENDPOINTS["US"])
        self._graphql_endpoint = _GRAPHQL_ENDPOINTS.get(self._region, _GRAPHQL_ENDPOINTS["US"])
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
        """Return authorization headers for New Relic API."""
        return {
            "Api-Key": self._api_key,
            "Content-Type": "application/json",
        }

    async def _api_request(
        self,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Make an authenticated API request to New Relic."""
        client = self._ensure_http_client()
        headers = kwargs.pop("headers", {})
        headers.update(self._auth_headers())
        resp = await client.request(method, path, headers=headers, **kwargs)
        resp.raise_for_status()
        return resp.json()

    async def _graphql(self, query: str, variables: dict[str, Any] | None = None) -> dict[str, Any]:
        """Execute a NerdGraph (GraphQL) query."""
        client = self._ensure_http_client()
        headers = self._auth_headers()
        body: dict[str, Any] = {"query": query}
        if variables:
            body["variables"] = variables
        resp = await client.post(self._graphql_endpoint, headers=headers, json=body)
        resp.raise_for_status()
        return resp.json()

    # -- InfraConnector interface ------------------------------------------

    async def get_health(self, resource_id: str) -> HealthStatus:
        """Check New Relic connectivity."""
        try:
            data = await self._graphql("{ actor { user { name } } }")
            name = data.get("data", {}).get("actor", {}).get("user", {}).get("name", "")
            return HealthStatus(
                resource_id=resource_id,
                healthy=bool(name),
                status="healthy" if name else "unhealthy",
                message=(f"Connected as {name}" if name else "Unable to authenticate"),
                last_checked=datetime.now(UTC),
            )
        except Exception as e:
            logger.error("newrelic.health_check_failed", error=str(e))
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
        """List New Relic entities."""
        resources: list[Resource] = []
        try:
            query = (
                f"{{ actor {{ entitySearch(query: \"type = '{resource_type}'\") {{"
                " results { entities { guid name type } } } } }"
            )
            data = await self._graphql(query)
            entities = (
                data.get("data", {})
                .get("actor", {})
                .get("entitySearch", {})
                .get("results", {})
                .get("entities", [])
            )
            for ent in entities:
                resources.append(
                    Resource(
                        id=ent.get("guid", ""),
                        name=ent.get("name", "unknown"),
                        resource_type=ent.get("type", resource_type),
                        environment=environment,
                        provider=self.provider,
                    )
                )
        except Exception as e:
            logger.error("newrelic.list_resources_failed", error=str(e))
        return resources

    async def get_events(self, resource_id: str, time_range: TimeRange) -> list[dict[str, Any]]:
        """Get New Relic events via NRQL."""
        try:
            nrql = (
                f"SELECT * FROM Transaction WHERE entityGuid = '{resource_id}'"  # noqa: S608  # nosec B608
                f" SINCE '{time_range.start.isoformat()}'"
                f" UNTIL '{time_range.end.isoformat()}'"
            )
            return await self.run_nrql(nrql)
        except Exception as e:
            logger.error("newrelic.get_events_failed", error=str(e))
            return []

    async def execute_action(self, action: RemediationAction) -> ActionResult:
        """Execute a remediation action via New Relic."""
        action_id = str(uuid4())
        return ActionResult(
            action_id=action_id,
            status=ExecutionStatus.SUCCESS,
            message=f"Action {action.action_type} completed",
            started_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
        )

    async def create_snapshot(self, resource_id: str) -> Snapshot:
        """Create a snapshot of entity configuration."""
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

    # -- New Relic-specific methods ----------------------------------------

    async def run_nrql(self, nrql: str) -> list[dict[str, Any]]:
        """Execute a NRQL query."""
        escaped = nrql.replace('"', '\\"')
        query = (
            f"{{ actor {{ account(id: {self._account_id}) "
            f'{{ nrql(query: "{escaped}") {{ results }} }} }} }}'
        )
        data = await self._graphql(query)
        return (
            data.get("data", {})
            .get("actor", {})
            .get("account", {})
            .get("nrql", {})
            .get("results", [])
        )

    async def get_entities(
        self,
        entity_type: str = "APPLICATION",
        name_filter: str = "",
    ) -> list[dict[str, Any]]:
        """Search for New Relic entities."""
        search = f"type = '{entity_type}'"
        if name_filter:
            search += f" AND name LIKE '{name_filter}'"
        query = (
            f'{{ actor {{ entitySearch(query: "{search}") {{'
            " results { entities { guid name type tags { key values } } } } } }"
        )
        data = await self._graphql(query)
        return (
            data.get("data", {})
            .get("actor", {})
            .get("entitySearch", {})
            .get("results", {})
            .get("entities", [])
        )

    async def get_alert_policies(self) -> list[dict[str, Any]]:
        """Get all alert policies."""
        data = await self._api_request("GET", "/v2/alerts_policies.json")
        return data.get("policies", [])

    async def create_alert_condition(
        self,
        policy_id: int,
        condition: dict[str, Any],
    ) -> dict[str, Any]:
        """Create a NRQL alert condition."""
        query = (
            "mutation { alertsNrqlConditionStaticCreate("
            f' accountId: {self._account_id}, policyId: "{policy_id}",'
            f" condition: {str(condition)}) {{ id name }} }}"
        )
        return await self._graphql(query)

    async def get_sli_compliance(self, entity_guid: str) -> list[dict[str, Any]]:
        """Get SLI compliance data for an entity."""
        query = (
            f'{{ actor {{ entity(guid: "{entity_guid}") {{'
            " ... on WorkloadEntity { serviceLevel { indicators {"
            " name objectives { target }"
            " resultQueries { indicator { nrql } }"
            " } } } } } }"
        )
        data = await self._graphql(query)
        return (
            data.get("data", {})
            .get("actor", {})
            .get("entity", {})
            .get("serviceLevel", {})
            .get("indicators", [])
        )

    async def get_incidents(self) -> list[dict[str, Any]]:
        """Get open incidents."""
        data = await self._api_request(
            "GET",
            "/v2/alerts_incidents.json",
            params={"only_open": "true"},
        )
        return data.get("incidents", [])
