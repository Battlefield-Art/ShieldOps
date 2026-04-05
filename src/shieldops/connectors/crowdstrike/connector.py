"""CrowdStrike Falcon connector for detections, incidents, RTR, and IOC management."""

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


class CrowdStrikeConnector(InfraConnector):
    """Connector for CrowdStrike Falcon platform.

    Provides access to detections, incidents, real-time response (RTR),
    host containment, threat graph, and IOC management APIs.
    """

    provider = "crowdstrike"

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        base_url: str = "https://api.crowdstrike.com",
    ) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        self._base_url = base_url.rstrip("/")
        self._access_token: str | None = None
        self._token_expires_at: float = 0.0
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

    async def _ensure_auth(self) -> None:
        """Obtain or refresh OAuth2 bearer token via client credentials grant."""
        if self._access_token and time.time() < self._token_expires_at - 60:
            return

        client = self._ensure_http_client()
        resp = await client.post(
            "/oauth2/token",
            data={
                "client_id": self._client_id,
                "client_secret": self._client_secret,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp.raise_for_status()
        data = resp.json()
        self._access_token = data["access_token"]
        self._token_expires_at = time.time() + data.get("expires_in", 1799)
        logger.info("crowdstrike.auth_refreshed", expires_in=data.get("expires_in"))

    async def _api_request(
        self,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Make an authenticated API request to CrowdStrike."""
        await self._ensure_auth()
        client = self._ensure_http_client()
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {self._access_token}"
        resp = await client.request(method, path, headers=headers, **kwargs)
        resp.raise_for_status()
        return resp.json()

    # -- InfraConnector interface ------------------------------------------

    async def get_health(self, resource_id: str) -> HealthStatus:
        """Get health of a CrowdStrike-managed host via device details."""
        try:
            data = await self._api_request(
                "GET",
                "/devices/entities/devices/v2",
                params={"ids": resource_id},
            )
            devices = data.get("resources", [])
            if not devices:
                return HealthStatus(
                    resource_id=resource_id,
                    healthy=False,
                    status="not_found",
                    message="Device not found in CrowdStrike",
                    last_checked=datetime.now(UTC),
                )
            device = devices[0]
            status = device.get("status", "unknown")
            healthy = status.lower() in ("normal", "online", "contained")
            return HealthStatus(
                resource_id=resource_id,
                healthy=healthy,
                status=status,
                message=device.get("last_seen"),
                last_checked=datetime.now(UTC),
                metrics={
                    "prevention_policy_applied": float(
                        bool(device.get("prevention_policy_applied"))
                    ),
                },
            )
        except Exception as e:
            logger.error("crowdstrike.health_check_failed", resource_id=resource_id, error=str(e))
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
        """List CrowdStrike resources (devices or detections)."""
        resources: list[Resource] = []
        try:
            if resource_type in ("host", "device"):
                fql = filters.get("fql", "") if filters else ""
                data = await self._api_request(
                    "GET",
                    "/devices/queries/devices-scroll/v1",
                    params={"filter": fql, "limit": 100},
                )
                device_ids = data.get("resources", [])
                if device_ids:
                    details = await self._api_request(
                        "GET",
                        "/devices/entities/devices/v2",
                        params={"ids": device_ids},
                    )
                    for d in details.get("resources", []):
                        resources.append(
                            Resource(
                                id=d.get("device_id", ""),
                                name=d.get("hostname", "unknown"),
                                resource_type="host",
                                environment=environment,
                                provider=self.provider,
                                labels={
                                    "platform": d.get("platform_name", ""),
                                    "os_version": d.get("os_version", ""),
                                },
                                metadata={
                                    "agent_version": d.get("agent_version"),
                                    "last_seen": d.get("last_seen"),
                                    "status": d.get("status"),
                                },
                            )
                        )
            elif resource_type == "detection":
                fql = filters.get("fql", "") if filters else ""
                data = await self._api_request(
                    "GET",
                    "/detects/queries/detects/v1",
                    params={"filter": fql, "limit": 100},
                )
                for det_id in data.get("resources", []):
                    resources.append(
                        Resource(
                            id=det_id,
                            name=det_id,
                            resource_type="detection",
                            environment=environment,
                            provider=self.provider,
                        )
                    )
        except Exception as e:
            logger.error(
                "crowdstrike.list_resources_failed",
                resource_type=resource_type,
                error=str(e),
            )
        return resources

    async def get_events(self, resource_id: str, time_range: TimeRange) -> list[dict[str, Any]]:
        """Get detection events for a host within a time range."""
        try:
            fql = (
                f"device.device_id:'{resource_id}'"
                f"+created_timestamp:>'{time_range.start.isoformat()}'"
                f"+created_timestamp:<'{time_range.end.isoformat()}'"
            )
            query = await self._api_request(
                "GET",
                "/detects/queries/detects/v1",
                params={"filter": fql, "limit": 200},
            )
            detect_ids = query.get("resources", [])
            if not detect_ids:
                return []
            details = await self._api_request(
                "POST",
                "/detects/entities/summaries/GET/v1",
                json={"ids": detect_ids},
            )
            return details.get("resources", [])
        except Exception as e:
            logger.error(
                "crowdstrike.get_events_failed",
                resource_id=resource_id,
                error=str(e),
            )
            return []

    async def execute_action(self, action: RemediationAction) -> ActionResult:
        """Execute a remediation action via CrowdStrike RTR or policy APIs."""
        started = datetime.now(UTC)
        try:
            if action.action_type == "rtr_command":
                result = await self._api_request(
                    "POST",
                    "/real-time-response/entities/command/v1",
                    json={
                        "device_id": action.target_resource,
                        "base_command": action.parameters.get("command", "runscript"),
                        "command_string": action.parameters.get("command_string", ""),
                    },
                )
                return ActionResult(
                    action_id=action.id,
                    status=ExecutionStatus.SUCCESS,
                    message=(
                        f"RTR command executed: "
                        f"{result.get('resources', [{}])[0].get('stdout', '')}"
                    ),
                    started_at=started,
                    completed_at=datetime.now(UTC),
                )
            elif action.action_type == "update_prevention_policy":
                result = await self._api_request(
                    "PATCH",
                    "/policy/entities/prevention/v1",
                    json=action.parameters.get("policy_body", {}),
                )
                return ActionResult(
                    action_id=action.id,
                    status=ExecutionStatus.SUCCESS,
                    message="Prevention policy updated",
                    started_at=started,
                    completed_at=datetime.now(UTC),
                )
            elif action.action_type == "contain_host":
                await self.contain_host(action.target_resource)
                return ActionResult(
                    action_id=action.id,
                    status=ExecutionStatus.SUCCESS,
                    message=f"Host {action.target_resource} contained",
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
            logger.error("crowdstrike.execute_action_failed", action_id=action.id, error=str(e))
            return ActionResult(
                action_id=action.id,
                status=ExecutionStatus.FAILED,
                message=str(e),
                started_at=started,
                completed_at=datetime.now(UTC),
                error=str(e),
            )

    async def create_snapshot(self, resource_id: str) -> Snapshot:
        """Capture current prevention policies and host groups for rollback."""
        policies = await self._api_request(
            "GET",
            "/policy/queries/prevention/v1",
            params={"limit": 500},
        )
        policy_ids = policies.get("resources", [])
        policy_details: list[dict[str, Any]] = []
        if policy_ids:
            details = await self._api_request(
                "GET",
                "/policy/entities/prevention/v1",
                params={"ids": policy_ids},
            )
            policy_details = details.get("resources", [])

        host_groups = await self._api_request(
            "GET",
            "/devices/queries/host-groups/v1",
            params={"limit": 500},
        )

        snapshot_id = str(uuid4())
        state = {
            "prevention_policies": policy_details,
            "host_group_ids": host_groups.get("resources", []),
            "captured_at": datetime.now(UTC).isoformat(),
        }
        snapshot = Snapshot(
            id=snapshot_id,
            resource_id=resource_id,
            snapshot_type="crowdstrike_config",
            state=state,
            created_at=datetime.now(UTC),
        )
        self._snapshots[snapshot_id] = state
        logger.info("crowdstrike.snapshot_created", snapshot_id=snapshot_id)
        return snapshot

    async def rollback(self, snapshot_id: str) -> ActionResult:
        """Restore prevention policies from a snapshot."""
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
            for policy in state.get("prevention_policies", []):
                await self._api_request(
                    "PATCH",
                    "/policy/entities/prevention/v1",
                    json={"resources": [policy]},
                )
            logger.info("crowdstrike.rollback_completed", snapshot_id=snapshot_id)
            return ActionResult(
                action_id=snapshot_id,
                status=ExecutionStatus.SUCCESS,
                message="Policies restored from snapshot",
                started_at=started,
                completed_at=datetime.now(UTC),
                id=snapshot_id,
            )
        except Exception as e:
            logger.error("crowdstrike.rollback_failed", snapshot_id=snapshot_id, error=str(e))
            return ActionResult(
                action_id=snapshot_id,
                status=ExecutionStatus.FAILED,
                message=str(e),
                started_at=started,
                completed_at=datetime.now(UTC),
                error=str(e),
            )

    async def validate_health(self, resource_id: str, timeout_seconds: int = 300) -> bool:
        """Verify host status after an action with polling."""
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            health = await self.get_health(resource_id)
            if health.healthy:
                logger.info("crowdstrike.health_validated", resource_id=resource_id)
                return True
            await asyncio.sleep(5)
        logger.warning(
            "crowdstrike.health_validation_timeout",
            resource_id=resource_id,
            timeout=timeout_seconds,
        )
        return False

    # -- CrowdStrike-specific methods --------------------------------------

    async def get_detections(
        self,
        filter_query: str = "",
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Query Falcon detections with optional FQL filter."""
        query = await self._api_request(
            "GET",
            "/detects/queries/detects/v1",
            params={"filter": filter_query, "limit": limit},
        )
        detect_ids = query.get("resources", [])
        if not detect_ids:
            return []
        details = await self._api_request(
            "POST",
            "/detects/entities/summaries/GET/v1",
            json={"ids": detect_ids},
        )
        return details.get("resources", [])

    async def get_incidents(self, filter_query: str = "") -> list[dict[str, Any]]:
        """Query Falcon incidents."""
        query = await self._api_request(
            "GET",
            "/incidents/queries/incidents/v1",
            params={"filter": filter_query, "limit": 100},
        )
        incident_ids = query.get("resources", [])
        if not incident_ids:
            return []
        details = await self._api_request(
            "POST",
            "/incidents/entities/incidents/GET/v1",
            json={"ids": incident_ids},
        )
        return details.get("resources", [])

    async def contain_host(self, device_id: str) -> dict[str, Any]:
        """Network-contain a host via CrowdStrike RTR."""
        result = await self._api_request(
            "POST",
            "/devices/entities/devices-actions/v2",
            params={"action_name": "contain"},
            json={"ids": [device_id]},
        )
        logger.info("crowdstrike.host_contained", device_id=device_id)
        return result

    async def lift_containment(self, device_id: str) -> dict[str, Any]:
        """Remove network containment from a host."""
        result = await self._api_request(
            "POST",
            "/devices/entities/devices-actions/v2",
            params={"action_name": "lift_containment"},
            json={"ids": [device_id]},
        )
        logger.info("crowdstrike.containment_lifted", device_id=device_id)
        return result

    async def get_threat_graph(self, indicator: str) -> dict[str, Any]:
        """Query CrowdStrike Threat Graph for an indicator."""
        result = await self._api_request(
            "GET",
            "/threatgraph/queries/indicators/v1",
            params={"indicator": indicator},
        )
        return result

    async def query_iocs(
        self,
        ioc_type: str = "",
        value: str = "",
    ) -> list[dict[str, Any]]:
        """Query IOC management API for indicators of compromise."""
        params: dict[str, Any] = {"limit": 100}
        if ioc_type and value:
            params["filter"] = f"type:'{ioc_type}'+value:'{value}'"
        elif ioc_type:
            params["filter"] = f"type:'{ioc_type}'"
        query = await self._api_request(
            "GET",
            "/iocs/queries/indicators/v1",
            params=params,
        )
        ioc_ids = query.get("resources", [])
        if not ioc_ids:
            return []
        details = await self._api_request(
            "GET",
            "/iocs/entities/indicators/v1",
            params={"ids": ioc_ids},
        )
        return details.get("resources", [])

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None
