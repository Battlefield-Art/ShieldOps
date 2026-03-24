"""Microsoft 365 Defender connector for machines, alerts, and advanced hunting."""

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

_DEFENDER_API_BASE = "https://api.securitycenter.microsoft.com"
_LOGIN_BASE = "https://login.microsoftonline.com"


class MicrosoftDefenderConnector(InfraConnector):
    """Connector for Microsoft 365 Defender (MDE).

    Provides access to machine management, alert triage, incident correlation,
    advanced hunting (KQL), machine isolation, and antivirus scanning.
    """

    provider = "microsoft_defender"

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
    ) -> None:
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
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
        """Obtain or refresh Azure AD token via client credentials (MSAL pattern)."""
        if self._access_token and time.time() < self._token_expires_at - 60:
            return

        client = self._ensure_http_client()
        token_url = f"{_LOGIN_BASE}/{self._tenant_id}/oauth2/v2.0/token"
        resp = await client.post(
            token_url,
            data={
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "scope": "https://api.securitycenter.microsoft.com/.default",
                "grant_type": "client_credentials",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp.raise_for_status()
        data = resp.json()
        self._access_token = data["access_token"]
        self._token_expires_at = time.time() + data.get("expires_in", 3599)
        logger.info("defender.auth_refreshed", expires_in=data.get("expires_in"))

    async def _api_request(
        self,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Make an authenticated request to the Microsoft Defender API."""
        await self._ensure_auth()
        client = self._ensure_http_client()
        url = f"{_DEFENDER_API_BASE}{path}"
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {self._access_token}"
        headers.setdefault("Content-Type", "application/json")
        resp = await client.request(method, url, headers=headers, **kwargs)
        resp.raise_for_status()
        return resp.json()

    # -- InfraConnector interface ------------------------------------------

    async def get_health(self, resource_id: str) -> HealthStatus:
        """Get machine health status from MDE."""
        try:
            data = await self._api_request("GET", f"/api/machines/{resource_id}")
            status = data.get("healthStatus", "unknown")
            healthy = status.lower() in ("active", "inactive")
            return HealthStatus(
                resource_id=resource_id,
                healthy=healthy,
                status=status,
                message=data.get("lastSeen"),
                last_checked=datetime.now(UTC),
                metrics={
                    "risk_score": float(data.get("riskScore", 0)),
                    "exposure_level": {"low": 1.0, "medium": 2.0, "high": 3.0}.get(
                        data.get("exposureLevel", "low"), 0.0
                    ),
                },
            )
        except Exception as e:
            logger.error("defender.health_check_failed", resource_id=resource_id, error=str(e))
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
        """List Defender resources (machines or alerts)."""
        resources: list[Resource] = []
        try:
            if resource_type in ("machine", "host", "device"):
                odata_filter = filters.get("odata_filter", "") if filters else ""
                params: dict[str, str] = {}
                if odata_filter:
                    params["$filter"] = odata_filter
                data = await self._api_request("GET", "/api/machines", params=params)
                for m in data.get("value", []):
                    resources.append(
                        Resource(
                            id=m.get("id", ""),
                            name=m.get("computerDnsName", "unknown"),
                            resource_type="machine",
                            environment=environment,
                            provider=self.provider,
                            labels={
                                "os_platform": m.get("osPlatform", ""),
                                "os_version": m.get("osVersion", ""),
                            },
                            metadata={
                                "health_status": m.get("healthStatus"),
                                "risk_score": m.get("riskScore"),
                                "exposure_level": m.get("exposureLevel"),
                                "last_seen": m.get("lastSeen"),
                            },
                        )
                    )
            elif resource_type == "alert":
                data = await self._api_request("GET", "/api/alerts")
                for a in data.get("value", []):
                    resources.append(
                        Resource(
                            id=a.get("id", ""),
                            name=a.get("title", "unknown"),
                            resource_type="alert",
                            environment=environment,
                            provider=self.provider,
                            labels={
                                "severity": a.get("severity", ""),
                                "status": a.get("status", ""),
                            },
                            metadata={
                                "category": a.get("category"),
                                "detection_source": a.get("detectionSource"),
                            },
                        )
                    )
        except Exception as e:
            logger.error(
                "defender.list_resources_failed",
                resource_type=resource_type,
                error=str(e),
            )
        return resources

    async def get_events(self, resource_id: str, time_range: TimeRange) -> list[dict[str, Any]]:
        """Run an advanced hunting query for events on a machine."""
        kql = (
            f"DeviceEvents "
            f"| where DeviceId == '{resource_id}' "
            f"| where Timestamp between (datetime({time_range.start.isoformat()}) "
            f".. datetime({time_range.end.isoformat()})) "
            f"| take 500"
        )
        return await self.run_hunting_query(kql)

    async def execute_action(self, action: RemediationAction) -> ActionResult:
        """Execute a remediation action on a Defender-managed machine."""
        started = datetime.now(UTC)
        try:
            if action.action_type == "isolate":
                await self.isolate_machine(
                    action.target_resource,
                    comment=action.parameters.get("comment", "ShieldOps auto-isolation"),
                )
                return ActionResult(
                    action_id=action.id,
                    status=ExecutionStatus.SUCCESS,
                    message=f"Machine {action.target_resource} isolated",
                    started_at=started,
                    completed_at=datetime.now(UTC),
                )
            elif action.action_type == "antivirus_scan":
                scan_type = action.parameters.get("scan_type", "Quick")
                await self._api_request(
                    "POST",
                    f"/api/machines/{action.target_resource}/runAntiVirusScan",
                    json={"Comment": "ShieldOps scan", "ScanType": scan_type},
                )
                return ActionResult(
                    action_id=action.id,
                    status=ExecutionStatus.SUCCESS,
                    message=f"{scan_type} antivirus scan initiated",
                    started_at=started,
                    completed_at=datetime.now(UTC),
                )
            elif action.action_type == "release":
                await self.release_machine(
                    action.target_resource,
                    comment=action.parameters.get("comment", "ShieldOps release"),
                )
                return ActionResult(
                    action_id=action.id,
                    status=ExecutionStatus.SUCCESS,
                    message=f"Machine {action.target_resource} released from isolation",
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
            logger.error("defender.execute_action_failed", action_id=action.id, error=str(e))
            return ActionResult(
                action_id=action.id,
                status=ExecutionStatus.FAILED,
                message=str(e),
                started_at=started,
                completed_at=datetime.now(UTC),
                error=str(e),
            )

    async def create_snapshot(self, resource_id: str) -> Snapshot:
        """Capture current machine state and alert status."""
        machine = await self._api_request("GET", f"/api/machines/{resource_id}")
        alerts = await self._api_request(
            "GET",
            "/api/alerts",
            params={"$filter": f"machineId eq '{resource_id}'"},
        )
        snapshot_id = str(uuid4())
        state = {
            "machine": machine,
            "alerts": alerts.get("value", []),
            "captured_at": datetime.now(UTC).isoformat(),
        }
        self._snapshots[snapshot_id] = state
        logger.info("defender.snapshot_created", snapshot_id=snapshot_id)
        return Snapshot(
            id=snapshot_id,
            resource_id=resource_id,
            snapshot_type="defender_state",
            state=state,
            created_at=datetime.now(UTC),
        )

    async def rollback(self, snapshot_id: str) -> ActionResult:
        """Release isolation if machine was isolated since snapshot."""
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
            resource_id = state["machine"].get("id", "")
            current = await self._api_request("GET", f"/api/machines/{resource_id}")
            if current.get("healthStatus") == "Isolated":
                await self.release_machine(resource_id, comment="ShieldOps rollback")
            logger.info("defender.rollback_completed", snapshot_id=snapshot_id)
            return ActionResult(
                action_id=snapshot_id,
                status=ExecutionStatus.SUCCESS,
                message="Machine state restored from snapshot",
                started_at=started,
                completed_at=datetime.now(UTC),
                snapshot_id=snapshot_id,
            )
        except Exception as e:
            logger.error("defender.rollback_failed", snapshot_id=snapshot_id, error=str(e))
            return ActionResult(
                action_id=snapshot_id,
                status=ExecutionStatus.FAILED,
                message=str(e),
                started_at=started,
                completed_at=datetime.now(UTC),
                error=str(e),
            )

    async def validate_health(self, resource_id: str, timeout_seconds: int = 300) -> bool:
        """Verify machine health after an action with polling."""
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            health = await self.get_health(resource_id)
            if health.healthy:
                logger.info("defender.health_validated", resource_id=resource_id)
                return True
            await asyncio.sleep(5)
        logger.warning(
            "defender.health_validation_timeout",
            resource_id=resource_id,
            timeout=timeout_seconds,
        )
        return False

    # -- Defender-specific methods -----------------------------------------

    async def get_alerts(
        self,
        odata_filter: str = "",
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get alerts from Microsoft Defender."""
        params: dict[str, Any] = {"$top": limit}
        if odata_filter:
            params["$filter"] = odata_filter
        data = await self._api_request("GET", "/api/alerts", params=params)
        return data.get("value", [])

    async def get_incidents(
        self,
        odata_filter: str = "",
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get incidents from Microsoft 365 Defender."""
        params: dict[str, Any] = {"$top": limit}
        if odata_filter:
            params["$filter"] = odata_filter
        data = await self._api_request("GET", "/api/incidents", params=params)
        return data.get("value", [])

    async def run_hunting_query(self, kql: str) -> list[dict[str, Any]]:
        """Run an advanced hunting KQL query."""
        data = await self._api_request(
            "POST",
            "/api/advancedhunting/run",
            json={"Query": kql},
        )
        return data.get("Results", [])

    async def isolate_machine(self, machine_id: str, comment: str = "") -> dict[str, Any]:
        """Isolate a machine from the network."""
        result = await self._api_request(
            "POST",
            f"/api/machines/{machine_id}/isolate",
            json={"Comment": comment or "ShieldOps isolation", "IsolationType": "Full"},
        )
        logger.info("defender.machine_isolated", machine_id=machine_id)
        return result

    async def release_machine(self, machine_id: str, comment: str = "") -> dict[str, Any]:
        """Release a machine from isolation."""
        result = await self._api_request(
            "POST",
            f"/api/machines/{machine_id}/unisolate",
            json={"Comment": comment or "ShieldOps release"},
        )
        logger.info("defender.machine_released", machine_id=machine_id)
        return result

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None
