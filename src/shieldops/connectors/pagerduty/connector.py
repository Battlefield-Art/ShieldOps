"""PagerDuty connector for incident management, on-call, and event orchestration."""

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

_BASE_URL = "https://api.pagerduty.com"
_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"


class PagerDutyConnector(InfraConnector):
    """Connector for PagerDuty incident management and event orchestration.

    Provides access to PagerDuty services, incidents, on-call schedules,
    escalation policies, and the Events API v2 for triggering alerts.
    """

    provider = "pagerduty"

    def __init__(
        self,
        api_key: str = "",
        routing_key: str = "",
    ) -> None:
        self._api_key = api_key
        self._routing_key = routing_key
        self._client: Any = None
        self._snapshots: dict[str, dict[str, Any]] = {}

    def _ensure_client(self) -> Any:
        """Lazily initialize httpx async client."""
        if self._client is None:
            import httpx

            self._client = httpx.AsyncClient(
                timeout=60.0,
            )
        return self._client

    def _auth_headers(self) -> dict[str, str]:
        """Return authentication headers for PagerDuty REST API."""
        return {
            "Authorization": f"Token token={self._api_key}",
            "Content-Type": "application/json",
            "Accept": "application/vnd.pagerduty+json;version=2",
        }

    async def _api_request(
        self,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Make an authenticated API request to PagerDuty REST API."""
        client = self._ensure_client()
        headers = kwargs.pop("headers", {})
        headers.update(self._auth_headers())
        url = f"{_BASE_URL}{path}"
        resp = await client.request(method, url, headers=headers, **kwargs)
        resp.raise_for_status()
        if resp.status_code == 204:
            return {}
        return resp.json()

    # -- InfraConnector interface ------------------------------------------

    async def get_health(self, resource_id: str) -> HealthStatus:
        """Get PagerDuty service health status."""
        try:
            data = await self._api_request("GET", f"/services/{resource_id}")
            service = data.get("service", {})
            status = service.get("status", "unknown")
            healthy = status in ("active", "warning")
            return HealthStatus(
                resource_id=resource_id,
                healthy=healthy,
                status=status,
                message=f"Service '{service.get('name', '')}': {status}",
                last_checked=datetime.now(UTC),
                metrics={
                    "incident_count": len(service.get("incident_counts", {}).get("triggered", [])),
                },
            )
        except Exception as e:
            logger.error("pagerduty.health_check_failed", resource_id=resource_id, error=str(e))
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
        """List PagerDuty resources (services or incidents)."""
        resources: list[Resource] = []
        filters = filters or {}
        try:
            if resource_type in ("service", "services"):
                params: dict[str, Any] = {"limit": 100}
                if "query" in filters:
                    params["query"] = filters["query"]
                if "team_ids" in filters:
                    params["team_ids[]"] = filters["team_ids"]
                data = await self._api_request("GET", "/services", params=params)
                for svc in data.get("services", []):
                    resources.append(
                        Resource(
                            id=svc.get("id", ""),
                            name=svc.get("name", "unknown"),
                            resource_type="service",
                            environment=environment,
                            provider=self.provider,
                            labels={
                                "status": svc.get("status", ""),
                                "team": (
                                    svc.get("teams", [{}])[0].get("summary", "")
                                    if svc.get("teams")
                                    else ""
                                ),
                            },
                            metadata={
                                "description": svc.get("description", ""),
                                "escalation_policy_id": (
                                    svc.get("escalation_policy", {}).get("id", "")
                                ),
                                "created_at": svc.get("created_at", ""),
                            },
                        )
                    )
            elif resource_type in ("incident", "incidents"):
                params = {"limit": 100}
                if "statuses" in filters:
                    for s in filters["statuses"]:
                        params.setdefault("statuses[]", [])
                        if isinstance(params["statuses[]"], list):
                            params["statuses[]"].append(s)
                data = await self._api_request("GET", "/incidents", params=params)
                for inc in data.get("incidents", []):
                    resources.append(
                        Resource(
                            id=inc.get("id", ""),
                            name=inc.get("title", "unknown"),
                            resource_type="incident",
                            environment=environment,
                            provider=self.provider,
                            labels={
                                "status": inc.get("status", ""),
                                "urgency": inc.get("urgency", ""),
                            },
                            metadata={
                                "service_id": inc.get("service", {}).get("id", ""),
                                "created_at": inc.get("created_at", ""),
                                "incident_number": inc.get("incident_number", 0),
                            },
                        )
                    )
        except Exception as e:
            logger.error(
                "pagerduty.list_resources_failed",
                resource_type=resource_type,
                error=str(e),
            )
        return resources

    async def get_events(self, resource_id: str, time_range: TimeRange) -> list[dict[str, Any]]:
        """Get PagerDuty incidents for a service within a time range."""
        try:
            params = {
                "since": time_range.start.isoformat(),
                "until": time_range.end.isoformat(),
                "service_ids[]": resource_id,
                "limit": 100,
            }
            data = await self._api_request("GET", "/incidents", params=params)
            incidents = data.get("incidents", [])
            logger.info(
                "pagerduty.events_fetched",
                resource_id=resource_id,
                count=len(incidents),
            )
            return incidents
        except Exception as e:
            logger.error(
                "pagerduty.get_events_failed",
                resource_id=resource_id,
                error=str(e),
            )
            return []

    async def execute_action(self, action: RemediationAction) -> ActionResult:
        """Execute a PagerDuty action (acknowledge or resolve incident)."""
        started = datetime.now(UTC)
        try:
            if action.action_type in ("acknowledge", "resolve"):
                incident_id = action.parameters.get("incident_id", action.target_resource)
                body = {
                    "incident": {
                        "type": "incident_reference",
                        "status": (
                            "acknowledged" if action.action_type == "acknowledge" else "resolved"
                        ),
                    }
                }
                headers = self._auth_headers()
                from_email = action.parameters.get("from", "shieldops@shieldops.io")
                headers["From"] = from_email
                client = self._ensure_client()
                resp = await client.put(
                    f"{_BASE_URL}/incidents/{incident_id}",
                    headers=headers,
                    json=body,
                )
                resp.raise_for_status()
                return ActionResult(
                    action_id=action.id,
                    status=ExecutionStatus.SUCCESS,
                    message=f"Incident {incident_id} {action.action_type}d",
                    started_at=started,
                    completed_at=datetime.now(UTC),
                )
            elif action.action_type == "create_incident":
                result = await self.create_incident(
                    service_id=action.parameters.get("service_id", action.target_resource),
                    title=action.parameters.get("title", action.description),
                    body=action.parameters.get("body", ""),
                    urgency=action.parameters.get("urgency", "high"),
                    from_email=action.parameters.get("from", "shieldops@shieldops.io"),
                )
                return ActionResult(
                    action_id=action.id,
                    status=ExecutionStatus.SUCCESS,
                    message=f"Incident created: {result.get('incident', {}).get('id', '')}",
                    started_at=started,
                    completed_at=datetime.now(UTC),
                )
            elif action.action_type == "trigger_event":
                result = await self.trigger_event(
                    routing_key=action.parameters.get("routing_key", self._routing_key),
                    summary=action.parameters.get("summary", action.description),
                    severity=action.parameters.get("severity", "error"),
                    source=action.parameters.get("source", "shieldops"),
                )
                return ActionResult(
                    action_id=action.id,
                    status=ExecutionStatus.SUCCESS,
                    message=f"Event triggered: {result.get('dedup_key', '')}",
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
            logger.error("pagerduty.execute_action_failed", action_id=action.id, error=str(e))
            return ActionResult(
                action_id=action.id,
                status=ExecutionStatus.FAILED,
                message=str(e),
                started_at=started,
                completed_at=datetime.now(UTC),
                error=str(e),
            )

    async def create_snapshot(self, resource_id: str) -> Snapshot:
        """Capture service and escalation policy configurations for rollback."""
        service_data = await self._api_request("GET", f"/services/{resource_id}")
        service = service_data.get("service", {})
        ep_id = service.get("escalation_policy", {}).get("id", "")
        ep_data: dict[str, Any] = {}
        if ep_id:
            ep_data = await self._api_request("GET", f"/escalation_policies/{ep_id}")

        snapshot_id = str(uuid4())
        state = {
            "service": service,
            "escalation_policy": ep_data.get("escalation_policy", {}),
            "captured_at": datetime.now(UTC).isoformat(),
        }
        snapshot = Snapshot(
            id=snapshot_id,
            resource_id=resource_id,
            snapshot_type="pagerduty_config",
            state=state,
            created_at=datetime.now(UTC),
        )
        self._snapshots[snapshot_id] = state
        logger.info("pagerduty.snapshot_created", snapshot_id=snapshot_id)
        return snapshot

    async def rollback(self, snapshot_id: str) -> ActionResult:
        """Restore service and escalation policy from a snapshot."""
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
            service = state.get("service", {})
            service_id = service.get("id", "")
            if service_id:
                await self._api_request(
                    "PUT",
                    f"/services/{service_id}",
                    json={
                        "service": {
                            "name": service.get("name", ""),
                            "description": service.get("description", ""),
                            "escalation_policy": service.get("escalation_policy", {}),
                            "alert_creation": service.get(
                                "alert_creation", "create_alerts_and_incidents"
                            ),
                        }
                    },
                )
            ep = state.get("escalation_policy", {})
            ep_id = ep.get("id", "")
            if ep_id:
                await self._api_request(
                    "PUT",
                    f"/escalation_policies/{ep_id}",
                    json={
                        "escalation_policy": {
                            "name": ep.get("name", ""),
                            "escalation_rules": ep.get("escalation_rules", []),
                            "num_loops": ep.get("num_loops", 0),
                        }
                    },
                )
            logger.info("pagerduty.rollback_completed", snapshot_id=snapshot_id)
            return ActionResult(
                action_id=snapshot_id,
                status=ExecutionStatus.SUCCESS,
                message="Service and escalation policy restored from snapshot",
                started_at=started,
                completed_at=datetime.now(UTC),
                snapshot_id=snapshot_id,
            )
        except Exception as e:
            logger.error("pagerduty.rollback_failed", snapshot_id=snapshot_id, error=str(e))
            return ActionResult(
                action_id=snapshot_id,
                status=ExecutionStatus.FAILED,
                message=str(e),
                started_at=started,
                completed_at=datetime.now(UTC),
                error=str(e),
            )

    async def validate_health(self, resource_id: str, timeout_seconds: int = 300) -> bool:
        """Validate PagerDuty service health by polling."""
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            health = await self.get_health(resource_id)
            if health.healthy:
                logger.info("pagerduty.health_validated", resource_id=resource_id)
                return True
            await asyncio.sleep(5)
        logger.warning(
            "pagerduty.health_validation_timeout",
            resource_id=resource_id,
            timeout=timeout_seconds,
        )
        return False

    # -- PagerDuty-specific methods ----------------------------------------

    async def get_incidents(
        self,
        statuses: list[str] | None = None,
        urgencies: list[str] | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get PagerDuty incidents with optional status and urgency filters.

        Args:
            statuses: Filter by status (triggered, acknowledged, resolved).
            urgencies: Filter by urgency (high, low).
            limit: Maximum number of incidents to return.

        Returns:
            List of incident objects.
        """
        params: dict[str, Any] = {"limit": limit}
        if statuses:
            for s in statuses:
                params.setdefault("statuses[]", [])
                if isinstance(params["statuses[]"], list):
                    params["statuses[]"].append(s)
        if urgencies:
            for u in urgencies:
                params.setdefault("urgencies[]", [])
                if isinstance(params["urgencies[]"], list):
                    params["urgencies[]"].append(u)
        data = await self._api_request("GET", "/incidents", params=params)
        incidents = data.get("incidents", [])
        logger.info("pagerduty.incidents_fetched", count=len(incidents))
        return incidents

    async def create_incident(
        self,
        service_id: str,
        title: str,
        body: str = "",
        urgency: str = "high",
        from_email: str = "shieldops@shieldops.io",
    ) -> dict[str, Any]:
        """Create a new PagerDuty incident.

        Args:
            service_id: PagerDuty service ID to create the incident on.
            title: Incident title.
            body: Incident body/details.
            urgency: Incident urgency (high or low).
            from_email: Email of the user creating the incident.

        Returns:
            Created incident object.
        """
        payload: dict[str, Any] = {
            "incident": {
                "type": "incident",
                "title": title,
                "urgency": urgency,
                "service": {
                    "id": service_id,
                    "type": "service_reference",
                },
            }
        }
        if body:
            payload["incident"]["body"] = {
                "type": "incident_body",
                "details": body,
            }
        headers = self._auth_headers()
        headers["From"] = from_email
        client = self._ensure_client()
        resp = await client.post(
            f"{_BASE_URL}/incidents",
            headers=headers,
            json=payload,
        )
        resp.raise_for_status()
        result = resp.json()
        logger.info(
            "pagerduty.incident_created",
            service_id=service_id,
            title=title,
        )
        return result

    async def get_services(
        self,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get PagerDuty services.

        Args:
            limit: Maximum number of services to return.

        Returns:
            List of service objects.
        """
        data = await self._api_request(
            "GET",
            "/services",
            params={"limit": limit},
        )
        services = data.get("services", [])
        logger.info("pagerduty.services_fetched", count=len(services))
        return services

    async def get_oncall(
        self,
        schedule_id: str,
    ) -> list[dict[str, Any]]:
        """Get current on-call users for a schedule.

        Args:
            schedule_id: PagerDuty schedule ID.

        Returns:
            List of on-call entry objects with user and schedule info.
        """
        data = await self._api_request(
            "GET",
            "/oncalls",
            params={"schedule_ids[]": schedule_id},
        )
        oncalls = data.get("oncalls", [])
        logger.info("pagerduty.oncall_fetched", schedule_id=schedule_id, count=len(oncalls))
        return oncalls

    async def trigger_event(
        self,
        routing_key: str,
        summary: str,
        severity: str = "error",
        source: str = "shieldops",
        component: str = "",
        custom_details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Trigger an event via PagerDuty Events API v2.

        Args:
            routing_key: Events API v2 routing/integration key.
            summary: Event summary (max 1024 chars).
            severity: Event severity (critical, error, warning, info).
            source: Source of the event.
            component: Component responsible for the event.
            custom_details: Additional event details.

        Returns:
            Events API response with status, dedup_key, and message.
        """
        client = self._ensure_client()
        payload: dict[str, Any] = {
            "routing_key": routing_key or self._routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": summary[:1024],
                "severity": severity,
                "source": source,
            },
        }
        if component:
            payload["payload"]["component"] = component
        if custom_details:
            payload["payload"]["custom_details"] = custom_details
        resp = await client.post(
            _EVENTS_URL,
            headers={"Content-Type": "application/json"},
            json=payload,
        )
        resp.raise_for_status()
        result = resp.json()
        logger.info(
            "pagerduty.event_triggered",
            dedup_key=result.get("dedup_key", ""),
            severity=severity,
        )
        return result

    async def get_escalation_policies(
        self,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get PagerDuty escalation policies.

        Args:
            limit: Maximum number of policies to return.

        Returns:
            List of escalation policy objects.
        """
        data = await self._api_request(
            "GET",
            "/escalation_policies",
            params={"limit": limit},
        )
        policies = data.get("escalation_policies", [])
        logger.info("pagerduty.escalation_policies_fetched", count=len(policies))
        return policies

    async def close(self) -> None:
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
