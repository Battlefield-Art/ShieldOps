"""Splunk ITSI connector for search, HEC ingestion, notable events, and KPI management."""

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


class SplunkConnector(InfraConnector):
    """Connector for Splunk Enterprise / ITSI / Enterprise Security.

    Provides access to SPL search, HTTP Event Collector (HEC) ingestion,
    Enterprise Security notable events, correlation searches, and ITSI
    service/KPI management.
    """

    provider = "splunk"

    def __init__(
        self,
        base_url: str,
        token: str,
        hec_url: str = "",
        hec_token: str = "",
        verify_ssl: bool = True,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._hec_url = hec_url.rstrip("/") if hec_url else ""
        self._hec_token = hec_token
        self._verify_ssl = verify_ssl
        self._http_client: Any = None
        self._hec_client: Any = None
        self._snapshots: dict[str, dict[str, Any]] = {}

    def _ensure_http_client(self) -> Any:
        """Lazily initialize httpx async client for Splunk REST API."""
        if self._http_client is None:
            import httpx

            self._http_client = httpx.AsyncClient(
                base_url=self._base_url,
                timeout=60.0,
                verify=self._verify_ssl,
            )
        return self._http_client

    def _ensure_hec_client(self) -> Any:
        """Lazily initialize httpx async client for HEC endpoint."""
        if self._hec_client is None:
            import httpx

            hec_base = self._hec_url or self._base_url
            self._hec_client = httpx.AsyncClient(
                base_url=hec_base,
                timeout=30.0,
                verify=self._verify_ssl,
            )
        return self._hec_client

    def _auth_headers(self) -> dict[str, str]:
        """Return authorization headers for Splunk REST API."""
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }

    async def _api_request(
        self,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Make an authenticated API request to Splunk REST API."""
        client = self._ensure_http_client()
        headers = kwargs.pop("headers", {})
        headers.update(self._auth_headers())
        params = kwargs.pop("params", {})
        params.setdefault("output_mode", "json")
        resp = await client.request(method, path, headers=headers, params=params, **kwargs)
        resp.raise_for_status()
        return resp.json()

    # -- InfraConnector interface ------------------------------------------

    async def get_health(self, resource_id: str) -> HealthStatus:
        """Get Splunk search head health via splunkd health endpoint."""
        try:
            data = await self._api_request(
                "GET",
                "/services/server/health/splunkd",
            )
            entries = data.get("entry", [])
            health_status = "unknown"
            healthy = False
            if entries:
                content = entries[0].get("content", {})
                health_status = content.get("health", "unknown")
                healthy = health_status.lower() in ("green", "yellow")
            return HealthStatus(
                resource_id=resource_id,
                healthy=healthy,
                status=health_status,
                message=f"Splunk search head health: {health_status}",
                last_checked=datetime.now(UTC),
            )
        except Exception as e:
            logger.error("splunk.health_check_failed", resource_id=resource_id, error=str(e))
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
        """List Splunk resources (search_jobs or saved_searches)."""
        resources: list[Resource] = []
        try:
            if resource_type in ("search_job", "search_jobs"):
                data = await self._api_request("GET", "/services/search/jobs")
                for entry in data.get("entry", []):
                    resources.append(
                        Resource(
                            id=entry.get("name", ""),
                            name=entry.get("name", "unknown"),
                            resource_type="search_job",
                            environment=environment,
                            provider=self.provider,
                            metadata={
                                "dispatch_state": entry.get("content", {}).get("dispatchState", ""),
                                "event_count": entry.get("content", {}).get("eventCount", 0),
                            },
                        )
                    )
            elif resource_type in ("saved_search", "saved_searches"):
                data = await self._api_request("GET", "/servicesNS/-/-/saved/searches")
                for entry in data.get("entry", []):
                    content = entry.get("content", {})
                    resources.append(
                        Resource(
                            id=entry.get("name", ""),
                            name=entry.get("name", "unknown"),
                            resource_type="saved_search",
                            environment=environment,
                            provider=self.provider,
                            labels={
                                "is_scheduled": str(content.get("is_scheduled", False)),
                                "disabled": str(content.get("disabled", False)),
                            },
                            metadata={
                                "search": content.get("search", ""),
                                "cron_schedule": content.get("cron_schedule", ""),
                            },
                        )
                    )
        except Exception as e:
            logger.error(
                "splunk.list_resources_failed",
                resource_type=resource_type,
                error=str(e),
            )
        return resources

    async def get_events(self, resource_id: str, time_range: TimeRange) -> list[dict[str, Any]]:
        """Get events via SPL search export within a time range."""
        try:
            spl = f'search index=* host="{resource_id}"'
            results = await self.search_spl(
                query=spl,
                earliest=time_range.start.isoformat(),
                latest=time_range.end.isoformat(),
            )
            return results
        except Exception as e:
            logger.error(
                "splunk.get_events_failed",
                resource_id=resource_id,
                error=str(e),
            )
            return []

    async def execute_action(self, action: RemediationAction) -> ActionResult:
        """Execute a Splunk action (ad-hoc search or trigger saved search)."""
        started = datetime.now(UTC)
        try:
            if action.action_type == "run_search":
                spl = action.parameters.get("query", "")
                results = await self.search_spl(
                    query=spl,
                    earliest=action.parameters.get("earliest", "-1h"),
                    latest=action.parameters.get("latest", "now"),
                )
                return ActionResult(
                    action_id=action.id,
                    status=ExecutionStatus.SUCCESS,
                    message=f"Search completed with {len(results)} results",
                    started_at=started,
                    completed_at=datetime.now(UTC),
                )
            elif action.action_type == "trigger_saved_search":
                name = action.parameters.get("name", "")
                await self._api_request(
                    "POST",
                    f"/servicesNS/-/-/saved/searches/{name}/dispatch",
                )
                return ActionResult(
                    action_id=action.id,
                    status=ExecutionStatus.SUCCESS,
                    message=f"Saved search '{name}' dispatched",
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
            logger.error("splunk.execute_action_failed", action_id=action.id, error=str(e))
            return ActionResult(
                action_id=action.id,
                status=ExecutionStatus.FAILED,
                message=str(e),
                started_at=started,
                completed_at=datetime.now(UTC),
                error=str(e),
            )

    async def create_snapshot(self, resource_id: str) -> Snapshot:
        """Capture current saved searches and alert configurations."""
        saved_searches_data = await self._api_request(
            "GET",
            "/servicesNS/-/-/saved/searches",
        )
        saved_searches = [
            {
                "name": entry.get("name"),
                "content": entry.get("content", {}),
            }
            for entry in saved_searches_data.get("entry", [])
        ]

        snapshot_id = str(uuid4())
        state = {
            "saved_searches": saved_searches,
            "captured_at": datetime.now(UTC).isoformat(),
        }
        snapshot = Snapshot(
            id=snapshot_id,
            resource_id=resource_id,
            snapshot_type="splunk_config",
            state=state,
            created_at=datetime.now(UTC),
        )
        self._snapshots[snapshot_id] = state
        logger.info("splunk.snapshot_created", snapshot_id=snapshot_id)
        return snapshot

    async def rollback(self, snapshot_id: str) -> ActionResult:
        """Restore saved searches from a snapshot."""
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
            for ss in state.get("saved_searches", []):
                name = ss.get("name", "")
                content = ss.get("content", {})
                await self._api_request(
                    "POST",
                    f"/servicesNS/-/-/saved/searches/{name}",
                    data=content,
                )
            logger.info("splunk.rollback_completed", snapshot_id=snapshot_id)
            return ActionResult(
                action_id=snapshot_id,
                status=ExecutionStatus.SUCCESS,
                message="Saved searches restored from snapshot",
                started_at=started,
                completed_at=datetime.now(UTC),
                snapshot_id=snapshot_id,
            )
        except Exception as e:
            logger.error("splunk.rollback_failed", snapshot_id=snapshot_id, error=str(e))
            return ActionResult(
                action_id=snapshot_id,
                status=ExecutionStatus.FAILED,
                message=str(e),
                started_at=started,
                completed_at=datetime.now(UTC),
                error=str(e),
            )

    async def validate_health(self, resource_id: str, timeout_seconds: int = 300) -> bool:
        """Verify Splunk search head is responsive with polling."""
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            health = await self.get_health(resource_id)
            if health.healthy:
                logger.info("splunk.health_validated", resource_id=resource_id)
                return True
            await asyncio.sleep(5)
        logger.warning(
            "splunk.health_validation_timeout",
            resource_id=resource_id,
            timeout=timeout_seconds,
        )
        return False

    # -- Splunk-specific methods -------------------------------------------

    async def search_spl(
        self,
        query: str,
        earliest: str = "-1h",
        latest: str = "now",
    ) -> list[dict[str, Any]]:
        """Run an SPL query and return results.

        Creates a search job, polls until completion, and fetches results.

        Args:
            query: SPL query string (e.g., 'search index=main error').
            earliest: Earliest time bound (e.g., '-1h', '2024-01-01T00:00:00').
            latest: Latest time bound (e.g., 'now', '2024-01-02T00:00:00').

        Returns:
            List of result dictionaries.
        """
        client = self._ensure_http_client()
        headers = self._auth_headers()
        headers["Content-Type"] = "application/x-www-form-urlencoded"

        # Create search job
        resp = await client.post(
            "/services/search/jobs",
            headers=headers,
            data={
                "search": query if query.startswith("|") else f"search {query}",
                "earliest_time": earliest,
                "latest_time": latest,
                "output_mode": "json",
            },
        )
        resp.raise_for_status()
        job_data = resp.json()
        sid = job_data.get("sid", "")

        # Poll for job completion
        for _ in range(120):
            status_resp = await self._api_request(
                "GET",
                f"/services/search/jobs/{sid}",
            )
            entries = status_resp.get("entry", [])
            if entries:
                dispatch_state = entries[0].get("content", {}).get("dispatchState", "")
                if dispatch_state in ("DONE", "FAILED"):
                    break
            await asyncio.sleep(1)

        # Fetch results
        results_data = await self._api_request(
            "GET",
            f"/services/search/v2/jobs/{sid}/results",
            params={"output_mode": "json", "count": 10000},
        )
        logger.info("splunk.search_completed", sid=sid, query=query[:80])
        return results_data.get("results", [])

    async def ingest_hec(
        self,
        events: list[dict[str, Any]],
        index: str = "main",
        sourcetype: str = "shieldops",
    ) -> dict[str, Any]:
        """Ingest events via HTTP Event Collector (HEC).

        Args:
            events: List of event dictionaries to ingest.
            index: Target Splunk index.
            sourcetype: Sourcetype for ingested events.

        Returns:
            HEC response with text and code fields.
        """
        hec_client = self._ensure_hec_client()
        hec_token = self._hec_token or self._token

        payload = ""
        for event in events:
            entry = {
                "event": event,
                "index": index,
                "sourcetype": sourcetype,
            }
            import json

            payload += json.dumps(entry) + "\n"

        resp = await hec_client.post(
            "/services/collector/event",
            headers={
                "Authorization": f"Splunk {hec_token}",
                "Content-Type": "application/json",
            },
            content=payload,
        )
        resp.raise_for_status()
        result = resp.json()
        logger.info(
            "splunk.hec_ingested",
            event_count=len(events),
            index=index,
            code=result.get("code"),
        )
        return result

    async def get_notable_events(
        self,
        severity: str = "",
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get Enterprise Security notable events.

        Args:
            severity: Filter by severity (critical, high, medium, low, informational).
            limit: Maximum number of notable events to return.

        Returns:
            List of notable event dictionaries.
        """
        spl = "| `notable`"
        if severity:
            spl += f' | search severity="{severity}"'
        spl += f" | head {limit}"
        results = await self.search_spl(query=spl, earliest="-24h", latest="now")
        logger.info("splunk.notable_events_fetched", count=len(results), severity=severity)
        return results

    async def create_correlation_search(
        self,
        name: str,
        spl: str,
        severity: str = "high",
        description: str = "",
    ) -> dict[str, Any]:
        """Create a new Enterprise Security correlation search.

        Args:
            name: Name of the correlation search.
            spl: SPL query for the correlation search.
            severity: Default severity (critical, high, medium, low, informational).
            description: Description of the correlation search.

        Returns:
            API response for the created correlation search.
        """
        client = self._ensure_http_client()
        headers = self._auth_headers()
        headers["Content-Type"] = "application/x-www-form-urlencoded"

        resp = await client.post(
            "/servicesNS/-/SplunkEnterpriseSecuritySuite/saved/searches",
            headers=headers,
            data={
                "name": name,
                "search": spl,
                "description": description,
                "action.correlationsearch.enabled": "1",
                "action.notable": "1",
                "action.notable.param.severity": severity,
                "is_scheduled": "1",
                "cron_schedule": "*/5 * * * *",
                "dispatch.earliest_time": "-5m",
                "dispatch.latest_time": "now",
                "output_mode": "json",
            },
        )
        resp.raise_for_status()
        result = resp.json()
        logger.info("splunk.correlation_search_created", name=name, severity=severity)
        return result

    async def get_itsi_services(self) -> list[dict[str, Any]]:
        """Get ITSI service health overview.

        Returns:
            List of ITSI service objects with health scores and KPIs.
        """
        data = await self._api_request(
            "GET",
            "/servicesNS/nobody/SA-ITOA/itoa_interface/service",
        )
        services = data if isinstance(data, list) else data.get("entry", [])
        logger.info("splunk.itsi_services_fetched", count=len(services))
        return services

    async def update_itsi_kpi(
        self,
        service_id: str,
        kpi_id: str,
        value: float,
    ) -> dict[str, Any]:
        """Update an ITSI KPI threshold value.

        Args:
            service_id: ITSI service identifier.
            kpi_id: KPI identifier within the service.
            value: New threshold value.

        Returns:
            API response confirming the update.
        """
        data = await self._api_request(
            "PUT",
            f"/servicesNS/nobody/SA-ITOA/itoa_interface/service/{service_id}",
            json={
                "kpis": [
                    {
                        "_key": kpi_id,
                        "adaptive_thresholds_is_enabled": False,
                        "aggregate_statop": "avg",
                        "threshold_value": value,
                    }
                ]
            },
        )
        logger.info(
            "splunk.itsi_kpi_updated",
            service_id=service_id,
            kpi_id=kpi_id,
            value=value,
        )
        return data

    async def close(self) -> None:
        """Close HTTP clients."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None
        if self._hec_client:
            await self._hec_client.aclose()
            self._hec_client = None
