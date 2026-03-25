"""Elastic SIEM connector for search, bulk ingestion, detection rules, and cases."""

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


class ElasticConnector(InfraConnector):
    """Connector for Elasticsearch and Elastic Security (SIEM).

    Provides access to Elasticsearch DSL and EQL queries, bulk document
    ingestion, Elastic Security SIEM alerts and detection rules,
    Elastic Cases, and Kibana response actions.
    """

    provider = "elastic"

    def __init__(
        self,
        url: str,
        api_key: str = "",
        username: str = "",
        password: str = "",
        cloud_id: str = "",
        verify_ssl: bool = True,
    ) -> None:
        self._url = url.rstrip("/")
        self._api_key = api_key
        self._username = username
        self._password = password
        self._cloud_id = cloud_id
        self._verify_ssl = verify_ssl
        self._http_client: Any = None
        self._snapshots: dict[str, dict[str, Any]] = {}

    def _ensure_http_client(self) -> Any:
        """Lazily initialize httpx async client."""
        if self._http_client is None:
            import httpx

            auth = None
            if self._username and self._password:
                auth = httpx.BasicAuth(self._username, self._password)

            self._http_client = httpx.AsyncClient(
                base_url=self._url,
                timeout=60.0,
                verify=self._verify_ssl,
                auth=auth,
            )
        return self._http_client

    def _auth_headers(self) -> dict[str, str]:
        """Return authorization headers for Elasticsearch API."""
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"ApiKey {self._api_key}"
        return headers

    async def _api_request(
        self,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Make an authenticated API request to Elasticsearch / Kibana."""
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
        """Get Elasticsearch cluster health."""
        try:
            data = await self._api_request("GET", "/_cluster/health")
            status = data.get("status", "unknown")
            healthy = status in ("green", "yellow")
            return HealthStatus(
                resource_id=resource_id,
                healthy=healthy,
                status=status,
                message=f"Cluster '{data.get('cluster_name', '')}': {status}",
                last_checked=datetime.now(UTC),
                metrics={
                    "active_shards": float(data.get("active_shards", 0)),
                    "relocating_shards": float(data.get("relocating_shards", 0)),
                    "unassigned_shards": float(data.get("unassigned_shards", 0)),
                    "number_of_nodes": float(data.get("number_of_nodes", 0)),
                },
            )
        except Exception as e:
            logger.error("elastic.health_check_failed", resource_id=resource_id, error=str(e))
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
        """List Elastic resources (indices or SIEM detection rules)."""
        resources: list[Resource] = []
        try:
            if resource_type in ("index", "indices"):
                data = await self._api_request(
                    "GET",
                    "/_cat/indices",
                    params={"format": "json", "h": "index,health,status,docs.count,store.size"},
                )
                indices = data if isinstance(data, list) else []
                for idx in indices:
                    resources.append(
                        Resource(
                            id=idx.get("index", ""),
                            name=idx.get("index", "unknown"),
                            resource_type="index",
                            environment=environment,
                            provider=self.provider,
                            labels={
                                "health": idx.get("health", ""),
                                "status": idx.get("status", ""),
                            },
                            metadata={
                                "docs_count": idx.get("docs.count", "0"),
                                "store_size": idx.get("store.size", "0"),
                            },
                        )
                    )
            elif resource_type in ("detection_rule", "siem_rule", "siem_rules"):
                data = await self._api_request(
                    "GET",
                    "/api/detection_engine/rules/_find",
                    params={"per_page": 100, "page": 1},
                    headers={"kbn-xsrf": "true"},
                )
                for rule in data.get("data", []):
                    resources.append(
                        Resource(
                            id=rule.get("id", ""),
                            name=rule.get("name", "unknown"),
                            resource_type="detection_rule",
                            environment=environment,
                            provider=self.provider,
                            labels={
                                "severity": rule.get("severity", ""),
                                "enabled": str(rule.get("enabled", False)),
                            },
                            metadata={
                                "rule_id": rule.get("rule_id", ""),
                                "type": rule.get("type", ""),
                                "index": str(rule.get("index", [])),
                            },
                        )
                    )
        except Exception as e:
            logger.error(
                "elastic.list_resources_failed",
                resource_type=resource_type,
                error=str(e),
            )
        return resources

    async def get_events(self, resource_id: str, time_range: TimeRange) -> list[dict[str, Any]]:
        """Get events from an index within a time range."""
        try:
            query = {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": time_range.start.isoformat(),
                                    "lte": time_range.end.isoformat(),
                                }
                            }
                        }
                    ],
                    "filter": [
                        {"term": {"host.name": resource_id}},
                    ],
                }
            }
            results = await self.search(index="*", query=query, size=200)
            return results
        except Exception as e:
            logger.error(
                "elastic.get_events_failed",
                resource_id=resource_id,
                error=str(e),
            )
            return []

    async def execute_action(self, action: RemediationAction) -> ActionResult:
        """Execute an Elastic response action via Kibana Actions API."""
        started = datetime.now(UTC)
        try:
            if action.action_type == "execute_connector":
                connector_id = action.parameters.get("connector_id", "")
                body = action.parameters.get("body", {})
                result = await self._api_request(
                    "POST",
                    f"/api/actions/connector/{connector_id}/_execute",
                    json={"params": body},
                    headers={"kbn-xsrf": "true"},
                )
                status_val = result.get("status", "")
                success = status_val == "ok"
                return ActionResult(
                    action_id=action.id,
                    status=ExecutionStatus.SUCCESS if success else ExecutionStatus.FAILED,
                    message=f"Connector {connector_id} executed: {status_val}",
                    started_at=started,
                    completed_at=datetime.now(UTC),
                )
            elif action.action_type == "isolate_host":
                result = await self._api_request(
                    "POST",
                    "/api/endpoint/action/isolate",
                    json={
                        "endpoint_ids": [action.target_resource],
                        "comment": action.parameters.get("comment", "ShieldOps isolation"),
                    },
                    headers={"kbn-xsrf": "true"},
                )
                return ActionResult(
                    action_id=action.id,
                    status=ExecutionStatus.SUCCESS,
                    message=f"Host {action.target_resource} isolated",
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
            logger.error("elastic.execute_action_failed", action_id=action.id, error=str(e))
            return ActionResult(
                action_id=action.id,
                status=ExecutionStatus.FAILED,
                message=str(e),
                started_at=started,
                completed_at=datetime.now(UTC),
                error=str(e),
            )

    async def create_snapshot(self, resource_id: str) -> Snapshot:
        """Capture current SIEM detection rules for rollback."""
        rules_data = await self._api_request(
            "GET",
            "/api/detection_engine/rules/_find",
            params={"per_page": 1000, "page": 1},
            headers={"kbn-xsrf": "true"},
        )
        rules = rules_data.get("data", [])

        snapshot_id = str(uuid4())
        state = {
            "detection_rules": rules,
            "captured_at": datetime.now(UTC).isoformat(),
        }
        snapshot = Snapshot(
            id=snapshot_id,
            resource_id=resource_id,
            snapshot_type="elastic_siem_config",
            state=state,
            created_at=datetime.now(UTC),
        )
        self._snapshots[snapshot_id] = state
        logger.info("elastic.snapshot_created", snapshot_id=snapshot_id, rule_count=len(rules))
        return snapshot

    async def rollback(self, snapshot_id: str) -> ActionResult:
        """Restore SIEM detection rules from a snapshot."""
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
            for rule in state.get("detection_rules", []):
                rule_id = rule.get("id", "")
                # Remove read-only fields before update
                update_body = {
                    k: v
                    for k, v in rule.items()
                    if k
                    not in (
                        "id",
                        "rule_id",
                        "created_at",
                        "created_by",
                        "updated_at",
                        "updated_by",
                        "immutable",
                        "revision",
                    )
                }
                await self._api_request(
                    "PUT",
                    "/api/detection_engine/rules",
                    json={"id": rule_id, **update_body},
                    headers={"kbn-xsrf": "true"},
                )
            logger.info("elastic.rollback_completed", snapshot_id=snapshot_id)
            return ActionResult(
                action_id=snapshot_id,
                status=ExecutionStatus.SUCCESS,
                message="Detection rules restored from snapshot",
                started_at=started,
                completed_at=datetime.now(UTC),
                snapshot_id=snapshot_id,
            )
        except Exception as e:
            logger.error("elastic.rollback_failed", snapshot_id=snapshot_id, error=str(e))
            return ActionResult(
                action_id=snapshot_id,
                status=ExecutionStatus.FAILED,
                message=str(e),
                started_at=started,
                completed_at=datetime.now(UTC),
                error=str(e),
            )

    async def validate_health(self, resource_id: str, timeout_seconds: int = 300) -> bool:
        """Verify Elasticsearch cluster health with polling."""
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            health = await self.get_health(resource_id)
            if health.healthy:
                logger.info("elastic.health_validated", resource_id=resource_id)
                return True
            await asyncio.sleep(5)
        logger.warning(
            "elastic.health_validation_timeout",
            resource_id=resource_id,
            timeout=timeout_seconds,
        )
        return False

    # -- Elastic-specific methods ------------------------------------------

    async def search(
        self,
        index: str,
        query: dict[str, Any],
        size: int = 100,
    ) -> list[dict[str, Any]]:
        """Execute an Elasticsearch DSL query.

        Args:
            index: Target index or index pattern (e.g., 'logs-*').
            query: Elasticsearch query DSL dictionary.
            size: Maximum number of hits to return.

        Returns:
            List of hit source documents.
        """
        data = await self._api_request(
            "POST",
            f"/{index}/_search",
            json={"query": query, "size": size},
        )
        hits = data.get("hits", {}).get("hits", [])
        results = [hit.get("_source", {}) for hit in hits]
        logger.info("elastic.search_completed", index=index, hit_count=len(results))
        return results

    async def ingest(
        self,
        index: str,
        documents: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Bulk index documents into Elasticsearch.

        Args:
            index: Target index name.
            documents: List of documents to index.

        Returns:
            Bulk API response with items and error summary.
        """
        import json

        bulk_body = ""
        for doc in documents:
            bulk_body += json.dumps({"index": {"_index": index}}) + "\n"
            bulk_body += json.dumps(doc) + "\n"

        client = self._ensure_http_client()
        headers = self._auth_headers()
        headers["Content-Type"] = "application/x-ndjson"

        resp = await client.post(
            "/_bulk",
            headers=headers,
            content=bulk_body,
        )
        resp.raise_for_status()
        result = resp.json()
        errors = result.get("errors", False)
        logger.info(
            "elastic.bulk_ingested",
            index=index,
            doc_count=len(documents),
            errors=errors,
        )
        return result

    async def get_siem_alerts(
        self,
        severity: str = "",
        status: str = "open",
        size: int = 100,
    ) -> list[dict[str, Any]]:
        """Get Elastic Security SIEM alerts.

        Args:
            severity: Filter by severity (critical, high, medium, low).
            status: Alert status filter (open, acknowledged, closed).
            size: Maximum number of alerts to return.

        Returns:
            List of SIEM alert documents.
        """
        must_clauses: list[dict[str, Any]] = []
        if status:
            must_clauses.append({"term": {"signal.status": status}})
        if severity:
            must_clauses.append({"term": {"signal.rule.severity": severity}})

        query: dict[str, Any] = (
            {"bool": {"must": must_clauses}} if must_clauses else {"match_all": {}}
        )

        data = await self._api_request(
            "POST",
            "/.siem-signals-*/_search",
            json={"query": query, "size": size, "sort": [{"@timestamp": "desc"}]},
        )
        hits = data.get("hits", {}).get("hits", [])
        alerts = [hit.get("_source", {}) for hit in hits]
        logger.info("elastic.siem_alerts_fetched", count=len(alerts), severity=severity)
        return alerts

    async def create_detection_rule(
        self,
        name: str,
        query: str,
        severity: str = "high",
        index_patterns: list[str] | None = None,
        description: str = "",
        risk_score: int = 73,
    ) -> dict[str, Any]:
        """Create an Elastic Security SIEM detection rule.

        Args:
            name: Rule name.
            query: KQL or Lucene query string for the rule.
            severity: Rule severity (critical, high, medium, low).
            index_patterns: Index patterns to search (default: ['logs-*']).
            description: Rule description.
            risk_score: Risk score (0-100) for alerts generated by this rule.

        Returns:
            Created rule object from the API.
        """
        if index_patterns is None:
            index_patterns = ["logs-*"]

        rule_body = {
            "name": name,
            "description": description or f"ShieldOps detection rule: {name}",
            "type": "query",
            "query": query,
            "language": "kuery",
            "index": index_patterns,
            "severity": severity,
            "risk_score": risk_score,
            "enabled": True,
            "interval": "5m",
            "from": "now-6m",
            "to": "now",
            "tags": ["shieldops", "auto-generated"],
        }

        result = await self._api_request(
            "POST",
            "/api/detection_engine/rules",
            json=rule_body,
            headers={"kbn-xsrf": "true"},
        )
        logger.info(
            "elastic.detection_rule_created",
            name=name,
            severity=severity,
            rule_id=result.get("id"),
        )
        return result

    async def get_cases(
        self,
        status: str = "open",
        size: int = 50,
    ) -> list[dict[str, Any]]:
        """Get Elastic Cases.

        Args:
            status: Case status filter (open, in-progress, closed).
            size: Maximum number of cases to return.

        Returns:
            List of case objects.
        """
        params: dict[str, Any] = {
            "perPage": size,
            "page": 1,
            "sortField": "createdAt",
            "sortOrder": "desc",
        }
        if status:
            params["status"] = status

        data = await self._api_request(
            "GET",
            "/api/cases/_find",
            params=params,
            headers={"kbn-xsrf": "true"},
        )
        cases = data.get("cases", [])
        logger.info("elastic.cases_fetched", count=len(cases), status=status)
        return cases

    async def run_eql_query(
        self,
        query: str,
        index: str = "logs-*",
        size: int = 100,
    ) -> list[dict[str, Any]]:
        """Run an Event Query Language (EQL) search.

        Args:
            query: EQL query string (e.g., 'process where process.name == "cmd.exe"').
            index: Target index or index pattern.
            size: Maximum number of events to return.

        Returns:
            List of matching event documents.
        """
        data = await self._api_request(
            "POST",
            f"/{index}/_eql/search",
            json={
                "query": query,
                "size": size,
            },
        )
        hits = data.get("hits", {})
        events = hits.get("events", [])
        sequences = hits.get("sequences", [])

        results: list[dict[str, Any]] = []
        for event in events:
            results.append(event.get("_source", {}))
        for seq in sequences:
            for event in seq.get("events", []):
                results.append(event.get("_source", {}))

        logger.info("elastic.eql_query_completed", index=index, hit_count=len(results))
        return results

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None
