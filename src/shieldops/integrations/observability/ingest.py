"""Unified Observability Ingestion Client.

Sends logs, metrics, and traces to observability backends.
Supports OpenObserve, Elasticsearch, and local file storage.
API compatible with OpenObserve's POST /api/{org}/{stream}/_json format.
"""

from __future__ import annotations

import base64
import json
import time
import uuid
from collections import defaultdict, deque
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


class SignalType(StrEnum):
    LOGS = "logs"
    METRICS = "metrics"
    TRACES = "traces"


class TelemetryRecord(BaseModel):
    """A single telemetry record (log, metric, or trace)."""

    signal_type: SignalType
    stream: str  # e.g., "agent_logs", "agent_metrics", "agent_traces"
    timestamp_us: int = Field(default_factory=lambda: int(time.time() * 1_000_000))
    data: dict[str, Any] = Field(default_factory=dict)
    _timestamp: int = 0  # microseconds, OpenObserve compat
    level: str = "info"
    service_name: str = ""
    agent_type: str = ""
    trace_id: str = ""
    span_id: str = ""


class IngestResult(BaseModel):
    """Result of a batch ingestion."""

    stream: str
    successful: int = 0
    failed: int = 0
    status_code: int = 200


class ObservabilityBackend(StrEnum):
    OPENOBSERVE = "openobserve"
    ELASTICSEARCH = "elasticsearch"
    LOCAL = "local"


class ObservabilityIngestClient:
    """Ingest telemetry data into observability backends.

    Compatible with OpenObserve's API:
    POST /api/{org}/{stream}/_json
    """

    def __init__(
        self,
        backend: ObservabilityBackend = ObservabilityBackend.LOCAL,
        base_url: str = "http://localhost:5080",
        organization: str = "shieldops",
        username: str = "",
        password: str = "",
        max_batch_size: int = 1000,
        max_buffer_size: int = 50_000,
    ):
        self.backend = backend
        self.base_url = base_url.rstrip("/")
        self.organization = organization
        self.username = username
        self.password = password
        self.max_batch_size = max_batch_size
        self.max_buffer_size = max_buffer_size

        # Local backend ring-buffer storage: stream -> deque of records
        self._local_store: dict[str, deque[dict[str, Any]]] = defaultdict(
            lambda: deque(maxlen=max_buffer_size)
        )

        # Auth header for OpenObserve / Elasticsearch
        self._auth_header = ""
        if username and password:
            token = base64.b64encode(f"{username}:{password}".encode()).decode()
            self._auth_header = f"Basic {token}"

        logger.info(
            "observability_ingest_client_init",
            backend=backend,
            base_url=base_url,
            organization=organization,
        )

    # ------------------------------------------------------------------
    # Core ingestion
    # ------------------------------------------------------------------

    async def ingest_logs(self, stream: str, records: list[dict[str, Any]]) -> IngestResult:
        """Ingest log records. Compatible with OpenObserve _json endpoint."""
        enriched = []
        for rec in records:
            enriched.append(self._enrich_record(rec, SignalType.LOGS))
        return await self._send(stream, SignalType.LOGS, enriched)

    async def ingest_metrics(self, stream: str, records: list[dict[str, Any]]) -> IngestResult:
        """Ingest metric records."""
        enriched = []
        for rec in records:
            enriched.append(self._enrich_record(rec, SignalType.METRICS))
        return await self._send(stream, SignalType.METRICS, enriched)

    async def ingest_traces(self, stream: str, spans: list[dict[str, Any]]) -> IngestResult:
        """Ingest trace spans."""
        enriched = []
        for span in spans:
            enriched.append(self._enrich_record(span, SignalType.TRACES))
        return await self._send(stream, SignalType.TRACES, enriched)

    async def ingest_agent_event(
        self,
        agent_type: str,
        event_type: str,
        data: dict[str, Any],
        trace_id: str = "",
        level: str = "info",
    ) -> IngestResult:
        """Convenience method to ingest a single agent event."""
        record = {
            "agent_type": agent_type,
            "event_type": event_type,
            "level": level,
            "trace_id": trace_id or uuid.uuid4().hex,
            "service_name": "shieldops",
            **data,
        }
        return await self.ingest_logs(f"agent_{agent_type}", [record])

    # ------------------------------------------------------------------
    # Querying
    # ------------------------------------------------------------------

    async def query_logs(
        self,
        stream: str,
        sql: str,
        start_time: int = 0,
        end_time: int = 0,
    ) -> list[dict[str, Any]]:
        """Query logs using SQL (OpenObserve-compatible)."""
        if self.backend == ObservabilityBackend.LOCAL:
            return self._local_query(stream, sql, start_time, end_time)
        elif self.backend == ObservabilityBackend.OPENOBSERVE:
            return await self._openobserve_query(stream, sql, start_time, end_time)
        elif self.backend == ObservabilityBackend.ELASTICSEARCH:
            return await self._elasticsearch_query(stream, sql, start_time, end_time)
        return []

    async def query_metrics(
        self,
        query: str,
        start_time: int = 0,
        end_time: int = 0,
    ) -> list[dict[str, Any]]:
        """Query metrics using PromQL or SQL."""
        if self.backend == ObservabilityBackend.LOCAL:
            return self._local_query_metrics(query, start_time, end_time)
        elif self.backend == ObservabilityBackend.OPENOBSERVE:
            return await self._openobserve_query_metrics(query, start_time, end_time)
        return []

    # ------------------------------------------------------------------
    # Internal: dispatch to backend
    # ------------------------------------------------------------------

    async def _send(
        self,
        stream: str,
        signal_type: SignalType,
        records: list[dict[str, Any]],
    ) -> IngestResult:
        """Route records to the configured backend."""
        if not records:
            return IngestResult(stream=stream, successful=0, failed=0)

        if self.backend == ObservabilityBackend.LOCAL:
            return self._local_ingest(stream, records)
        elif self.backend == ObservabilityBackend.OPENOBSERVE:
            return await self._openobserve_ingest(stream, signal_type, records)
        elif self.backend == ObservabilityBackend.ELASTICSEARCH:
            return await self._elasticsearch_ingest(stream, records)

        return IngestResult(stream=stream, successful=0, failed=len(records), status_code=500)

    # ------------------------------------------------------------------
    # Local backend
    # ------------------------------------------------------------------

    def _local_ingest(self, stream: str, records: list[dict[str, Any]]) -> IngestResult:
        """Store records in the in-memory ring buffer."""
        buf = self._local_store[stream]
        count = 0
        for rec in records:
            buf.append(rec)
            count += 1
        logger.debug("local_ingest", stream=stream, count=count)
        return IngestResult(stream=stream, successful=count, failed=0)

    def _local_query(
        self,
        stream: str,
        sql: str,
        start_time: int = 0,
        end_time: int = 0,
    ) -> list[dict[str, Any]]:
        """Simple local query with time range filtering.

        Supports basic WHERE-like filtering by parsing trivial SQL fragments.
        For production, use the real backend query engines.
        """
        if stream not in self._local_store:
            return []

        results: list[dict[str, Any]] = []
        for rec in self._local_store[stream]:
            ts = rec.get("_timestamp", 0)
            if start_time and ts < start_time:
                continue
            if end_time and ts > end_time:
                continue
            results.append(rec)

        # Extremely simple SQL WHERE clause extraction for local dev
        sql_lower = sql.lower()
        if "where" in sql_lower:
            where_clause = sql_lower.split("where", 1)[1].strip()
            # Support: field = 'value'
            if "=" in where_clause and "'" in where_clause:
                parts = where_clause.split("=", 1)
                field = parts[0].strip().strip('"').strip("'")
                value = parts[1].strip().strip("'").strip('"').rstrip(";").strip()
                results = [r for r in results if str(r.get(field, "")).lower() == value]

        # Support LIMIT
        if "limit" in sql_lower:
            try:
                limit_val = int(sql_lower.split("limit")[-1].strip().split()[0])
                results = results[:limit_val]
            except (ValueError, IndexError):
                pass

        return results

    def _local_query_metrics(
        self,
        query: str,
        start_time: int = 0,
        end_time: int = 0,
    ) -> list[dict[str, Any]]:
        """Query metrics from local store. Scans all metric streams."""
        results: list[dict[str, Any]] = []
        for stream_name, buf in self._local_store.items():
            for rec in buf:
                if rec.get("_signal_type") != SignalType.METRICS:
                    continue
                ts = rec.get("_timestamp", 0)
                if start_time and ts < start_time:
                    continue
                if end_time and ts > end_time:
                    continue
                # Simple name-based filtering
                metric_name = rec.get("metric_name", "")
                if query and query.lower() not in metric_name.lower():
                    continue
                results.append(rec)
        return results

    # ------------------------------------------------------------------
    # OpenObserve backend
    # ------------------------------------------------------------------

    async def _openobserve_ingest(
        self,
        stream: str,
        signal_type: SignalType,
        records: list[dict[str, Any]],
    ) -> IngestResult:
        """Send records to OpenObserve via POST /api/{org}/{stream}/_json."""
        url = f"{self.base_url}/api/{self.organization}/{stream}/_json"
        headers = {
            "Content-Type": "application/json",
        }
        if self._auth_header:
            headers["Authorization"] = self._auth_header

        # Send in batches
        total_ok = 0
        total_fail = 0
        for i in range(0, len(records), self.max_batch_size):
            batch = records[i : i + self.max_batch_size]
            try:
                import httpx

                async with httpx.AsyncClient(timeout=30.0) as client:
                    resp = await client.post(url, json=batch, headers=headers)
                    if resp.status_code in (200, 204):
                        total_ok += len(batch)
                    else:
                        logger.warning(
                            "openobserve_ingest_error",
                            stream=stream,
                            status=resp.status_code,
                            body=resp.text[:200],
                        )
                        total_fail += len(batch)
            except ImportError:
                logger.error("httpx_not_installed", msg="pip install httpx for remote backends")
                total_fail += len(batch)
            except Exception as exc:
                logger.error("openobserve_ingest_exception", stream=stream, error=str(exc))
                total_fail += len(batch)

        status = 200 if total_fail == 0 else (207 if total_ok > 0 else 500)
        return IngestResult(
            stream=stream, successful=total_ok, failed=total_fail, status_code=status
        )

    async def _openobserve_query(
        self,
        stream: str,
        sql: str,
        start_time: int,
        end_time: int,
    ) -> list[dict[str, Any]]:
        """Query OpenObserve via POST /api/{org}/_search."""
        url = f"{self.base_url}/api/{self.organization}/_search"
        headers = {"Content-Type": "application/json"}
        if self._auth_header:
            headers["Authorization"] = self._auth_header

        now_us = int(time.time() * 1_000_000)
        payload = {
            "query": {
                "sql": sql,
                "start_time": start_time or (now_us - 3_600_000_000),
                "end_time": end_time or now_us,
                "from": 0,
                "size": 1000,
            },
        }

        try:
            import httpx

            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(url, json=payload, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    return data.get("hits", [])
                logger.warning("openobserve_query_error", status=resp.status_code)
        except ImportError:
            logger.error("httpx_not_installed")
        except Exception as exc:
            logger.error("openobserve_query_exception", error=str(exc))
        return []

    async def _openobserve_query_metrics(
        self,
        query: str,
        start_time: int,
        end_time: int,
    ) -> list[dict[str, Any]]:
        """Query OpenObserve metrics via PromQL endpoint."""
        url = f"{self.base_url}/api/{self.organization}/prometheus/api/v1/query_range"
        headers = {}
        if self._auth_header:
            headers["Authorization"] = self._auth_header

        now = time.time()
        params = {
            "query": query,
            "start": start_time / 1_000_000 if start_time else now - 3600,
            "end": end_time / 1_000_000 if end_time else now,
            "step": "60s",
        }

        try:
            import httpx

            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(url, params=params, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    return data.get("data", {}).get("result", [])
        except ImportError:
            logger.error("httpx_not_installed")
        except Exception as exc:
            logger.error("openobserve_metrics_query_exception", error=str(exc))
        return []

    # ------------------------------------------------------------------
    # Elasticsearch backend
    # ------------------------------------------------------------------

    async def _elasticsearch_ingest(
        self, stream: str, records: list[dict[str, Any]]
    ) -> IngestResult:
        """Send records to Elasticsearch via _bulk API."""
        url = f"{self.base_url}/_bulk"
        headers = {"Content-Type": "application/x-ndjson"}
        if self._auth_header:
            headers["Authorization"] = self._auth_header

        total_ok = 0
        total_fail = 0

        for i in range(0, len(records), self.max_batch_size):
            batch = records[i : i + self.max_batch_size]
            ndjson_lines: list[str] = []
            for rec in batch:
                action = json.dumps({"index": {"_index": stream}})
                doc = json.dumps(rec)
                ndjson_lines.append(action)
                ndjson_lines.append(doc)
            body = "\n".join(ndjson_lines) + "\n"

            try:
                import httpx

                async with httpx.AsyncClient(timeout=30.0) as client:
                    resp = await client.post(url, content=body, headers=headers)
                    if resp.status_code in (200, 201):
                        resp_data = resp.json()
                        if resp_data.get("errors"):
                            items = resp_data.get("items", [])
                            ok = sum(
                                1
                                for item in items
                                if item.get("index", {}).get("status", 500) < 400
                            )
                            total_ok += ok
                            total_fail += len(batch) - ok
                        else:
                            total_ok += len(batch)
                    else:
                        logger.warning(
                            "elasticsearch_ingest_error",
                            stream=stream,
                            status=resp.status_code,
                        )
                        total_fail += len(batch)
            except ImportError:
                logger.error("httpx_not_installed")
                total_fail += len(batch)
            except Exception as exc:
                logger.error("elasticsearch_ingest_exception", error=str(exc))
                total_fail += len(batch)

        status = 200 if total_fail == 0 else (207 if total_ok > 0 else 500)
        return IngestResult(
            stream=stream, successful=total_ok, failed=total_fail, status_code=status
        )

    async def _elasticsearch_query(
        self,
        stream: str,
        sql: str,
        start_time: int,
        end_time: int,
    ) -> list[dict[str, Any]]:
        """Query Elasticsearch via _search API (uses SQL plugin or match_all)."""
        url = f"{self.base_url}/{stream}/_search"
        headers = {"Content-Type": "application/json"}
        if self._auth_header:
            headers["Authorization"] = self._auth_header

        # Simple time-range query
        body: dict[str, Any] = {
            "size": 1000,
            "query": {"match_all": {}},
            "sort": [{"_timestamp": {"order": "desc"}}],
        }
        if start_time or end_time:
            range_filter: dict[str, Any] = {}
            if start_time:
                range_filter["gte"] = start_time
            if end_time:
                range_filter["lte"] = end_time
            body["query"] = {"range": {"_timestamp": range_filter}}

        try:
            import httpx

            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(url, json=body, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    return [hit["_source"] for hit in data.get("hits", {}).get("hits", [])]
        except ImportError:
            logger.error("httpx_not_installed")
        except Exception as exc:
            logger.error("elasticsearch_query_exception", error=str(exc))
        return []

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _enrich_record(self, record: dict[str, Any], signal_type: SignalType) -> dict[str, Any]:
        """Add standard fields to a record."""
        enriched = {**record}
        if "_timestamp" not in enriched:
            enriched["_timestamp"] = int(time.time() * 1_000_000)
        enriched["_signal_type"] = signal_type.value
        enriched.setdefault("service_name", "shieldops")
        enriched.setdefault("_org", self.organization)
        return enriched

    def get_local_stream_names(self) -> list[str]:
        """Return all stream names in local store (for testing/debugging)."""
        return list(self._local_store.keys())

    def get_local_stream_count(self, stream: str) -> int:
        """Return record count for a local stream."""
        if stream in self._local_store:
            return len(self._local_store[stream])
        return 0

    def clear_local_store(self) -> None:
        """Clear all local storage."""
        self._local_store.clear()
