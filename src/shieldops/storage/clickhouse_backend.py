"""ClickHouse event store backend — multi-tenant columnar storage for SaaS deployments.

Supports both single-node deployments (DuckDB-equivalent drop-in) and the production
3-node HA cluster defined in ``infrastructure/terraform/aws/production/clickhouse.tf``.
In cluster mode, a list of hosts is accepted and connections are round-robin across
them with automatic failover on connection errors.
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import json
import threading
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog

from shieldops.storage.interface import PaginatedResult, StorageStats

logger = structlog.get_logger()

try:
    import clickhouse_connect  # type: ignore[import-untyped]
except ImportError:
    clickhouse_connect = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# DDL statements
# ---------------------------------------------------------------------------

_EVENTS_DDL = """\
CREATE TABLE IF NOT EXISTS events (
    event_id String,
    org_id String,
    timestamp DateTime64(3),
    event_type LowCardinality(String),
    severity LowCardinality(String),
    source_provider LowCardinality(String),
    source_type LowCardinality(String),
    raw_event String,
    normalized String,
    enrichments String,

    INDEX idx_event_type event_type TYPE set(100) GRANULARITY 4,
    INDEX idx_severity severity TYPE set(10) GRANULARITY 4
) ENGINE = MergeTree()
PARTITION BY (org_id, toYYYYMM(timestamp))
ORDER BY (org_id, event_type, timestamp)
"""

_EVENTS_PER_HOUR_MV = """\
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_events_per_hour
ENGINE = SummingMergeTree()
ORDER BY (org_id, event_type, hour)
AS SELECT
    org_id,
    event_type,
    toStartOfHour(timestamp) AS hour,
    count() AS cnt
FROM events
GROUP BY org_id, event_type, hour
"""

_TOP_SOURCE_IPS_MV = """\
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_top_source_ips
ENGINE = SummingMergeTree()
ORDER BY (org_id, source_provider, day)
AS SELECT
    org_id,
    source_provider,
    toDate(timestamp) AS day,
    count() AS cnt
FROM events
GROUP BY org_id, source_provider, day
"""

_ALERT_VOLUME_TREND_MV = """\
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_alert_volume_trend
ENGINE = SummingMergeTree()
ORDER BY (org_id, severity, day)
AS SELECT
    org_id,
    severity,
    toDate(timestamp) AS day,
    count() AS cnt
FROM events
GROUP BY org_id, severity, day
"""

_MITRE_FREQUENCY_MV = """\
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_mitre_frequency
ENGINE = SummingMergeTree()
ORDER BY (org_id, event_type, week)
AS SELECT
    org_id,
    event_type,
    toMonday(timestamp) AS week,
    count() AS cnt
FROM events
GROUP BY org_id, event_type, week
"""

_MATERIALIZED_VIEWS = [
    _EVENTS_PER_HOUR_MV,
    _TOP_SOURCE_IPS_MV,
    _ALERT_VOLUME_TREND_MV,
    _MITRE_FREQUENCY_MV,
]

_BATCH_SIZE = 50_000

# Retention tier presets (days).
RETENTION_TIERS: dict[str, int] = {
    "starter": 30,
    "professional": 90,
    "enterprise": 365,
}


def _ttl_alter_sql(table: str, ttl_days: int) -> str:
    """Return ALTER TABLE statement to set TTL retention on the events table."""
    return f"ALTER TABLE {table} MODIFY TTL toDateTime(timestamp) + INTERVAL {ttl_days} DAY DELETE"


class ClickHouseEventStore:
    """ClickHouse-backed event store with multi-tenant isolation.

    Uses ``clickhouse-connect`` for native protocol communication.
    Async interface wraps synchronous client calls with ``asyncio.to_thread``.
    """

    def __init__(
        self,
        host: str | list[str] = "localhost",
        port: int = 8123,
        database: str = "shieldops",
        user: str = "default",
        password: str = "",
        ttl_days: int | None = None,
        *,
        secure: bool = False,
        cluster_name: str | None = None,
        max_failover_attempts: int = 3,
        skip_schema_init: bool = False,
    ) -> None:
        if clickhouse_connect is None:
            raise RuntimeError(
                "clickhouse-connect is not installed. Install with: pip install clickhouse-connect"
            )
        # Normalize hosts to a list (cluster-ready). A single string still works.
        if isinstance(host, str):
            self._hosts: list[str] = [host]
        else:
            self._hosts = list(host) or ["localhost"]
        self._host = self._hosts[0]  # back-compat attribute
        self._port = port
        self._database = database
        self._user = user
        self._password = password
        self._secure = secure
        self._ttl_days = ttl_days
        self._cluster_name = cluster_name
        self._max_failover_attempts = max(1, max_failover_attempts)
        self._local = threading.local()
        self._lock = threading.Lock()
        self._host_cycle = itertools.cycle(self._hosts)

        # Ensure schema exists. Skipped when talking to a cluster that is
        # bootstrapped out-of-band via init.sql (ON CLUSTER DDL).
        if not skip_schema_init:
            client = self._get_client()
            client.command(f"CREATE DATABASE IF NOT EXISTS {database}")  # noqa: S608
            client.command(_EVENTS_DDL)
            for mv_ddl in _MATERIALIZED_VIEWS:
                client.command(mv_ddl)
            if ttl_days is not None:
                client.command(_ttl_alter_sql("events", ttl_days))

        logger.info(
            "clickhouse_event_store_initialized",
            hosts=self._hosts,
            port=port,
            database=database,
            ttl_days=ttl_days,
            cluster_name=cluster_name,
        )

    # ------------------------------------------------------------------
    # Connection management (thread-local)
    # ------------------------------------------------------------------

    def _get_client(self) -> Any:
        """Return a thread-local ClickHouse client with round-robin failover.

        On first use per thread, iterate candidate hosts and connect to the
        first that accepts our connection. A cached client is pinned until
        :meth:`_invalidate_client` is called (typically after a query error).
        """
        client: Any = getattr(self._local, "client", None)
        if client is not None:
            return client

        last_error: Exception | None = None
        # Try up to len(hosts) * max_failover_attempts candidates.
        total_attempts = len(self._hosts) * self._max_failover_attempts
        for _ in range(total_attempts):
            candidate = next(self._host_cycle)
            try:
                client = clickhouse_connect.get_client(
                    host=candidate,
                    port=self._port,
                    database=self._database,
                    username=self._user,
                    password=self._password,
                    secure=self._secure,
                )
                self._local.client = client
                self._local.host = candidate
                logger.debug("clickhouse_client_connected", host=candidate)
                return client
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                logger.warning(
                    "clickhouse_client_connect_failed",
                    host=candidate,
                    error=str(exc),
                )
                continue

        raise RuntimeError(
            f"Failed to connect to any ClickHouse host in {self._hosts}: {last_error}"
        )

    def _invalidate_client(self) -> None:
        """Drop the cached thread-local client so the next call reconnects."""
        client: Any = getattr(self._local, "client", None)
        if client is not None:
            with contextlib.suppress(Exception):
                client.close()
        self._local.client = None
        self._local.host = None

    # ------------------------------------------------------------------
    # Cluster helpers
    # ------------------------------------------------------------------

    def create_distributed_table(
        self,
        local_table: str = "events_local",
        distributed_table: str = "events",
        *,
        sharding_key: str = "rand()",
    ) -> str:
        """Create (or replace) the Distributed proxy table for the events cluster.

        Returns the SQL statement that was executed. In unit tests without a
        live ClickHouse, callers can read the generated SQL from
        :meth:`get_distributed_table_ddl`.
        """
        if not self._cluster_name:
            raise RuntimeError(
                "create_distributed_table() requires cluster_name to be set on the backend"
            )
        sql = self.get_distributed_table_ddl(
            cluster_name=self._cluster_name,
            database=self._database,
            local_table=local_table,
            distributed_table=distributed_table,
            sharding_key=sharding_key,
        )
        client = self._get_client()
        client.command(sql)
        logger.info(
            "clickhouse_distributed_table_created",
            cluster=self._cluster_name,
            table=distributed_table,
        )
        return sql

    @staticmethod
    def get_distributed_table_ddl(
        *,
        cluster_name: str,
        database: str,
        local_table: str = "events_local",
        distributed_table: str = "events",
        sharding_key: str = "rand()",
    ) -> str:
        """Return the CREATE TABLE ... Distributed(...) DDL for the events table."""
        return (
            f"CREATE TABLE IF NOT EXISTS {database}.{distributed_table} "
            f"ON CLUSTER {cluster_name} "
            f"AS {database}.{local_table} "
            f"ENGINE = Distributed({cluster_name}, {database}, {local_table}, {sharding_key})"
        )

    # ------------------------------------------------------------------
    # DDL helpers (exposed for testing)
    # ------------------------------------------------------------------

    @staticmethod
    def get_events_ddl() -> str:
        """Return the CREATE TABLE DDL for the events table."""
        return _EVENTS_DDL

    @staticmethod
    def get_materialized_view_ddls() -> list[str]:
        """Return DDL statements for all materialized views."""
        return list(_MATERIALIZED_VIEWS)

    @staticmethod
    def get_ttl_sql(ttl_days: int) -> str:
        """Return the ALTER TABLE TTL statement for the given retention days."""
        return _ttl_alter_sql("events", ttl_days)

    # ------------------------------------------------------------------
    # Sync helpers
    # ------------------------------------------------------------------

    def _insert_events_sync(self, events: list[dict[str, Any]]) -> int:
        client = self._get_client()
        inserted = 0
        columns = [
            "event_id",
            "org_id",
            "timestamp",
            "event_type",
            "severity",
            "source_provider",
            "source_type",
            "raw_event",
            "normalized",
            "enrichments",
        ]

        for batch_start in range(0, len(events), _BATCH_SIZE):
            batch = events[batch_start : batch_start + _BATCH_SIZE]
            rows = [
                [
                    e.get("event_id", ""),
                    e.get("org_id", ""),
                    e.get(
                        "timestamp",
                        datetime.now(tz=UTC).isoformat(),
                    ),
                    e.get("event_type", ""),
                    e.get("severity", ""),
                    e.get("source_provider", ""),
                    e.get("source_type", ""),
                    json.dumps(e.get("raw_event")) if e.get("raw_event") else "",
                    json.dumps(e.get("normalized")) if e.get("normalized") else "",
                    json.dumps(e.get("enrichments")) if e.get("enrichments") else "",
                ]
                for e in batch
            ]
            client.insert(
                "events",
                rows,
                column_names=columns,
            )
            inserted += len(rows)

        logger.info("events_inserted", count=inserted, backend="clickhouse")
        return inserted

    def _query_sync(
        self,
        sql: str,
        params: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        client = self._get_client()
        result = client.query(sql, parameters=params or {})
        columns = result.column_names
        return [dict(zip(columns, row, strict=False)) for row in result.result_rows]

    def _query_paginated_sync(
        self,
        sql: str,
        params: dict[str, Any] | None = None,
        page: int = 1,
        limit: int = 100,
    ) -> PaginatedResult:
        client = self._get_client()
        count_sql = f"SELECT count() AS cnt FROM ({sql}) AS _sub"  # noqa: S608  # nosec B608
        count_result = client.query(count_sql, parameters=params or {})
        total = count_result.result_rows[0][0] if count_result.result_rows else 0

        offset = (page - 1) * limit
        paged_sql = f"{sql} LIMIT {limit} OFFSET {offset}"  # noqa: S608
        result = client.query(paged_sql, parameters=params or {})
        columns = result.column_names
        items = [dict(zip(columns, row, strict=False)) for row in result.result_rows]

        return PaginatedResult(
            items=items,
            total=total,
            page=page,
            limit=limit,
            has_more=(offset + limit) < total,
        )

    def _get_stats_sync(self) -> StorageStats:
        client = self._get_client()
        result = client.query(
            "SELECT count() AS cnt, "
            "sum(length(raw_event)) AS sz, "
            "min(timestamp) AS oldest, "
            "max(timestamp) AS newest "
            "FROM events"
        )
        if not result.result_rows or result.result_rows[0][0] == 0:
            return StorageStats()

        row = result.result_rows[0]

        # Approximate on-disk size from system tables.
        size_result = client.query(
            "SELECT sum(bytes_on_disk) FROM system.parts "
            "WHERE database = {db:String} AND table = 'events' AND active",
            parameters={"db": self._database},
        )
        storage_bytes = int(row[1])
        if size_result.result_rows and size_result.result_rows[0][0]:
            storage_bytes = int(size_result.result_rows[0][0])

        return StorageStats(
            total_events=int(row[0]),
            storage_bytes=storage_bytes,
            oldest_event=row[2],
            newest_event=row[3],
        )

    def _enforce_retention_sync(self, org_id: str, max_days: int) -> int:
        client = self._get_client()
        cutoff = datetime.now(tz=UTC) - timedelta(days=max_days)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        count_result = client.query(
            "SELECT count() FROM events "
            "WHERE org_id = {org:String} AND timestamp < {cutoff:String}",
            parameters={"org": org_id, "cutoff": cutoff_str},
        )
        before_count = count_result.result_rows[0][0] if count_result.result_rows else 0

        client.command(
            "ALTER TABLE events DELETE WHERE org_id = {org:String} AND timestamp < {cutoff:String}",
            parameters={"org": org_id, "cutoff": cutoff_str},
        )
        logger.info(
            "retention_enforced",
            org_id=org_id,
            max_days=max_days,
            deleted=before_count,
            backend="clickhouse",
        )
        return int(before_count)

    # ------------------------------------------------------------------
    # Async public API (matches EventStore protocol)
    # ------------------------------------------------------------------

    async def insert_events(self, events: list[dict[str, Any]]) -> int:
        """Batch insert events. Returns count of inserted events."""
        return await asyncio.to_thread(self._insert_events_sync, events)

    async def query(
        self,
        sql: str,
        params: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Execute a read-only SQL query. Returns results as list of dicts."""
        return await asyncio.to_thread(self._query_sync, sql, params)

    async def query_paginated(
        self,
        sql: str,
        params: dict[str, Any] | None = None,
        page: int = 1,
        limit: int = 100,
    ) -> PaginatedResult:
        """Execute a paginated SQL query."""
        return await asyncio.to_thread(self._query_paginated_sync, sql, params, page, limit)

    async def get_stats(self) -> StorageStats:
        """Return storage statistics."""
        return await asyncio.to_thread(self._get_stats_sync)

    async def enforce_retention(self, org_id: str, max_days: int) -> int:
        """Delete events older than max_days for org_id. Returns count deleted."""
        return await asyncio.to_thread(self._enforce_retention_sync, org_id, max_days)

    async def close(self) -> None:
        """Close the thread-local client."""
        client: Any = getattr(self._local, "client", None)
        if client is not None:
            client.close()
            self._local.client = None
