"""DuckDB event store backend — embedded columnar storage for security events."""

from __future__ import annotations

import asyncio
import json
import os
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import structlog

from shieldops.storage.interface import PaginatedResult, StorageStats

logger = structlog.get_logger()

try:
    import duckdb
except ImportError:
    duckdb = None  # type: ignore[assignment]

_EVENTS_DDL = """
CREATE TABLE IF NOT EXISTS events (
    event_id VARCHAR PRIMARY KEY,
    org_id VARCHAR NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    event_type VARCHAR NOT NULL,
    severity VARCHAR,
    source_provider VARCHAR NOT NULL,
    source_type VARCHAR,
    raw_event JSON,
    normalized JSON,
    enrichments JSON
)
"""

_BATCH_SIZE = 10_000


class DuckDBEventStore:
    """DuckDB-backed event store with Parquet export and tenant isolation.

    Thread-safe: each thread gets its own DuckDB connection via a local store.
    Async interface wraps synchronous DuckDB calls with ``asyncio.to_thread``.
    """

    def __init__(
        self,
        db_path: str = "shieldops_events.duckdb",
        parquet_path: str = "./data/parquet",
    ) -> None:
        if duckdb is None:
            raise RuntimeError(
                "duckdb package is not installed. Install it with: pip install duckdb"
            )
        self._db_path = db_path
        self._parquet_path = Path(parquet_path)
        self._local = threading.local()
        self._lock = threading.Lock()

        # Initialize table on the main connection.
        conn = self._get_conn()
        conn.execute(_EVENTS_DDL)
        logger.info(
            "duckdb_event_store_initialized",
            db_path=db_path,
            parquet_path=parquet_path,
        )

    # ------------------------------------------------------------------
    # Connection pooling (thread-local)
    # ------------------------------------------------------------------

    def _get_conn(self) -> duckdb.DuckDBPyConnection:  # type: ignore[name-defined]
        """Return a thread-local DuckDB connection."""
        conn: duckdb.DuckDBPyConnection | None = getattr(self._local, "conn", None)  # type: ignore[name-defined]
        if conn is None:
            conn = duckdb.connect(self._db_path)  # type: ignore[union-attr]
            self._local.conn = conn
        return conn

    # ------------------------------------------------------------------
    # Core interface (sync helpers wrapped by async public methods)
    # ------------------------------------------------------------------

    def _insert_events_sync(self, events: list[dict[str, Any]]) -> int:
        conn = self._get_conn()
        inserted = 0
        for batch_start in range(0, len(events), _BATCH_SIZE):
            batch = events[batch_start : batch_start + _BATCH_SIZE]
            rows = [
                (
                    e.get("event_id", ""),
                    e.get("org_id", ""),
                    e.get("timestamp", datetime.now(tz=UTC).isoformat()),
                    e.get("event_type", ""),
                    e.get("severity"),
                    e.get("source_provider", ""),
                    e.get("source_type"),
                    json.dumps(e.get("raw_event")) if e.get("raw_event") else None,
                    json.dumps(e.get("normalized")) if e.get("normalized") else None,
                    json.dumps(e.get("enrichments")) if e.get("enrichments") else None,
                )
                for e in batch
            ]
            conn.executemany(
                "INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                rows,
            )
            inserted += len(rows)
        logger.info("events_inserted", count=inserted)
        return inserted

    def _query_sync(
        self,
        sql: str,
        params: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        conn = self._get_conn()
        if params:
            result = conn.execute(sql, params)
        else:
            result = conn.execute(sql)
        columns = [desc[0] for desc in result.description]
        return [dict(zip(columns, row, strict=False)) for row in result.fetchall()]

    def _query_paginated_sync(
        self,
        sql: str,
        params: dict[str, Any] | None = None,
        page: int = 1,
        limit: int = 100,
    ) -> PaginatedResult:
        conn = self._get_conn()

        # Count total rows for the base query.
        count_sql = f"SELECT COUNT(*) AS cnt FROM ({sql}) AS _sub"  # noqa: S608  # nosec B608
        if params:
            total = conn.execute(count_sql, params).fetchone()[0]  # type: ignore[index]
        else:
            total = conn.execute(count_sql).fetchone()[0]  # type: ignore[index]

        offset = (page - 1) * limit
        paged_sql = f"{sql} LIMIT {limit} OFFSET {offset}"  # noqa: S608
        if params:
            result = conn.execute(paged_sql, params)
        else:
            result = conn.execute(paged_sql)

        columns = [desc[0] for desc in result.description]
        items = [dict(zip(columns, row, strict=False)) for row in result.fetchall()]

        return PaginatedResult(
            items=items,
            total=total,
            page=page,
            limit=limit,
            has_more=(offset + limit) < total,
        )

    def _get_stats_sync(self) -> StorageStats:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT COUNT(*) AS cnt, "
            "COALESCE(SUM(LENGTH(CAST(raw_event AS VARCHAR))), 0) AS sz, "
            "MIN(timestamp) AS oldest, "
            "MAX(timestamp) AS newest "
            "FROM events"
        ).fetchone()
        if row is None or row[0] == 0:
            return StorageStats()

        # Also get actual file size if available.
        storage_bytes = int(row[1])
        if os.path.exists(self._db_path):
            storage_bytes = os.path.getsize(self._db_path)

        return StorageStats(
            total_events=int(row[0]),
            storage_bytes=storage_bytes,
            oldest_event=row[2],
            newest_event=row[3],
        )

    def _enforce_retention_sync(self, org_id: str, max_days: int) -> int:
        conn = self._get_conn()
        cutoff = datetime.now(tz=UTC) - timedelta(days=max_days)
        before_count = conn.execute(
            "SELECT COUNT(*) FROM events WHERE org_id = ? AND timestamp < ?",
            [org_id, cutoff],
        ).fetchone()[0]  # type: ignore[index]
        conn.execute(
            "DELETE FROM events WHERE org_id = ? AND timestamp < ?",
            [org_id, cutoff],
        )
        logger.info(
            "retention_enforced",
            org_id=org_id,
            max_days=max_days,
            deleted=before_count,
        )
        return int(before_count)

    # ------------------------------------------------------------------
    # Parquet export
    # ------------------------------------------------------------------

    def _export_to_parquet_sync(
        self,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
    ) -> list[str]:
        """Export event data to Parquet files partitioned by year/month/day.

        Returns list of written file paths.
        """
        conn = self._get_conn()
        where_clauses: list[str] = []
        bind_params: list[Any] = []
        if start_date:
            where_clauses.append("timestamp >= ?")
            bind_params.append(start_date)
        if end_date:
            where_clauses.append("timestamp < ?")
            bind_params.append(end_date)

        where_sql = f" WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
        rows_sql = f"SELECT *, YEAR(timestamp) AS yr, MONTH(timestamp) AS mn, DAY(timestamp) AS dy FROM events{where_sql}"  # noqa: S608, E501  # nosec B608

        if bind_params:
            rows = conn.execute(rows_sql, bind_params).fetchall()
        else:
            rows = conn.execute(rows_sql).fetchall()

        if not rows:
            return []

        # Group by date partition.
        partitions: dict[tuple[int, int, int], list[Any]] = {}
        for row in rows:
            yr, mn, dy = row[-3], row[-2], row[-1]
            partitions.setdefault((yr, mn, dy), []).append(row[:-3])

        written: list[str] = []
        columns = [desc[0] for desc in conn.execute("SELECT * FROM events LIMIT 0").description]
        for (yr, mn, dy), part_rows in partitions.items():
            part_dir = self._parquet_path / str(yr) / f"{mn:02d}" / f"{dy:02d}"
            part_dir.mkdir(parents=True, exist_ok=True)
            out_path = part_dir / "events.parquet"

            # Write via DuckDB from a temporary table for efficiency.
            tmp_name = f"_tmp_export_{yr}_{mn}_{dy}"
            conn.execute(f"DROP TABLE IF EXISTS {tmp_name}")  # noqa: S608  # nosec B608
            conn.execute(
                f"CREATE TEMPORARY TABLE {tmp_name} AS SELECT * FROM events LIMIT 0"  # noqa: S608, E501  # nosec B608
            )
            conn.executemany(
                f"INSERT INTO {tmp_name} VALUES ({','.join('?' for _ in columns)})",  # noqa: S608  # nosec B608
                part_rows,
            )
            conn.execute(
                f"COPY {tmp_name} TO '{out_path}' (FORMAT PARQUET)"  # noqa: S608
            )
            conn.execute(f"DROP TABLE IF EXISTS {tmp_name}")  # noqa: S608  # nosec B608
            written.append(str(out_path))

        logger.info("parquet_export_complete", files=len(written))
        return written

    # ------------------------------------------------------------------
    # Parquet query support
    # ------------------------------------------------------------------

    def _register_parquet_view(self) -> None:
        """Register a view that unions the DuckDB table with Parquet files."""
        conn = self._get_conn()
        parquet_glob = str(self._parquet_path / "**" / "*.parquet")
        if any(self._parquet_path.rglob("*.parquet")):
            conn.execute(
                f"CREATE OR REPLACE VIEW events_all AS "  # noqa: S608  # nosec B608
                f"SELECT * FROM events "
                f"UNION ALL "
                f"SELECT * FROM read_parquet('{parquet_glob}', union_by_name=true)"
            )
        else:
            conn.execute("CREATE OR REPLACE VIEW events_all AS SELECT * FROM events")

    # ------------------------------------------------------------------
    # Async public API
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

    async def export_to_parquet(
        self,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
    ) -> list[str]:
        """Export events to Parquet files partitioned by date."""
        return await asyncio.to_thread(self._export_to_parquet_sync, start_date, end_date)

    async def close(self) -> None:
        """Close the thread-local connection."""
        conn: Any = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None
