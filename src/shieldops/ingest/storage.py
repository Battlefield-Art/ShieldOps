"""Columnar storage backend for normalized OCSF events.

Supports DuckDB (embedded/self-hosted) with SQL query interface,
Parquet export, and configurable retention policies.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

import structlog

logger = structlog.get_logger()


class ColumnarStorage:
    """In-memory columnar storage with DuckDB-compatible SQL interface.

    For production, this class wraps DuckDB. For testing and development,
    it operates as an in-memory store with the same API surface.
    """

    def __init__(
        self,
        *,
        max_events: int = 1_000_000,
        retention_days: int = 30,
        use_duckdb: bool = False,
        db_path: str = ":memory:",
    ) -> None:
        self._max_events = max_events
        self._retention_days = retention_days
        self._events: list[dict[str, Any]] = []
        self._db: Any = None

        if use_duckdb:
            self._init_duckdb(db_path)

    def _init_duckdb(self, db_path: str) -> None:
        """Initialize DuckDB connection and create events table."""
        try:
            import duckdb

            self._db = duckdb.connect(db_path)
            self._db.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    event_id VARCHAR,
                    org_id VARCHAR,
                    timestamp TIMESTAMP,
                    event_type VARCHAR,
                    category_name VARCHAR,
                    severity VARCHAR,
                    severity_id INTEGER,
                    source_provider VARCHAR,
                    message VARCHAR,
                    activity_name VARCHAR,
                    status VARCHAR,
                    actor_json VARCHAR,
                    src_json VARCHAR,
                    observables_json VARCHAR,
                    metadata_json VARCHAR,
                    raw_data VARCHAR
                )
            """)
            logger.info("columnar_storage.duckdb_initialized", path=db_path)
        except ImportError:
            logger.warning("columnar_storage.duckdb_not_available_using_memory")
            self._db = None

    def insert(self, event: dict[str, Any], org_id: str = "default") -> None:
        """Insert a normalized OCSF event."""
        import json
        from uuid import uuid4

        record = {
            "event_id": event.get("event_id", str(uuid4())),
            "org_id": org_id,
            "timestamp": event.get("time", datetime.now(UTC).isoformat()),
            "event_type": event.get("activity_name", ""),
            "category_name": event.get("category_name", ""),
            "severity": event.get("severity", "informational"),
            "severity_id": event.get("severity_id", 1),
            "source_provider": event.get("source_provider", ""),
            "message": event.get("message", ""),
            "activity_name": event.get("activity_name", ""),
            "status": event.get("status", ""),
            "actor_json": json.dumps(event.get("actor", {})),
            "src_json": json.dumps(event.get("src", {})),
            "observables_json": json.dumps(event.get("observables", [])),
            "metadata_json": json.dumps(event.get("metadata", {})),
            "raw_data": event.get("raw_data", "")[:5000],
        }

        if self._db is not None:
            self._db.execute(
                "INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                list(record.values()),
            )
        else:
            self._events.append(record)
            # Ring buffer eviction
            if len(self._events) > self._max_events:
                self._events = self._events[-self._max_events :]

    def insert_batch(self, events: list[dict[str, Any]], org_id: str = "default") -> int:
        """Insert multiple events. Returns count inserted."""
        for event in events:
            self.insert(event, org_id)
        return len(events)

    def query(self, sql: str, params: list[Any] | None = None) -> list[dict[str, Any]]:
        """Execute SQL query and return results as list of dicts."""
        if self._db is not None:
            try:
                result = self._db.execute(sql, params or [])
                columns = [desc[0] for desc in result.description]
                return [dict(zip(columns, row, strict=False)) for row in result.fetchall()]
            except Exception as e:
                logger.error("columnar_storage.query_error", error=str(e), sql=sql[:200])
                return []

        # In-memory fallback: simple filtering
        return self._memory_query(sql)

    def _memory_query(self, sql: str) -> list[dict[str, Any]]:
        """Simple in-memory query for development/testing."""
        sql_lower = sql.lower().strip()

        # COUNT query
        if "count(*)" in sql_lower or "count(1)" in sql_lower:
            filtered = self._apply_where(sql_lower, self._events)
            return [{"count": len(filtered)}]

        # SELECT with WHERE
        filtered = self._apply_where(sql_lower, self._events)

        # LIMIT
        if "limit" in sql_lower:
            try:
                limit = int(sql_lower.split("limit")[-1].strip().split()[0])
                filtered = filtered[:limit]
            except (ValueError, IndexError):
                pass

        # ORDER BY severity_id DESC
        if "order by" in sql_lower and "desc" in sql_lower:
            filtered = sorted(filtered, key=lambda e: e.get("severity_id", 0), reverse=True)

        return filtered

    def _apply_where(self, sql_lower: str, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Apply simple WHERE clause filtering."""
        if "where" not in sql_lower:
            return list(events)

        where_clause = sql_lower.split("where", 1)[1].split("order")[0].split("limit")[0].strip()
        filtered = list(events)

        # Handle simple equality: field = 'value'
        import re

        equalities = re.findall(r"(\w+)\s*=\s*'([^']*)'", where_clause)
        for field, value in equalities:
            filtered = [e for e in filtered if str(e.get(field, "")).lower() == value.lower()]

        return filtered

    def get_stats(self) -> dict[str, Any]:
        """Return storage statistics."""
        if self._db is not None:
            try:
                total = self._db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                by_source = self._db.execute(
                    "SELECT source_provider, COUNT(*) as cnt FROM events GROUP BY source_provider"
                ).fetchall()
                by_severity = self._db.execute(
                    "SELECT severity, COUNT(*) as cnt FROM events GROUP BY severity"
                ).fetchall()
                return {
                    "total_events": total,
                    "by_source": dict(by_source),
                    "by_severity": dict(by_severity),
                    "storage_backend": "duckdb",
                }
            except Exception:
                pass

        # In-memory stats
        by_source: dict[str, int] = defaultdict(int)  # type: ignore[no-redef]
        by_severity: dict[str, int] = defaultdict(int)  # type: ignore[no-redef]
        for e in self._events:
            by_source[e.get("source_provider", "unknown")] += 1
            by_severity[e.get("severity", "unknown")] += 1

        return {
            "total_events": len(self._events),
            "by_source": dict(by_source),
            "by_severity": dict(by_severity),
            "storage_backend": "memory",
            "max_events": self._max_events,
            "retention_days": self._retention_days,
        }

    def export_parquet(self, path: str) -> int:
        """Export events to Parquet file. Returns count exported."""
        if self._db is not None:
            try:
                self._db.execute(f"COPY events TO '{path}' (FORMAT PARQUET)")
                count = self._db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                logger.info("columnar_storage.parquet_exported", path=path, count=count)
                return count  # type: ignore[no-any-return]
            except Exception as e:
                logger.error("columnar_storage.parquet_export_error", error=str(e))
                return 0

        logger.warning("columnar_storage.parquet_requires_duckdb")
        return 0

    def enforce_retention(self) -> int:
        """Remove events older than retention period. Returns count removed."""
        cutoff = datetime.now(UTC).timestamp() - (self._retention_days * 86400)
        cutoff_iso = datetime.fromtimestamp(cutoff, tz=UTC).isoformat()

        if self._db is not None:
            try:
                before = self._db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                self._db.execute("DELETE FROM events WHERE timestamp < ?", [cutoff_iso])
                after = self._db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                removed = before - after
                logger.info("columnar_storage.retention_enforced", removed=removed)
                return removed  # type: ignore[no-any-return]
            except Exception as e:
                logger.error("columnar_storage.retention_error", error=str(e))
                return 0

        before = len(self._events)
        self._events = [e for e in self._events if e.get("timestamp", "") >= cutoff_iso]
        removed = before - len(self._events)
        if removed:
            logger.info("columnar_storage.retention_enforced", removed=removed)
        return removed  # type: ignore[no-any-return]

    def clear(self) -> None:
        """Clear all events."""
        if self._db is not None:
            self._db.execute("DELETE FROM events")
        self._events.clear()
