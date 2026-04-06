"""Storage singleton — shared EventStore instance for the application.

Provides a lazy-init ``get_event_store()`` that returns the same instance
across webhook routes, query routes, and pipeline processing.

Set ``SHIELDOPS_STORAGE_BACKEND=clickhouse`` to use ClickHouse instead of
the default DuckDB backend.
"""

from __future__ import annotations

import os
from typing import Any

import structlog

logger = structlog.get_logger()

_store: Any | None = None


def get_event_store() -> Any:
    """Return the module-level EventStore singleton.

    Creates the instance on first call.  The backend is selected via the
    ``SHIELDOPS_STORAGE_BACKEND`` env var (``duckdb`` or ``clickhouse``,
    default ``duckdb``).
    """
    global _store  # noqa: PLW0603
    if _store is not None:
        return _store

    backend = os.environ.get("SHIELDOPS_STORAGE_BACKEND", "duckdb").lower()

    if backend == "clickhouse":
        from shieldops.storage.clickhouse_backend import ClickHouseEventStore

        _store = ClickHouseEventStore(
            host=os.environ.get("CLICKHOUSE_HOST", "localhost"),
            port=int(os.environ.get("CLICKHOUSE_PORT", "8123")),
            database=os.environ.get("CLICKHOUSE_DATABASE", "shieldops"),
            user=os.environ.get("CLICKHOUSE_USER", "default"),
            password=os.environ.get("CLICKHOUSE_PASSWORD", ""),
            ttl_days=(
                int(os.environ["CLICKHOUSE_TTL_DAYS"])
                if os.environ.get("CLICKHOUSE_TTL_DAYS")
                else None
            ),
            secure=os.environ.get("CLICKHOUSE_SECURE", "").lower() in ("1", "true"),
        )
        logger.info(
            "event_store_singleton_created",
            backend="clickhouse",
            host=os.environ.get("CLICKHOUSE_HOST", "localhost"),
        )
    else:
        from shieldops.storage.duckdb_backend import DuckDBEventStore

        db_path = os.environ.get("SHIELDOPS_DUCKDB_PATH", "shieldops_events.duckdb")
        parquet_path = os.environ.get("SHIELDOPS_PARQUET_PATH", "./data/parquet")
        _store = DuckDBEventStore(db_path=db_path, parquet_path=parquet_path)
        logger.info("event_store_singleton_created", backend="duckdb", db_path=db_path)

    return _store


def set_event_store(store: Any) -> None:
    """Override the singleton (useful for testing with a temp backend)."""
    global _store  # noqa: PLW0603
    _store = store


def reset_event_store() -> None:
    """Reset the singleton (useful for testing teardown)."""
    global _store  # noqa: PLW0603
    _store = None
