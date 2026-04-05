"""Storage singleton — shared DuckDBEventStore instance for the application.

Provides a lazy-init ``get_event_store()`` that returns the same instance
across webhook routes, query routes, and pipeline processing.
"""

from __future__ import annotations

import os
from typing import Any

import structlog

logger = structlog.get_logger()

_store: Any | None = None


def get_event_store() -> Any:
    """Return the module-level DuckDBEventStore singleton.

    Creates the instance on first call.  The database path is read from
    the ``SHIELDOPS_DUCKDB_PATH`` env var (default ``shieldops_events.duckdb``).
    """
    global _store  # noqa: PLW0603
    if _store is not None:
        return _store

    from shieldops.storage.duckdb_backend import DuckDBEventStore

    db_path = os.environ.get("SHIELDOPS_DUCKDB_PATH", "shieldops_events.duckdb")
    parquet_path = os.environ.get("SHIELDOPS_PARQUET_PATH", "./data/parquet")
    _store = DuckDBEventStore(db_path=db_path, parquet_path=parquet_path)
    logger.info("event_store_singleton_created", db_path=db_path)
    return _store


def set_event_store(store: Any) -> None:
    """Override the singleton (useful for testing with a temp DuckDB)."""
    global _store  # noqa: PLW0603
    _store = store


def reset_event_store() -> None:
    """Reset the singleton (useful for testing teardown)."""
    global _store  # noqa: PLW0603
    _store = None
