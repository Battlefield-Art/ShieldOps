"""Storage interface — protocol for event store backends."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, Field


class PaginatedResult(BaseModel):
    """Paginated query result."""

    items: list[dict] = Field(default_factory=list)  # type: ignore[arg-type]
    total: int = 0
    page: int = 1
    limit: int = 100
    has_more: bool = False


class StorageStats(BaseModel):
    """Storage statistics."""

    total_events: int = 0
    storage_bytes: int = 0
    oldest_event: datetime | None = None
    newest_event: datetime | None = None


@runtime_checkable
class EventStore(Protocol):
    """Protocol defining the event store interface.

    All implementations must provide async methods for inserting, querying,
    paginating, collecting stats, and enforcing retention on security events.
    """

    async def insert_events(self, events: list[dict]) -> int:  # type: ignore[type-arg]
        """Batch insert events. Returns count of inserted events."""
        ...

    async def query(
        self,
        sql: str,
        params: dict | None = None,  # type: ignore[type-arg]
    ) -> list[dict]:  # type: ignore[type-arg]
        """Execute a read-only SQL query. Returns results as list of dicts."""
        ...

    async def query_paginated(
        self,
        sql: str,
        params: dict | None = None,  # type: ignore[type-arg]
        page: int = 1,
        limit: int = 100,
    ) -> PaginatedResult:
        """Execute a paginated SQL query."""
        ...

    async def get_stats(self) -> StorageStats:
        """Return storage statistics (event count, size, date range)."""
        ...

    async def enforce_retention(self, org_id: str, max_days: int) -> int:
        """Delete events older than max_days for org_id. Returns count deleted."""
        ...
