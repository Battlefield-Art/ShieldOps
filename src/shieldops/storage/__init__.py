"""ShieldOps embedded columnar storage — DuckDB backend for security events."""

from __future__ import annotations

from shieldops.storage.interface import EventStore, PaginatedResult, StorageStats

__all__ = ["EventStore", "PaginatedResult", "StorageStats"]
