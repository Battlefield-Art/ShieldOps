"""Honeycomb Observability Integration for ShieldOps.

Provides wide structured event ingestion, distributed tracing, and pre-built
query definitions for monitoring autonomous SRE agents via Honeycomb.
"""

from shieldops.integrations.honeycomb.ingest import (
    HoneycombClient,
    HoneycombEvent,
    HoneycombSpan,
)
from shieldops.integrations.honeycomb.queries import (
    HoneycombQuery,
    HoneycombQueryManager,
)

__all__ = [
    "HoneycombClient",
    "HoneycombEvent",
    "HoneycombQuery",
    "HoneycombQueryManager",
    "HoneycombSpan",
]
