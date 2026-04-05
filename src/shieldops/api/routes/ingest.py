"""Data ingestion API — accepts security telemetry from external sources."""

from __future__ import annotations

import time
from collections import Counter
from typing import Any
from uuid import uuid4

import structlog
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.auth.models import UserResponse
from shieldops.ingest.validator import validate_event

logger = structlog.get_logger()

router = APIRouter(prefix="/ingest", tags=["Data Ingestion"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class IngestEvent(BaseModel):
    """Single event for ingestion."""

    source: str = ""  # cloudtrail, crowdstrike_fdr, syslog, webhook, custom
    event_type: str = ""  # authentication, network, security_finding, api_activity
    timestamp: str = ""  # ISO 8601
    raw_event: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class IngestBatchRequest(BaseModel):
    """Batch of events for ingestion."""

    events: list[IngestEvent] = Field(default_factory=list)
    source: str = ""  # override source for all events in the batch
    model_config = {"extra": "forbid"}


class IngestResponse(BaseModel):
    """Response from ingestion endpoint."""

    accepted: int = 0
    rejected: int = 0
    event_ids: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# In-memory event buffer (replaced by Kafka / DuckDB in later slices)
# ---------------------------------------------------------------------------

_event_buffer: list[dict[str, Any]] = []
_MAX_BUFFER = 100_000

# Counters for /stats
_stats: dict[str, int] = {
    "total_accepted": 0,
    "total_rejected": 0,
    "total_requests": 0,
}
_source_counts: Counter[str] = Counter()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/events", status_code=202, operation_id="ingest_events")
async def ingest_events(
    body: IngestBatchRequest,
    _user: UserResponse = Depends(get_current_user),
) -> IngestResponse:
    """Ingest a batch of security events.

    Returns 202 Accepted — events are buffered for asynchronous processing.
    Individual events that fail validation are rejected while valid ones are
    still accepted (partial success).
    """
    _stats["total_requests"] += 1

    accepted = 0
    rejected = 0
    event_ids: list[str] = []
    errors: list[str] = []

    for idx, evt in enumerate(body.events):
        # Allow batch-level source override
        effective_source = evt.source or body.source

        raw = evt.model_dump()
        raw["source"] = effective_source

        validation_errors = validate_event(raw)
        if validation_errors:
            rejected += 1
            errors.append(f"event[{idx}]: {'; '.join(validation_errors)}")
            continue

        event_id = str(uuid4())

        # Evict oldest events when buffer is full
        if len(_event_buffer) >= _MAX_BUFFER:
            _event_buffer.pop(0)

        _event_buffer.append(
            {
                "event_id": event_id,
                "source": effective_source,
                "event_type": evt.event_type,
                "timestamp": evt.timestamp or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "raw_event": evt.raw_event,
                "metadata": evt.metadata,
                "ingested_at": time.time(),
            }
        )

        event_ids.append(event_id)
        accepted += 1
        _source_counts[effective_source] += 1

    _stats["total_accepted"] += accepted
    _stats["total_rejected"] += rejected

    logger.info(
        "ingest.batch_processed",
        accepted=accepted,
        rejected=rejected,
        buffer_size=len(_event_buffer),
    )

    return IngestResponse(
        accepted=accepted,
        rejected=rejected,
        event_ids=event_ids,
        errors=errors,
    )


@router.get("/health", operation_id="ingest_health")
async def ingest_health() -> dict[str, Any]:
    """Health check for ingestion pipeline."""
    return {
        "status": "healthy",
        "buffer_size": len(_event_buffer),
        "buffer_capacity": _MAX_BUFFER,
        "timestamp": time.time(),
    }


@router.get("/stats", operation_id="ingest_stats")
async def ingest_stats(
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """Ingestion pipeline statistics."""
    return {
        "total_requests": _stats["total_requests"],
        "total_accepted": _stats["total_accepted"],
        "total_rejected": _stats["total_rejected"],
        "buffer_size": len(_event_buffer),
        "buffer_capacity": _MAX_BUFFER,
        "source_counts": dict(_source_counts),
        "timestamp": time.time(),
    }
