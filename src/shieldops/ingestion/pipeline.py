"""Ingestion pipeline — validate, normalize (OCSF), store (DuckDB).

Wires the OCSF mapper and DuckDB event store into a single
``process_event`` / ``process_batch`` interface used by webhook endpoints.
"""

from __future__ import annotations

from typing import Any

import structlog
from pydantic import BaseModel, Field

from shieldops.ingestion.ocsf.mapper import normalize
from shieldops.storage.singleton import get_event_store

logger = structlog.get_logger()


class BatchResult(BaseModel):
    """Result of processing a batch of events through the pipeline."""

    accepted: int = 0
    rejected: int = 0
    event_ids: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


async def process_event(
    raw_event: dict[str, Any],
    source_provider: str,
    org_id: str,
) -> str:
    """Process a single raw event through the full pipeline.

    Steps:
        1. OCSF normalize (via mapper registry)
        2. Store in DuckDB (via EventStore.insert_events)

    Args:
        raw_event: Raw vendor event dict.
        source_provider: Vendor identifier (e.g. "cloudtrail").
        org_id: Tenant / organization identifier.

    Returns:
        The event_id (as string) of the stored event.

    Raises:
        ValueError: If the event cannot be processed.
    """
    # 1. Normalize
    ocsf_event = normalize(source_provider, raw_event)

    event_id = str(ocsf_event.event_id)

    # 2. Build storage record
    record: dict[str, Any] = {
        "event_id": event_id,
        "org_id": org_id,
        "timestamp": ocsf_event.timestamp.isoformat(),
        "event_type": ocsf_event.event_type,
        "severity": ocsf_event.severity,
        "source_provider": ocsf_event.source_provider,
        "source_type": ocsf_event.source_type,
        "raw_event": ocsf_event.raw_event,
        "normalized": ocsf_event.normalized,
        "enrichments": ocsf_event.enrichments,
    }

    # 3. Store
    store = get_event_store()
    await store.insert_events([record])

    logger.info(
        "pipeline.event_processed",
        event_id=event_id,
        source_provider=source_provider,
        event_type=ocsf_event.event_type,
        org_id=org_id,
    )

    return event_id


async def process_batch(
    events: list[dict[str, Any]],
    source_provider: str,
    org_id: str,
) -> BatchResult:
    """Process a batch of raw events through the pipeline.

    Each event is independently normalized and failures are captured
    without aborting the entire batch.

    Args:
        events: List of raw vendor event dicts.
        source_provider: Vendor identifier.
        org_id: Tenant / organization identifier.

    Returns:
        BatchResult with accepted/rejected counts and event_ids.
    """
    result = BatchResult()
    records: list[dict[str, Any]] = []

    for idx, raw_event in enumerate(events):
        try:
            ocsf_event = normalize(source_provider, raw_event)
            event_id = str(ocsf_event.event_id)

            record: dict[str, Any] = {
                "event_id": event_id,
                "org_id": org_id,
                "timestamp": ocsf_event.timestamp.isoformat(),
                "event_type": ocsf_event.event_type,
                "severity": ocsf_event.severity,
                "source_provider": ocsf_event.source_provider,
                "source_type": ocsf_event.source_type,
                "raw_event": ocsf_event.raw_event,
                "normalized": ocsf_event.normalized,
                "enrichments": ocsf_event.enrichments,
            }
            records.append(record)
            result.event_ids.append(event_id)
            result.accepted += 1
        except Exception as exc:
            result.rejected += 1
            result.errors.append(f"event[{idx}]: {exc}")
            logger.warning(
                "pipeline.event_rejected",
                index=idx,
                source_provider=source_provider,
                error=str(exc),
            )

    # Bulk insert all accepted events
    if records:
        store = get_event_store()
        await store.insert_events(records)

    logger.info(
        "pipeline.batch_processed",
        accepted=result.accepted,
        rejected=result.rejected,
        source_provider=source_provider,
        org_id=org_id,
    )

    return result
