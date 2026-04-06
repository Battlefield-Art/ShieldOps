"""Ingestion API — front door for all telemetry flowing into ShieldOps.

POST /api/v1/ingestion/events  — single or batch event ingestion
  - 202 Accepted for valid events (queued for processing)
  - 400 Bad Request for malformed payloads
  - 409 Conflict for duplicate event_ids
  - 429 Too Many Requests when rate limit is exceeded

Deduplication uses a Redis set with 24-hour TTL keyed by event_id.
If Redis is unavailable, dedup is skipped (fail-open).
"""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import ValidationError

from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.auth.models import UserResponse
from shieldops.api.middleware.metrics import MetricsRegistry
from shieldops.api.models.ingestion import (
    IngestBatchResponse,
    IngestEvent,
    IngestResponse,
)
from shieldops.ingestion.kafka_consumer import get_consumer as _get_kafka_consumer
from shieldops.ingestion.kafka_producer import get_producer as _get_kafka_producer

logger = structlog.get_logger()

router = APIRouter(prefix="/ingestion", tags=["Ingestion"])

# 24 hours in seconds for dedup TTL
_DEDUP_TTL_SECONDS = 86_400

# Backpressure: reject ingestion when consumer lag exceeds this many messages.
# Configurable via ``set_backpressure_threshold``.
_BACKPRESSURE_THRESHOLD: int = 10_000

# Module-level Redis handle — set via ``set_redis()`` during app startup.
_redis: Any | None = None


def set_redis(redis_client: Any) -> None:
    """Inject a Redis client for deduplication checks."""
    global _redis  # noqa: PLW0603
    _redis = redis_client


def set_backpressure_threshold(threshold: int) -> None:
    """Override the consumer-lag threshold used for 429 backpressure."""
    global _BACKPRESSURE_THRESHOLD  # noqa: PLW0603
    _BACKPRESSURE_THRESHOLD = max(0, int(threshold))


async def _check_backpressure() -> None:
    """Raise 429 if Kafka consumer lag exceeds the configured threshold."""
    consumer = _get_kafka_consumer()
    if consumer is None:
        return
    try:
        lag = await consumer.lag()
    except Exception as exc:
        logger.warning("ingestion.lag_check_error", error=str(exc))
        return
    if lag > _BACKPRESSURE_THRESHOLD:
        logger.warning(
            "ingestion.backpressure_triggered",
            lag=lag,
            threshold=_BACKPRESSURE_THRESHOLD,
        )
        raise HTTPException(
            status_code=429,
            detail=(
                f"Ingestion backpressure: consumer lag {lag} exceeds "
                f"threshold {_BACKPRESSURE_THRESHOLD}"
            ),
        )


def _metrics() -> MetricsRegistry:
    return MetricsRegistry.get_instance()


# ---------------------------------------------------------------------------
# Deduplication helpers
# ---------------------------------------------------------------------------


async def _is_duplicate(event_id: UUID) -> bool:
    """Check if *event_id* was already ingested (Redis SISMEMBER).

    Returns ``False`` (not duplicate) when Redis is unavailable (fail-open).
    """
    if _redis is None:
        return False
    try:
        key = "shieldops:ingest_dedup"
        return bool(await _redis.sismember(key, str(event_id)))
    except Exception as exc:
        logger.warning("dedup_redis_error", error=str(exc))
        return False


async def _mark_ingested(event_id: UUID) -> None:
    """Add *event_id* to the dedup set with a 24-hour TTL member expiry.

    Uses a per-event key with TTL since Redis sets don't support per-member
    expiry.
    """
    if _redis is None:
        return
    try:
        key = f"shieldops:ingest_seen:{event_id}"
        await _redis.set(key, "1", ex=_DEDUP_TTL_SECONDS)
    except Exception as exc:
        logger.warning("dedup_mark_redis_error", error=str(exc))


async def _is_duplicate_v2(event_id: UUID) -> bool:
    """Per-key dedup check (matches ``_mark_ingested`` storage scheme)."""
    if _redis is None:
        return False
    try:
        key = f"shieldops:ingest_seen:{event_id}"
        return bool(await _redis.exists(key))
    except Exception as exc:
        logger.warning("dedup_redis_error", error=str(exc))
        return False


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/events", status_code=202, operation_id="ingestion_events")
async def ingest_events(
    request: Request,
    _user: UserResponse = Depends(get_current_user),
) -> IngestBatchResponse:
    """Ingest one or more telemetry events.

    Accepts either a single ``IngestEvent`` JSON object or a JSON array of
    ``IngestEvent`` objects.  Returns 202 Accepted with per-event status.
    """
    metrics = _metrics()

    # Backpressure: reject early if downstream consumers are lagging.
    await _check_backpressure()

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload") from None

    # Normalise to a list
    if isinstance(body, dict):
        raw_events = [body]
    elif isinstance(body, list):
        raw_events = body
    else:
        raise HTTPException(
            status_code=400,
            detail="Payload must be a JSON object or array of objects",
        )

    accepted = 0
    rejected = 0
    results: list[IngestResponse] = []

    for idx, raw in enumerate(raw_events):
        if not isinstance(raw, dict):
            rejected += 1
            metrics.inc_counter("ingestion_rejected_total", {"reason": "validation"})
            results.append(
                IngestResponse(
                    event_id=UUID("00000000-0000-0000-0000-000000000000"),
                    status="rejected",
                    message=f"event[{idx}]: not a JSON object",
                )
            )
            continue

        # Validate via Pydantic
        try:
            event = IngestEvent.model_validate(raw)
        except ValidationError as exc:
            rejected += 1
            metrics.inc_counter("ingestion_rejected_total", {"reason": "validation"})
            # Build a concise error message from Pydantic errors
            error_msgs = "; ".join(
                f"{'.'.join(str(part) for part in e['loc'])}: {e['msg']}" for e in exc.errors()
            )
            results.append(
                IngestResponse(
                    event_id=UUID("00000000-0000-0000-0000-000000000000"),
                    status="rejected",
                    message=f"event[{idx}]: {error_msgs}",
                )
            )
            continue

        # Deduplication
        if await _is_duplicate_v2(event.event_id):
            rejected += 1
            metrics.inc_counter("ingestion_rejected_total", {"reason": "duplicate"})
            results.append(
                IngestResponse(
                    event_id=event.event_id,
                    status="rejected",
                    message="duplicate event_id",
                )
            )
            continue

        # --- Event accepted ---
        await _mark_ingested(event.event_id)

        # Publish to Kafka if a producer is configured. Failures are
        # logged but do not fail the request (fail-open so the existing
        # in-process pipeline can still handle the event).
        kafka_producer = _get_kafka_producer()
        if kafka_producer is not None and kafka_producer.available:
            try:
                await kafka_producer.publish(
                    org_id=str(getattr(event, "org_id", "") or ""),
                    event_id=str(event.event_id),
                    event=raw,
                )
            except Exception as exc:
                logger.warning("ingestion.kafka_publish_error", error=str(exc))

        # Track metrics
        metrics.inc_counter(
            "ingestion_events_total",
            {"source_provider": event.source_provider, "status": "accepted"},
        )
        payload_size = len(json.dumps(raw).encode())
        metrics.inc_counter(
            "ingestion_bytes_total",
            {"source_provider": event.source_provider},
            amount=payload_size,
        )

        accepted += 1
        results.append(
            IngestResponse(
                event_id=event.event_id,
                status="accepted",
            )
        )

        logger.debug(
            "ingestion.event_accepted",
            event_id=str(event.event_id),
            source_provider=event.source_provider,
            event_type=event.event_type,
        )

    logger.info(
        "ingestion.batch_processed",
        accepted=accepted,
        rejected=rejected,
        total=len(raw_events),
    )

    return IngestBatchResponse(
        accepted=accepted,
        rejected=rejected,
        events=results,
    )


@router.get("/health", operation_id="ingestion_health")
async def ingestion_health() -> dict[str, str]:
    """Lightweight health check for the ingestion endpoint."""
    return {"status": "healthy"}
