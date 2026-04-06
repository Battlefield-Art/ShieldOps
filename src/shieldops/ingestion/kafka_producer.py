"""Kafka producer for raw event ingestion.

Publishes incoming events to the ``ingest.raw`` topic, partitioned by
``org_id`` so that per-tenant ordering is preserved. Uses aiokafka for
async publishing and a Redis-backed bloom-ish dedup check (SET with TTL)
to drop repeat event_ids before they hit the broker.

Graceful degradation:
    - If ``aiokafka`` is not installed or the broker is unreachable, the
      producer logs a warning and ``publish()`` becomes a no-op returning
      ``False`` (callers should treat that as "not published, fall back").
    - Redis errors during dedup checks fail-open (not duplicate).
"""

from __future__ import annotations

import json
from typing import Any

import structlog

logger = structlog.get_logger()

# Topic names (kept module-level so they can be monkeypatched in tests).
TOPIC_RAW = "ingest.raw"
TOPIC_DLQ = "ingest.dlq"

# Redis key format for event_id dedup (24h TTL).
_DEDUP_KEY_FMT = "shieldops:ingest_seen:{event_id}"
_DEDUP_TTL_SECONDS = 86_400


class KafkaEventProducer:
    """Async Kafka producer for raw telemetry events.

    Example:
        producer = KafkaEventProducer(bootstrap_servers="kafka:9092")
        await producer.start()
        await producer.publish(org_id="acme", event_id="abc", event={...})
        await producer.stop()
    """

    def __init__(
        self,
        bootstrap_servers: str = "localhost:9092",
        topic: str = TOPIC_RAW,
        redis_client: Any | None = None,
        client_id: str = "shieldops-ingest-producer",
    ) -> None:
        self.bootstrap_servers = bootstrap_servers
        self.topic = topic
        self.redis = redis_client
        self.client_id = client_id
        self._producer: Any | None = None
        self._available: bool = False

    async def start(self) -> None:
        """Start the underlying aiokafka producer.

        Falls back to a disabled state (``_available = False``) if
        aiokafka is not installed or the broker is unreachable.
        """
        try:
            from aiokafka import AIOKafkaProducer  # lazy import
        except Exception as exc:  # pragma: no cover - import guard
            logger.warning("kafka_producer.aiokafka_unavailable", error=str(exc))
            self._available = False
            return

        try:
            self._producer = AIOKafkaProducer(
                bootstrap_servers=self.bootstrap_servers,
                client_id=self.client_id,
                enable_idempotence=True,
                acks="all",
                compression_type="gzip",
            )
            await self._producer.start()
            self._available = True
            logger.info(
                "kafka_producer.started",
                bootstrap_servers=self.bootstrap_servers,
                topic=self.topic,
            )
        except Exception as exc:
            logger.warning("kafka_producer.start_failed", error=str(exc))
            self._producer = None
            self._available = False

    async def stop(self) -> None:
        if self._producer is not None:
            try:
                await self._producer.stop()
            except Exception as exc:  # pragma: no cover - shutdown path
                logger.warning("kafka_producer.stop_failed", error=str(exc))
        self._producer = None
        self._available = False

    @property
    def available(self) -> bool:
        return self._available and self._producer is not None

    # ------------------------------------------------------------------
    # Dedup
    # ------------------------------------------------------------------

    async def _is_duplicate(self, event_id: str) -> bool:
        """Redis-backed dedup check (fail-open on Redis error)."""
        if self.redis is None or not event_id:
            return False
        try:
            key = _DEDUP_KEY_FMT.format(event_id=event_id)
            return bool(await self.redis.exists(key))
        except Exception as exc:
            logger.warning("kafka_producer.dedup_error", error=str(exc))
            return False

    async def _mark_seen(self, event_id: str) -> None:
        if self.redis is None or not event_id:
            return
        try:
            key = _DEDUP_KEY_FMT.format(event_id=event_id)
            await self.redis.set(key, "1", ex=_DEDUP_TTL_SECONDS)
        except Exception as exc:
            logger.warning("kafka_producer.mark_seen_error", error=str(exc))

    # ------------------------------------------------------------------
    # Publish
    # ------------------------------------------------------------------

    async def publish(
        self,
        *,
        org_id: str,
        event_id: str,
        event: dict[str, Any],
    ) -> bool:
        """Publish a single event to ``ingest.raw``.

        Args:
            org_id: Tenant identifier used as the partition key so that
                events from the same tenant land on the same partition
                (preserves per-tenant ordering).
            event_id: Unique event identifier used for deduplication.
            event: Raw event payload. Stored as a JSON string on the
                wire so that downstream consumers can parse lazily and
                schema evolution is non-breaking.

        Returns:
            ``True`` if the event was published, ``False`` if it was
            deduplicated or Kafka is unavailable.
        """
        if not self.available:
            logger.debug("kafka_producer.unavailable_skip", event_id=event_id)
            return False

        if await self._is_duplicate(event_id):
            logger.debug("kafka_producer.duplicate_skip", event_id=event_id)
            return False

        try:
            # Wire format: raw JSON string — lazy parse downstream,
            # schema-evolution friendly (new fields do not break consumers).
            value = json.dumps(event, default=str).encode("utf-8")
            key = org_id.encode("utf-8") if org_id else b""
            assert self._producer is not None  # for type narrowing
            await self._producer.send_and_wait(self.topic, value=value, key=key)
        except Exception as exc:
            logger.warning(
                "kafka_producer.publish_failed",
                event_id=event_id,
                error=str(exc),
            )
            return False

        await self._mark_seen(event_id)
        logger.debug(
            "kafka_producer.published",
            event_id=event_id,
            org_id=org_id,
            topic=self.topic,
        )
        return True

    async def publish_dlq(
        self,
        *,
        org_id: str,
        raw_value: bytes,
        reason: str,
    ) -> bool:
        """Route a malformed event to the dead-letter topic."""
        if not self.available:
            return False
        try:
            assert self._producer is not None
            headers = [("reason", reason.encode("utf-8"))]
            await self._producer.send_and_wait(
                TOPIC_DLQ,
                value=raw_value,
                key=org_id.encode("utf-8") if org_id else b"",
                headers=headers,
            )
            return True
        except Exception as exc:
            logger.warning("kafka_producer.dlq_publish_failed", error=str(exc))
            return False


# ---------------------------------------------------------------------------
# Module-level singleton accessors (mirrors other ingestion helpers)
# ---------------------------------------------------------------------------

_producer: KafkaEventProducer | None = None


def set_producer(producer: KafkaEventProducer | None) -> None:
    """Inject a producer at app startup."""
    global _producer  # noqa: PLW0603
    _producer = producer


def get_producer() -> KafkaEventProducer | None:
    return _producer
