"""Kafka consumer for raw event ingestion.

Reads from the ``ingest.raw`` topic in consumer group
``shieldops-ingestion``, normalizes each message through the OCSF
mapper, and batch-inserts the result into the event store. Commits
offsets only after a successful batch insert.

Malformed messages (bad JSON, mapper failure) are routed to the
``ingest.dlq`` topic via the injected ``KafkaEventProducer`` so that
the main pipeline never blocks on a poison pill.

Graceful degradation:
    - If ``aiokafka`` is missing or the broker is unreachable, ``start``
      logs a warning and ``run`` becomes a no-op.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import structlog

from shieldops.ingestion.kafka_producer import TOPIC_DLQ, TOPIC_RAW, KafkaEventProducer
from shieldops.ingestion.ocsf.mapper import normalize

logger = structlog.get_logger()

CONSUMER_GROUP = "shieldops-ingestion"


class KafkaEventConsumer:
    """Async Kafka consumer that normalizes and stores events."""

    def __init__(
        self,
        bootstrap_servers: str = "localhost:9092",
        topic: str = TOPIC_RAW,
        group_id: str = CONSUMER_GROUP,
        batch_size: int = 500,
        batch_timeout_ms: int = 1_000,
        dlq_producer: KafkaEventProducer | None = None,
        store: Any | None = None,
    ) -> None:
        self.bootstrap_servers = bootstrap_servers
        self.topic = topic
        self.group_id = group_id
        self.batch_size = batch_size
        self.batch_timeout_ms = batch_timeout_ms
        self.dlq_producer = dlq_producer
        self._store = store
        self._consumer: Any | None = None
        self._available: bool = False
        self._stop_event = asyncio.Event()

    async def start(self) -> None:
        try:
            from aiokafka import AIOKafkaConsumer  # lazy import
        except Exception as exc:  # pragma: no cover - import guard
            logger.warning("kafka_consumer.aiokafka_unavailable", error=str(exc))
            self._available = False
            return

        try:
            self._consumer = AIOKafkaConsumer(
                self.topic,
                bootstrap_servers=self.bootstrap_servers,
                group_id=self.group_id,
                enable_auto_commit=False,
                auto_offset_reset="earliest",
                max_poll_records=self.batch_size,
            )
            await self._consumer.start()
            self._available = True
            logger.info(
                "kafka_consumer.started",
                topic=self.topic,
                group=self.group_id,
            )
        except Exception as exc:
            logger.warning("kafka_consumer.start_failed", error=str(exc))
            self._consumer = None
            self._available = False

    async def stop(self) -> None:
        self._stop_event.set()
        if self._consumer is not None:
            try:
                await self._consumer.stop()
            except Exception as exc:  # pragma: no cover - shutdown path
                logger.warning("kafka_consumer.stop_failed", error=str(exc))
        self._consumer = None
        self._available = False

    @property
    def available(self) -> bool:
        return self._available and self._consumer is not None

    # ------------------------------------------------------------------
    # Store resolution (lazy, to avoid import cycles and ease testing)
    # ------------------------------------------------------------------

    def _get_store(self) -> Any:
        if self._store is not None:
            return self._store
        from shieldops.storage.singleton import get_event_store

        return get_event_store()

    # ------------------------------------------------------------------
    # Lag metric
    # ------------------------------------------------------------------

    async def lag(self) -> int:
        """Return the total consumer lag across assigned partitions.

        Returns 0 if the consumer is unavailable or lag cannot be
        computed (fail-open so ingest is never blocked on a metric).
        """
        if not self.available:
            return 0
        try:
            assert self._consumer is not None
            partitions = self._consumer.assignment()
            if not partitions:
                return 0
            total = 0
            highs = await self._consumer.end_offsets(list(partitions))
            for tp in partitions:
                committed = await self._consumer.committed(tp) or 0
                total += max(0, int(highs.get(tp, 0)) - int(committed))
            return total
        except Exception as exc:
            logger.warning("kafka_consumer.lag_error", error=str(exc))
            return 0

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Main consume loop — poll, normalize, insert, commit."""
        if not self.available:
            logger.info("kafka_consumer.run_skipped_unavailable")
            return

        assert self._consumer is not None
        logger.info("kafka_consumer.run_started")
        while not self._stop_event.is_set():
            try:
                batches = await self._consumer.getmany(
                    timeout_ms=self.batch_timeout_ms,
                    max_records=self.batch_size,
                )
                if not batches:
                    continue

                records: list[dict[str, Any]] = []
                for _tp, messages in batches.items():
                    for msg in messages:
                        record = await self._process_message(msg)
                        if record is not None:
                            records.append(record)

                if records:
                    try:
                        store = self._get_store()
                        await store.insert_events(records)
                    except Exception as exc:
                        logger.error(
                            "kafka_consumer.store_insert_failed",
                            error=str(exc),
                            batch_size=len(records),
                        )
                        # Do NOT commit — let the batch be redelivered.
                        continue

                # Commit only after successful insert (or empty-after-DLQ).
                await self._consumer.commit()
                logger.debug(
                    "kafka_consumer.batch_committed",
                    accepted=len(records),
                )
            except asyncio.CancelledError:  # pragma: no cover
                break
            except Exception as exc:
                logger.error("kafka_consumer.loop_error", error=str(exc))
                await asyncio.sleep(0.5)

        logger.info("kafka_consumer.run_stopped")

    async def _process_message(self, msg: Any) -> dict[str, Any] | None:
        """Parse + normalize one Kafka message.

        Returns a storage record or ``None`` if the message is bad and
        has been routed to the DLQ.
        """
        org_id = msg.key.decode("utf-8") if msg.key else ""
        raw_value: bytes = msg.value or b""

        # Lazy JSON parse — schema evolution friendly.
        try:
            raw_event = json.loads(raw_value.decode("utf-8"))
        except Exception as exc:
            logger.warning("kafka_consumer.bad_json", error=str(exc))
            await self._route_dlq(org_id, raw_value, f"bad_json: {exc}")
            return None

        source_provider = str(raw_event.get("source_provider") or "unknown")

        try:
            ocsf_event = normalize(source_provider, raw_event)
        except Exception as exc:
            logger.warning(
                "kafka_consumer.normalize_failed",
                source_provider=source_provider,
                error=str(exc),
            )
            await self._route_dlq(org_id, raw_value, f"normalize_failed: {exc}")
            return None

        return {
            "event_id": str(ocsf_event.event_id),
            "org_id": org_id or str(raw_event.get("org_id") or ""),
            "timestamp": ocsf_event.timestamp.isoformat(),
            "event_type": ocsf_event.event_type,
            "severity": ocsf_event.severity,
            "source_provider": ocsf_event.source_provider,
            "source_type": ocsf_event.source_type,
            "raw_event": ocsf_event.raw_event,
            "normalized": ocsf_event.normalized,
            "enrichments": ocsf_event.enrichments,
        }

    async def _route_dlq(self, org_id: str, raw_value: bytes, reason: str) -> None:
        if self.dlq_producer is None:
            logger.warning("kafka_consumer.dlq_unconfigured", reason=reason)
            return
        await self.dlq_producer.publish_dlq(
            org_id=org_id,
            raw_value=raw_value,
            reason=reason,
        )
        logger.info("kafka_consumer.dlq_routed", reason=reason, topic=TOPIC_DLQ)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_consumer: KafkaEventConsumer | None = None


def set_consumer(consumer: KafkaEventConsumer | None) -> None:
    global _consumer  # noqa: PLW0603
    _consumer = consumer


def get_consumer() -> KafkaEventConsumer | None:
    return _consumer
