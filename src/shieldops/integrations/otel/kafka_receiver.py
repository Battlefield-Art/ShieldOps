"""Kafka-based OpenTelemetry receiver for ShieldOps.

Inspired by splunk-opentelemetry-collector-for-kafka.
Consumes OTLP-encoded telemetry from Kafka topics and forwards
to ShieldOps observability pipeline.
"""

from __future__ import annotations

import time
from typing import Any, Protocol

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


class KafkaConsumerProtocol(Protocol):
    """Protocol for Kafka consumer implementations."""

    async def subscribe(self, topics: list[str]) -> None: ...
    async def poll(self, timeout_ms: int = 1000) -> list[dict[str, Any]]: ...
    async def commit(self) -> None: ...
    async def close(self) -> None: ...


class ReceiverConfig(BaseModel):
    """Configuration for the Kafka OTel receiver."""

    brokers: list[str] = Field(default_factory=lambda: ["localhost:9092"])
    topics: list[str] = Field(default_factory=lambda: ["otel.traces", "otel.metrics", "otel.logs"])
    topic_pattern: str = ""  # Regex pattern for dynamic topic discovery
    group_id: str = "shieldops-otel-receiver"
    encoding: str = "otlp_proto"  # otlp_proto, otlp_json, raw_json
    poll_timeout_ms: int = 1000
    batch_size: int = 512
    max_poll_records: int = 500


class ReceivedTelemetry(BaseModel):
    """A batch of received telemetry data."""

    signal_type: str = ""  # traces, metrics, logs
    topic: str = ""
    records: list[dict[str, Any]] = Field(default_factory=list)
    record_count: int = 0
    received_at: float = Field(default_factory=time.time)
    encoding: str = "otlp_proto"


class KafkaOTelReceiver:
    """Receives OpenTelemetry data from Kafka topics.

    Follows the Receiver->Processor->Exporter pattern from
    splunk-opentelemetry-collector-for-kafka.
    """

    def __init__(
        self,
        config: ReceiverConfig | None = None,
        consumer: KafkaConsumerProtocol | None = None,
    ) -> None:
        self._config = config or ReceiverConfig()
        self._consumer = consumer
        self._running = False
        self._stats = {
            "total_received": 0,
            "total_batches": 0,
            "errors": 0,
            "last_poll_at": 0.0,
        }
        logger.info(
            "kafka_otel_receiver.init",
            topics=self._config.topics,
            encoding=self._config.encoding,
        )

    async def start(self) -> None:
        """Start consuming from Kafka topics."""
        if self._consumer is None:
            logger.warning("kafka_otel_receiver.no_consumer")
            return
        topics = self._config.topics
        if self._config.topic_pattern:
            logger.info(
                "kafka_otel_receiver.topic_pattern",
                pattern=self._config.topic_pattern,
            )
        await self._consumer.subscribe(topics)
        self._running = True
        logger.info("kafka_otel_receiver.started", topics=topics)

    async def poll(self) -> ReceivedTelemetry | None:
        """Poll for a batch of telemetry records."""
        if not self._running or self._consumer is None:
            return None
        try:
            records = await self._consumer.poll(timeout_ms=self._config.poll_timeout_ms)
            if not records:
                return None

            self._stats["total_received"] += len(records)
            self._stats["total_batches"] += 1
            self._stats["last_poll_at"] = time.time()

            signal_type = self._infer_signal_type(records)
            return ReceivedTelemetry(
                signal_type=signal_type,
                topic=records[0].get("topic", "") if records else "",
                records=records,
                record_count=len(records),
                encoding=self._config.encoding,
            )
        except Exception:
            self._stats["errors"] += 1
            logger.exception("kafka_otel_receiver.poll.error")
            return None

    async def commit(self) -> None:
        """Commit consumer offsets."""
        if self._consumer:
            await self._consumer.commit()

    async def stop(self) -> None:
        """Stop the receiver."""
        self._running = False
        if self._consumer:
            await self._consumer.close()
        logger.info("kafka_otel_receiver.stopped", stats=self._stats)

    def get_stats(self) -> dict[str, Any]:
        """Get receiver statistics."""
        return {**self._stats, "running": self._running}

    def _infer_signal_type(self, records: list[dict[str, Any]]) -> str:
        """Infer telemetry signal type from topic or record structure."""
        if not records:
            return "unknown"
        topic = records[0].get("topic", "")
        if "trace" in topic.lower():
            return "traces"
        if "metric" in topic.lower():
            return "metrics"
        if "log" in topic.lower():
            return "logs"
        return "unknown"
