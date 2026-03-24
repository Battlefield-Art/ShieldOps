"""Kafka producer for AI Security events."""

from __future__ import annotations

import json
import uuid
from typing import Any

import structlog

from shieldops.events.topics import SecurityEvent, SecurityTopic

logger = structlog.get_logger()


class SecurityEventProducer:
    """Publishes AI Security events to Kafka topics.

    The producer lazily initializes the underlying ``AIOKafkaProducer`` on the
    first ``publish`` call.  When ``aiokafka`` is not installed, events are
    buffered in-memory (up to ``_max_buffer``) so that callers never raise.
    """

    def __init__(self, bootstrap_servers: str = "localhost:9092") -> None:
        self._bootstrap_servers = bootstrap_servers
        self._producer: Any | None = None  # AIOKafkaProducer or None
        self._buffer: list[SecurityEvent] = []
        self._max_buffer: int = 1000
        self._started: bool = False
        self._publish_count: int = 0
        self._error_count: int = 0

    # ── Lifecycle ────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Initialize and start the Kafka producer."""
        try:
            from aiokafka import AIOKafkaProducer  # type: ignore[import-untyped]

            self._producer = AIOKafkaProducer(
                bootstrap_servers=self._bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                key_serializer=lambda k: k.encode("utf-8") if k else None,
            )
            await self._producer.start()
            self._started = True
            logger.info(
                "security_producer_started",
                bootstrap_servers=self._bootstrap_servers,
            )

            # Flush any buffered events
            if self._buffer:
                logger.info("security_producer_flushing_buffer", count=len(self._buffer))
                for evt in self._buffer:
                    await self._send(evt.topic, evt)
                self._buffer.clear()

        except ImportError:
            logger.warning(
                "security_producer_no_aiokafka",
                msg="aiokafka not installed — events will be buffered locally",
            )
        except Exception as exc:
            logger.error("security_producer_start_failed", error=str(exc))

    async def stop(self) -> None:
        """Flush pending messages and stop the producer."""
        if self._producer is not None:
            await self._producer.stop()
            self._producer = None
            self._started = False
            logger.info("security_producer_stopped")

    # ── Core publish ─────────────────────────────────────────────────────

    async def _send(self, topic: SecurityTopic, event: SecurityEvent) -> bool:
        """Low-level send to Kafka."""
        if self._producer is None:
            return False
        try:
            await self._producer.send_and_wait(
                topic.value,
                value=event.model_dump(),
                key=event.agent_id or event.event_id,
            )
            self._publish_count += 1
            logger.debug(
                "security_event_published",
                topic=topic.value,
                event_id=event.event_id,
                event_type=event.event_type,
            )
            return True
        except Exception as exc:
            self._error_count += 1
            logger.error(
                "security_event_publish_failed",
                topic=topic.value,
                event_id=event.event_id,
                error=str(exc),
            )
            return False

    async def publish(self, topic: SecurityTopic, event: SecurityEvent) -> bool:
        """Publish a security event to the specified Kafka topic.

        If the producer is not started, the event is buffered in-memory
        (ring-buffer with ``_max_buffer`` capacity).
        """
        event.topic = topic

        if not self._started or self._producer is None:
            # Buffer locally
            self._buffer.append(event)
            if len(self._buffer) > self._max_buffer:
                self._buffer.pop(0)
            logger.debug(
                "security_event_buffered",
                topic=topic.value,
                event_id=event.event_id,
                buffer_size=len(self._buffer),
            )
            return False

        return await self._send(topic, event)

    # ── Convenience publishers ───────────────────────────────────────────

    async def publish_firewall_event(
        self,
        agent_id: str,
        tool_name: str,
        action: str,
        risk_score: float,
        **kwargs: Any,
    ) -> bool:
        """Publish a firewall interception event."""
        event = SecurityEvent(
            topic=SecurityTopic.FIREWALL_EVENTS,
            event_type="firewall.intercept",
            agent_id=agent_id,
            severity="high" if risk_score > 0.7 else "medium" if risk_score > 0.4 else "low",
            payload={
                "tool_name": tool_name,
                "action": action,
                "risk_score": risk_score,
                **kwargs,
            },
        )
        return await self.publish(SecurityTopic.FIREWALL_EVENTS, event)

    async def publish_anomaly(
        self,
        agent_id: str,
        anomaly_type: str,
        severity: str,
        **kwargs: Any,
    ) -> bool:
        """Publish a firewall anomaly detection event."""
        event = SecurityEvent(
            topic=SecurityTopic.FIREWALL_ANOMALIES,
            event_type=f"firewall.anomaly.{anomaly_type}",
            agent_id=agent_id,
            severity=severity,
            payload={"anomaly_type": anomaly_type, **kwargs},
        )
        return await self.publish(SecurityTopic.FIREWALL_ANOMALIES, event)

    async def publish_circuit_breaker(
        self,
        agent_id: str,
        state: str,
        reason: str,
        **kwargs: Any,
    ) -> bool:
        """Publish a circuit breaker state change event."""
        event = SecurityEvent(
            topic=SecurityTopic.FIREWALL_CIRCUIT_BREAKER,
            event_type=f"firewall.circuit_breaker.{state}",
            agent_id=agent_id,
            severity="critical" if state == "open" else "info",
            payload={"state": state, "reason": reason, **kwargs},
        )
        return await self.publish(SecurityTopic.FIREWALL_CIRCUIT_BREAKER, event)

    async def publish_nhi_change(
        self,
        nhi_id: str,
        change_type: str,
        **kwargs: Any,
    ) -> bool:
        """Publish an NHI registry change event."""
        event = SecurityEvent(
            topic=SecurityTopic.NHI_CHANGES,
            event_type=f"nhi.{change_type}",
            agent_id=nhi_id,
            severity="medium",
            payload={"nhi_id": nhi_id, "change_type": change_type, **kwargs},
        )
        return await self.publish(SecurityTopic.NHI_CHANGES, event)

    async def publish_situation(
        self,
        situation_id: str,
        status: str,
        severity: str,
        **kwargs: Any,
    ) -> bool:
        """Publish a SOC situation event."""
        event = SecurityEvent(
            topic=SecurityTopic.SOC_SITUATIONS,
            event_type=f"soc.situation.{status}",
            agent_id=situation_id,
            severity=severity,
            payload={"situation_id": situation_id, "status": status, **kwargs},
        )
        return await self.publish(SecurityTopic.SOC_SITUATIONS, event)

    async def publish_webhook_event(
        self,
        event_id: str = "",
        vendor: str = "",
        severity: str = "medium",
        **kwargs: Any,
    ) -> bool:
        """Publish a normalized vendor webhook event."""
        event = SecurityEvent(
            event_id=event_id or str(uuid.uuid4()),
            topic=SecurityTopic.SECURITY_WEBHOOKS,
            event_type=f"webhook.{vendor}",
            agent_id=f"webhook-{vendor}",
            severity=severity,
            payload={"vendor": vendor, **kwargs},
        )
        return await self.publish(SecurityTopic.SECURITY_WEBHOOKS, event)

    # ── Flush & stats ────────────────────────────────────────────────────

    async def flush(self) -> int:
        """Flush all buffered events to Kafka.

        Returns the number of events successfully flushed.
        """
        if not self._started or self._producer is None:
            return 0

        flushed = 0
        remaining: list[SecurityEvent] = []
        for evt in self._buffer:
            ok = await self._send(evt.topic, evt)
            if ok:
                flushed += 1
            else:
                remaining.append(evt)
        self._buffer = remaining
        if flushed:
            logger.info("security_producer_flushed", count=flushed)
        return flushed

    def get_stats(self) -> dict[str, Any]:
        """Return producer metrics."""
        return {
            "started": self._started,
            "bootstrap_servers": self._bootstrap_servers,
            "publish_count": self._publish_count,
            "error_count": self._error_count,
            "buffer_size": len(self._buffer),
            "max_buffer": self._max_buffer,
        }
