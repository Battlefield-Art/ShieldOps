"""Kafka consumer for AI Security events — routes events to appropriate handlers."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any

import structlog

from shieldops.events.topics import SecurityEvent, SecurityTopic

logger = structlog.get_logger()

# Type alias for event handlers
EventHandler = Callable[[SecurityEvent], Awaitable[None]]


class SecurityEventConsumer:
    """Consumes AI Security events from Kafka and routes to registered handlers.

    Subscribe handlers for specific topics, then call :meth:`start` to begin
    consuming.  Each incoming message is deserialized into a
    :class:`SecurityEvent` and dispatched to all handlers registered for
    that topic.  Handler errors are logged but do not halt the consumer.
    """

    def __init__(
        self,
        bootstrap_servers: str = "localhost:9092",
        group_id: str = "shieldops-security",
    ) -> None:
        self._bootstrap_servers = bootstrap_servers
        self._group_id = group_id
        self._handlers: dict[SecurityTopic, list[EventHandler]] = {}
        self._consumer: Any | None = None  # AIOKafkaConsumer or None
        self._running: bool = False
        self._processed_count: int = 0
        self._error_count: int = 0

    # ── Handler registration ─────────────────────────────────────────────

    def register_handler(self, topic: SecurityTopic, handler: EventHandler) -> None:
        """Register a handler function for a specific security topic.

        Multiple handlers can be registered per topic; all will be invoked.
        """
        if topic not in self._handlers:
            self._handlers[topic] = []
        self._handlers[topic].append(handler)
        logger.info(
            "security_handler_registered",
            topic=topic.value,
            handler=handler.__name__,
        )

    # ── Lifecycle ────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Initialize the Kafka consumer and subscribe to registered topics."""
        topics = [t.value for t in self._handlers]
        if not topics:
            logger.warning("security_consumer_no_topics", msg="No handlers registered")
            return

        try:
            from aiokafka import AIOKafkaConsumer  # type: ignore[import-untyped]

            self._consumer = AIOKafkaConsumer(
                *topics,
                bootstrap_servers=self._bootstrap_servers,
                group_id=self._group_id,
                value_deserializer=lambda raw: json.loads(raw),
                auto_offset_reset="latest",
                enable_auto_commit=True,
            )
            await self._consumer.start()
            self._running = True
            logger.info(
                "security_consumer_started",
                bootstrap_servers=self._bootstrap_servers,
                group_id=self._group_id,
                topics=topics,
            )
        except ImportError:
            logger.warning(
                "security_consumer_no_aiokafka",
                msg="aiokafka not installed — consumer cannot start",
            )
        except Exception as exc:
            logger.error("security_consumer_start_failed", error=str(exc))

    async def stop(self) -> None:
        """Gracefully stop the consumer and commit offsets."""
        self._running = False
        if self._consumer is not None:
            await self._consumer.stop()
            self._consumer = None
            logger.info(
                "security_consumer_stopped",
                processed=self._processed_count,
                errors=self._error_count,
            )

    # ── Consume loop ─────────────────────────────────────────────────────

    async def consume(self) -> None:
        """Enter the consume loop — blocks until :meth:`stop` is called.

        Each message is deserialized to a ``SecurityEvent`` and routed to
        handlers registered for that topic.
        """
        if self._consumer is None:
            logger.warning("security_consumer_not_started")
            return

        async for message in self._consumer:
            if not self._running:
                break

            try:
                # Deserialize raw dict into SecurityEvent
                event = SecurityEvent.model_validate(message.value)
                await self._process_event(
                    SecurityTopic(message.topic),
                    event,
                )
                self._processed_count += 1
            except Exception as exc:
                self._error_count += 1
                logger.exception(
                    "security_consumer_process_error",
                    topic=message.topic,
                    offset=message.offset,
                    error=str(exc),
                )

    async def _process_event(self, topic: SecurityTopic, event: SecurityEvent) -> None:
        """Route an event to all handlers registered for the given topic."""
        handlers = self._handlers.get(topic, [])
        if not handlers:
            logger.debug(
                "security_event_no_handlers",
                topic=topic.value,
                event_id=event.event_id,
            )
            return

        for handler in handlers:
            try:
                await handler(event)
                logger.debug(
                    "security_event_handled",
                    topic=topic.value,
                    event_id=event.event_id,
                    handler=handler.__name__,
                )
            except Exception as exc:
                self._error_count += 1
                logger.error(
                    "security_handler_error",
                    topic=topic.value,
                    event_id=event.event_id,
                    handler=handler.__name__,
                    error=str(exc),
                )

    # ── Stats ────────────────────────────────────────────────────────────

    def get_stats(self) -> dict[str, Any]:
        """Return consumer metrics."""
        return {
            "running": self._running,
            "bootstrap_servers": self._bootstrap_servers,
            "group_id": self._group_id,
            "registered_topics": [t.value for t in self._handlers],
            "handler_count": sum(len(h) for h in self._handlers.values()),
            "processed_count": self._processed_count,
            "error_count": self._error_count,
        }


# ── Pre-built handlers ──────────────────────────────────────────────────────


async def handle_firewall_event(event: SecurityEvent) -> None:
    """Process firewall interception event — update metrics, check thresholds."""
    payload = event.payload
    risk_score = payload.get("risk_score", 0.0)
    action = payload.get("action", "unknown")

    logger.info(
        "firewall_event_processed",
        event_id=event.event_id,
        agent_id=event.agent_id,
        action=action,
        risk_score=risk_score,
    )

    # Escalate high-risk events
    if risk_score > 0.85:
        logger.warning(
            "firewall_high_risk_escalation",
            event_id=event.event_id,
            agent_id=event.agent_id,
            risk_score=risk_score,
        )


async def handle_anomaly_event(event: SecurityEvent) -> None:
    """Process anomaly detection — trigger escalation if severity is critical."""
    anomaly_type = event.payload.get("anomaly_type", "unknown")

    logger.info(
        "anomaly_event_processed",
        event_id=event.event_id,
        anomaly_type=anomaly_type,
        severity=event.severity,
    )

    if event.severity in ("critical", "high"):
        logger.warning(
            "anomaly_escalation_triggered",
            event_id=event.event_id,
            anomaly_type=anomaly_type,
            severity=event.severity,
        )


async def handle_situation_event(event: SecurityEvent) -> None:
    """Process new SOC situation — notify channels, update dashboard."""
    situation_id = event.payload.get("situation_id", "")
    status = event.payload.get("status", "new")

    logger.info(
        "situation_event_processed",
        event_id=event.event_id,
        situation_id=situation_id,
        status=status,
        severity=event.severity,
    )

    if event.severity == "critical":
        logger.warning(
            "situation_critical_notification",
            situation_id=situation_id,
            msg="Critical SOC situation — notify on-call and stakeholders",
        )


async def handle_webhook_event(event: SecurityEvent) -> None:
    """Process incoming vendor webhook — normalize and feed to SOC Brain."""
    vendor = event.payload.get("vendor", "unknown")
    title = event.payload.get("title", "")

    logger.info(
        "webhook_event_processed",
        event_id=event.event_id,
        vendor=vendor,
        severity=event.severity,
        title=title,
    )

    # High-severity webhook events trigger immediate SOC attention
    if event.severity in ("critical", "high"):
        logger.warning(
            "webhook_high_severity_alert",
            event_id=event.event_id,
            vendor=vendor,
            severity=event.severity,
            title=title,
        )
