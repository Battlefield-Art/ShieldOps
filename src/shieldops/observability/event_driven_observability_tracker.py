"""Event Driven Observability Tracker event-driven observability tracking and event bus monito..."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

EventDrivenObservabilityTracker = engine(
    "EventDrivenObservabilityTracker",
    description="Event Driven Observability Tracker event-driven observability tracking and...",
    enums={
        "event_bus_type": EnumDef(
            "EventBusType",
            {
                "KAFKA": "kafka",
                "RABBITMQ": "rabbitmq",
                "SQS": "sqs",
                "PUBSUB": "pubsub",
                "NATS": "nats",
            },
        ),
        "event_source": EnumDef(
            "EventSource",
            {
                "PRODUCER": "producer",
                "CONSUMER": "consumer",
                "BROKER": "broker",
                "CONNECTOR": "connector",
                "STREAM": "stream",
            },
        ),
        "event_health": EnumDef(
            "EventHealth",
            {
                "HEALTHY": "healthy",
                "LAGGING": "lagging",
                "BACKPRESSURE": "backpressure",
                "STALLED": "stalled",
                "DEAD_LETTER": "dead_letter",
            },
        ),
    },
)

# Backward-compatible re-exports
EventBusType = EventDrivenObservabilityTracker.EventBusType
EventSource = EventDrivenObservabilityTracker.EventSource
EventHealth = EventDrivenObservabilityTracker.EventHealth
EventBusRecord = EventDrivenObservabilityTracker.Record
EventBusAnalysis = EventDrivenObservabilityTracker.Analysis
EventDrivenObservabilityReport = EventDrivenObservabilityTracker.Report
