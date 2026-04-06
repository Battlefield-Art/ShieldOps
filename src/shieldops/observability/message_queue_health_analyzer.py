"""Message Queue Health Analyzer — compute queue health scores, detect saturation, rank queues..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

MessageQueueHealthAnalyzer = engine(
    "MessageQueueHealthAnalyzer",
    description="Compute queue health scores, detect saturation, rank queues by processing r...",
    enums={
        "queue_type": EnumDef(
            "QueueType",
            {
                "KAFKA": "kafka",
                "RABBITMQ": "rabbitmq",
                "SQS": "sqs",
                "PUBSUB": "pubsub",
            },
        ),
        "health_status": EnumDef(
            "HealthStatus",
            {
                "HEALTHY": "healthy",
                "DEGRADED": "degraded",
                "CRITICAL": "critical",
                "UNKNOWN": "unknown",
            },
        ),
        "saturation_level": EnumDef(
            "SaturationLevel",
            {
                "SAFE": "safe",
                "WARNING": "warning",
                "DANGER": "danger",
                "CRITICAL": "critical",
            },
        ),
    },
    record_fields=[
        FieldDef("depth", int, 0),
        FieldDef("throughput", float, 0.0),
        FieldDef("error_rate", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="queue_name",
)

# Backward-compatible re-exports
QueueType = MessageQueueHealthAnalyzer.QueueType
HealthStatus = MessageQueueHealthAnalyzer.HealthStatus
SaturationLevel = MessageQueueHealthAnalyzer.SaturationLevel
QueueHealthRecord = MessageQueueHealthAnalyzer.Record
QueueHealthAnalysis = MessageQueueHealthAnalyzer.Analysis
QueueHealthReport = MessageQueueHealthAnalyzer.Report
