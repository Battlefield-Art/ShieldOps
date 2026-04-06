"""Notification Delivery Optimizer optimize delivery timing, plan notification batching, evalu..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

NotificationDeliveryOptimizer = engine(
    "NotificationDeliveryOptimizer",
    module="operations",  # uses record_item
    description="Optimize delivery timing, plan notification batching, evaluate delivery rel...",
    enums={
        "delivery_priority": EnumDef(
            "DeliveryPriority",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            },
        ),
        "batch_strategy": EnumDef(
            "BatchStrategy",
            {
                "IMMEDIATE": "immediate",
                "DIGEST": "digest",
                "SCHEDULED": "scheduled",
                "ADAPTIVE": "adaptive",
            },
        ),
        "reliability_level": EnumDef(
            "ReliabilityLevel",
            {
                "GUARANTEED": "guaranteed",
                "HIGH": "high",
                "BEST_EFFORT": "best_effort",
                "DEGRADED": "degraded",
            },
        ),
    },
    record_fields=[
        FieldDef("delivery_time_ms", float, 0.0),
        FieldDef("batch_size", int, 1),
        FieldDef("success", bool, True),
        FieldDef("channel", str, ""),
    ],
    key_field="notification_id",
)

# Backward-compatible re-exports
DeliveryPriority = NotificationDeliveryOptimizer.DeliveryPriority
BatchStrategy = NotificationDeliveryOptimizer.BatchStrategy
ReliabilityLevel = NotificationDeliveryOptimizer.ReliabilityLevel
NotificationDeliveryRecord = NotificationDeliveryOptimizer.Record
NotificationDeliveryAnalysis = NotificationDeliveryOptimizer.Analysis
NotificationDeliveryReport = NotificationDeliveryOptimizer.Report
