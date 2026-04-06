"""Consumer Lag Intelligence — forecast lag growth, detect consumer stalls, rank consumer grou..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ConsumerLagIntelligence = engine(
    "ConsumerLagIntelligence",
    description="Forecast lag growth, detect consumer stalls, rank consumer groups by lag se...",
    enums={
        "lag_trend": EnumDef(
            "LagTrend",
            {
                "GROWING": "growing",
                "STABLE": "stable",
                "SHRINKING": "shrinking",
                "VOLATILE": "volatile",
            },
        ),
        "stall_reason": EnumDef(
            "StallReason",
            {
                "PROCESSING_ERROR": "processing_error",
                "RESOURCE_LIMIT": "resource_limit",
                "BACKPRESSURE": "backpressure",
                "CONFIGURATION": "configuration",
            },
        ),
        "lag_severity": EnumDef(
            "LagSeverity",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            },
        ),
    },
    record_fields=[
        FieldDef("current_lag", int, 0),
        FieldDef("lag_rate", float, 0.0),
        FieldDef("topic", str, ""),
        FieldDef("description", str, ""),
    ],
    key_field="consumer_group",
)

# Backward-compatible re-exports
LagTrend = ConsumerLagIntelligence.LagTrend
StallReason = ConsumerLagIntelligence.StallReason
LagSeverity = ConsumerLagIntelligence.LagSeverity
ConsumerLagRecord = ConsumerLagIntelligence.Record
ConsumerLagAnalysis = ConsumerLagIntelligence.Analysis
ConsumerLagReport = ConsumerLagIntelligence.Report
