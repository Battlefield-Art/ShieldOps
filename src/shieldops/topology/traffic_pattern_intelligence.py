"""Traffic Pattern Intelligence. Detect traffic anomalies, classify seasonality patterns, and..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

TrafficPatternIntelligence = engine(
    "TrafficPatternIntelligence",
    module="operations",  # uses record_item
    description="Detect traffic anomalies, classify seasonality, and predict traffic shifts.",
    enums={
        "pattern_type": EnumDef(
            "PatternType",
            {
                "SEASONAL": "seasonal",
                "EVENT_DRIVEN": "event_driven",
                "ORGANIC": "organic",
                "ANOMALOUS": "anomalous",
            },
        ),
        "traffic_trend": EnumDef(
            "TrafficTrend",
            {
                "GROWING": "growing",
                "STABLE": "stable",
                "DECLINING": "declining",
                "VOLATILE": "volatile",
            },
        ),
        "anomaly_severity": EnumDef(
            "AnomalySeverity",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            },
        ),
    },
    record_fields=[
        FieldDef("request_rate", float, 0.0),
        FieldDef("baseline_rate", float, 0.0),
        FieldDef("deviation_pct", float, 0.0),
    ],
    key_field="endpoint",
)

# Backward-compatible re-exports
PatternType = TrafficPatternIntelligence.PatternType
TrafficTrend = TrafficPatternIntelligence.TrafficTrend
AnomalySeverity = TrafficPatternIntelligence.AnomalySeverity
TrafficPatternRecord = TrafficPatternIntelligence.Record
TrafficPatternAnalysis = TrafficPatternIntelligence.Analysis
TrafficPatternReport = TrafficPatternIntelligence.Report
