"""Temporal Anomaly Engine Detects time-context violations such as off-hours deployments, unex..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

TemporalAnomalyEngine = engine(
    "TemporalAnomalyEngine",
    description="Temporal Anomaly Engine Detects time-context violations such as off-hours d...",
    enums={
        "temporal_context": EnumDef(
            "TemporalContext",
            {
                "BUSINESS_HOURS": "business_hours",
                "OFF_HOURS": "off_hours",
                "WEEKEND": "weekend",
                "HOLIDAY": "holiday",
                "CHANGE_WINDOW": "change_window",
                "MAINTENANCE": "maintenance",
            },
        ),
        "violation_type": EnumDef(
            "TemporalViolation",
            {
                "OFF_HOURS_DEPLOY": "off_hours_deploy",
                "UNEXPECTED_ACCESS": "unexpected_access",
                "WINDOW_BREACH": "window_breach",
                "SCHEDULE_DRIFT": "schedule_drift",
                "UNUSUAL_FREQUENCY": "unusual_frequency",
            },
        ),
        "risk_level": EnumDef(
            "RiskLevel",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "INFORMATIONAL": "informational",
            },
        ),
    },
    record_fields=[
        FieldDef("timestamp_hour", int, 0),
        FieldDef("day_of_week", str, ""),
        FieldDef("expected_window", str, ""),
        FieldDef("operator", str, ""),
    ],
    key_field="event_type",
)

# Backward-compatible re-exports
TemporalContext = TemporalAnomalyEngine.TemporalContext
TemporalViolation = TemporalAnomalyEngine.TemporalViolation
RiskLevel = TemporalAnomalyEngine.RiskLevel
TemporalAnomalyRecord = TemporalAnomalyEngine.Record
TemporalAnomalyAnalysis = TemporalAnomalyEngine.Analysis
TemporalAnomalyReport = TemporalAnomalyEngine.Report
