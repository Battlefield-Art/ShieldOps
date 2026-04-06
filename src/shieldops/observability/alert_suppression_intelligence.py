"""Alert Suppression Intelligence learn suppression windows, evaluate suppression safety, auto..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AlertSuppressionIntelligence = engine(
    "AlertSuppressionIntelligence",
    description="Learn suppression windows, evaluate suppression safety, auto tune suppressi...",
    enums={
        "suppression_reason": EnumDef(
            "SuppressionReason",
            {
                "MAINTENANCE": "maintenance",
                "DEPLOYMENT": "deployment",
                "KNOWN_ISSUE": "known_issue",
                "RECURRING": "recurring",
            },
        ),
        "safety_level": EnumDef(
            "SafetyLevel",
            {
                "SAFE": "safe",
                "CAUTION": "caution",
                "RISKY": "risky",
                "UNSAFE": "unsafe",
            },
        ),
        "window_type": EnumDef(
            "WindowType",
            {
                "SCHEDULED": "scheduled",
                "LEARNED": "learned",
                "MANUAL": "manual",
                "EMERGENCY": "emergency",
            },
        ),
    },
    record_fields=[
        FieldDef("duration_min", float, 0.0),
        FieldDef("alerts_suppressed", int, 0),
        FieldDef("missed_incidents", int, 0),
        FieldDef("source", str, ""),
    ],
    key_field="alert_name",
)

# Backward-compatible re-exports
SuppressionReason = AlertSuppressionIntelligence.SuppressionReason
SafetyLevel = AlertSuppressionIntelligence.SafetyLevel
WindowType = AlertSuppressionIntelligence.WindowType
AlertSuppressionRecord = AlertSuppressionIntelligence.Record
AlertSuppressionAnalysis = AlertSuppressionIntelligence.Analysis
AlertSuppressionReport = AlertSuppressionIntelligence.Report
