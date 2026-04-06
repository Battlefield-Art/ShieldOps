"""Alert Lifecycle Intelligence track alert aging, identify stale alert definitions, generate..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AlertLifecycleIntelligence = engine(
    "AlertLifecycleIntelligence",
    description="Track alert aging, identify stale definitions, generate retirement recommen...",
    enums={
        "lifecycle_stage": EnumDef(
            "LifecycleStage",
            {
                "ACTIVE": "active",
                "AGING": "aging",
                "STALE": "stale",
                "RETIRED": "retired",
            },
        ),
        "alert_value": EnumDef(
            "AlertValue",
            {
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "NONE": "none",
            },
        ),
        "retirement_reason": EnumDef(
            "RetirementReason",
            {
                "LOW_VALUE": "low_value",
                "REDUNDANT": "redundant",
                "OBSOLETE": "obsolete",
                "REPLACED": "replaced",
            },
        ),
    },
    record_fields=[
        FieldDef("age_days", int, 0),
        FieldDef("last_fired_days_ago", int, 0),
        FieldDef("fire_count", int, 0),
        FieldDef("action_rate", float, 0.0),
    ],
    key_field="alert_name",
)

# Backward-compatible re-exports
LifecycleStage = AlertLifecycleIntelligence.LifecycleStage
AlertValue = AlertLifecycleIntelligence.AlertValue
RetirementReason = AlertLifecycleIntelligence.RetirementReason
AlertLifecycleRecord = AlertLifecycleIntelligence.Record
AlertLifecycleAnalysis = AlertLifecycleIntelligence.Analysis
AlertLifecycleReport = AlertLifecycleIntelligence.Report
