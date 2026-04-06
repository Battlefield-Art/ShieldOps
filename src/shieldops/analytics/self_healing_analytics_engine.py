"""Self-Healing Analytics Engine — analyze self-healing automation effectiveness, identify hea..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

SelfHealingAnalyticsEngine = engine(
    "SelfHealingAnalyticsEngine",
    description="Analyze self-healing automation effectiveness, identify healing patterns, a...",
    enums={
        "healing_action": EnumDef(
            "HealingAction",
            {
                "RESTART": "restart",
                "SCALE": "scale",
                "FAILOVER": "failover",
                "ROLLBACK": "rollback",
            },
        ),
        "healing_outcome": EnumDef(
            "HealingOutcome",
            {
                "RESOLVED": "resolved",
                "PARTIAL": "partial",
                "FAILED": "failed",
                "ESCALATED": "escalated",
            },
        ),
        "healing_trigger": EnumDef(
            "HealingTrigger",
            {
                "ALERT": "alert",
                "THRESHOLD": "threshold",
                "PREDICTION": "prediction",
                "MANUAL": "manual",
            },
        ),
    },
    record_fields=[
        FieldDef("incident_id", str, ""),
        FieldDef("execution_time_seconds", float, 0.0),
        FieldDef("downtime_seconds", float, 0.0),
        FieldDef("success_rate", float, 0.0),
        FieldDef("retry_count", int, 0),
        FieldDef("description", str, ""),
    ],
    score_field="confidence_score",
    key_field="service_name",
)

# Backward-compatible re-exports
HealingAction = SelfHealingAnalyticsEngine.HealingAction
HealingOutcome = SelfHealingAnalyticsEngine.HealingOutcome
HealingTrigger = SelfHealingAnalyticsEngine.HealingTrigger
SelfHealingRecord = SelfHealingAnalyticsEngine.Record
SelfHealingAnalysis = SelfHealingAnalyticsEngine.Analysis
SelfHealingReport = SelfHealingAnalyticsEngine.Report
