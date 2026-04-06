"""SRE Toil Intelligence Toil classification, automation ROI scoring, effort tracking, and eli..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

SreToilIntelligence = engine(
    "SreToilIntelligence",
    description="SRE Toil Intelligence Toil classification, automation ROI scoring, effort t...",
    enums={
        "toil_category": EnumDef(
            "ToilCategory",
            {
                "MANUAL_REMEDIATION": "manual_remediation",
                "ALERT_RESPONSE": "alert_response",
                "DEPLOYMENT": "deployment",
                "CONFIGURATION": "configuration",
                "ACCESS_MANAGEMENT": "access_management",
                "CAPACITY_PLANNING": "capacity_planning",
                "INCIDENT_MANAGEMENT": "incident_management",
                "MONITORING_TUNING": "monitoring_tuning",
                "OTHER": "other",
            },
        ),
        "automation_feasibility": EnumDef(
            "AutomationFeasibility",
            {
                "FULLY_AUTOMATABLE": "fully_automatable",
                "PARTIALLY_AUTOMATABLE": "partially_automatable",
                "REQUIRES_TOOLING": "requires_tooling",
                "NOT_AUTOMATABLE": "not_automatable",
                "ALREADY_AUTOMATED": "already_automated",
            },
        ),
        "effort_level": EnumDef(
            "EffortLevel",
            {
                "TRIVIAL": "trivial",
                "LOW": "low",
                "MEDIUM": "medium",
                "HIGH": "high",
                "VERY_HIGH": "very_high",
            },
        ),
    },
    record_fields=[
        FieldDef("time_spent_minutes", float, 0.0),
        FieldDef("frequency_per_week", float, 0.0),
        FieldDef("people_involved", int, 1),
        FieldDef("is_repetitive", bool, True),
        FieldDef("is_automatable", bool, False),
        FieldDef("automation_cost_hours", float, 0.0),
    ],
    key_field="task_name",
)

# Backward-compatible re-exports
ToilCategory = SreToilIntelligence.ToilCategory
AutomationFeasibility = SreToilIntelligence.AutomationFeasibility
EffortLevel = SreToilIntelligence.EffortLevel
ToilRecord = SreToilIntelligence.Record
ToilAnalysis = SreToilIntelligence.Analysis
ToilIntelligenceReport = SreToilIntelligence.Report
