"""AnalystProductivityEngine — Measure analyst productivity, time savings, and automation impact."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AnalystProductivityEngine = engine(
    "AnalystProductivityEngine",
    description="Measure analyst productivity, time savings, and automation impact.",
    enums={
        "task_type": EnumDef(
            "TaskType",
            {
                "TRIAGE": "triage",
                "INVESTIGATION": "investigation",
                "RESPONSE": "response",
                "DOCUMENTATION": "documentation",
                "REVIEW": "review",
            },
        ),
        "automation_level": EnumDef(
            "AutomationLevel",
            {
                "FULLY_AUTOMATED": "fully_automated",
                "AI_ASSISTED": "ai_assisted",
                "MANUAL": "manual",
            },
        ),
        "productivity_metric": EnumDef(
            "ProductivityMetric",
            {
                "TIME_SAVINGS": "time_savings",
                "CASE_THROUGHPUT": "case_throughput",
                "QUALITY_SCORE": "quality_score",
            },
        ),
    },
    record_fields=[
        FieldDef("time_spent_min", float, 0.0),
        FieldDef("manual_baseline_min", float, 0.0),
        FieldDef("analyst_id", str, ""),
    ],
)

# Backward-compatible re-exports
TaskType = AnalystProductivityEngine.TaskType
AutomationLevel = AnalystProductivityEngine.AutomationLevel
ProductivityMetric = AnalystProductivityEngine.ProductivityMetric
ProductivityRecord = AnalystProductivityEngine.Record
ProductivityAnalysis = AnalystProductivityEngine.Analysis
ProductivityReport = AnalystProductivityEngine.Report
