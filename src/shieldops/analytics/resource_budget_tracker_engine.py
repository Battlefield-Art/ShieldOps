"""Resource Budget Tracker Engine — track resource consumption of autonomous agents/experiment..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ResourceBudgetTrackerEngine = engine(
    "ResourceBudgetTrackerEngine",
    description="Track resource consumption and enforce budgets for autonomous agents, exper...",
    enums={
        "resource_type": EnumDef(
            "ResourceType",
            {
                "CPU_SECONDS": "cpu_seconds",
                "MEMORY_MB": "memory_mb",
                "API_CALLS": "api_calls",
                "WALL_CLOCK_SECONDS": "wall_clock_seconds",
            },
        ),
        "budget_compliance": EnumDef(
            "BudgetCompliance",
            {
                "COMPLIANT": "compliant",
                "WARNING": "warning",
                "EXCEEDED": "exceeded",
                "UNKNOWN": "unknown",
            },
        ),
        "consumer_type": EnumDef(
            "ConsumerType",
            {
                "AGENT": "agent",
                "EXPERIMENT": "experiment",
                "PIPELINE": "pipeline",
                "SCHEDULED_JOB": "scheduled_job",
            },
        ),
    },
    record_fields=[
        FieldDef("allocated", float, 0.0),
        FieldDef("consumed", float, 0.0),
        FieldDef("utilization_pct", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="consumer_id",
)

# Backward-compatible re-exports
ResourceType = ResourceBudgetTrackerEngine.ResourceType
BudgetCompliance = ResourceBudgetTrackerEngine.BudgetCompliance
ConsumerType = ResourceBudgetTrackerEngine.ConsumerType
ResourceBudgetRecord = ResourceBudgetTrackerEngine.Record
ResourceBudgetAnalysis = ResourceBudgetTrackerEngine.Analysis
ResourceBudgetReport = ResourceBudgetTrackerEngine.Report
