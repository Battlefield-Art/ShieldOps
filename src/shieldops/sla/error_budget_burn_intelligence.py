"""Error Budget Burn Intelligence compute burn rate trajectory, detect accelerated burn, rank..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ErrorBudgetBurnIntelligence = engine(
    "ErrorBudgetBurnIntelligence",
    description="Compute burn rate trajectory, detect accelerated burn, rank services by bud...",
    enums={
        "burn_rate": EnumDef(
            "BurnRate",
            {
                "FAST": "fast",
                "MODERATE": "moderate",
                "SLOW": "slow",
                "NONE": "none",
            },
        ),
        "budget_status": EnumDef(
            "BudgetStatus",
            {
                "HEALTHY": "healthy",
                "WARNING": "warning",
                "CRITICAL": "critical",
                "EXHAUSTED": "exhausted",
            },
        ),
        "burn_cause": EnumDef(
            "BurnCause",
            {
                "DEPLOYMENT": "deployment",
                "INCIDENT": "incident",
                "DEGRADATION": "degradation",
                "TRAFFIC": "traffic",
            },
        ),
    },
    record_fields=[
        FieldDef("budget_total", float, 100.0),
        FieldDef("budget_consumed", float, 0.0),
        FieldDef("burn_velocity", float, 0.0),
        FieldDef("window_hours", int, 24),
        FieldDef("description", str, ""),
    ],
    key_field="service_id",
)

# Backward-compatible re-exports
BurnRate = ErrorBudgetBurnIntelligence.BurnRate
BudgetStatus = ErrorBudgetBurnIntelligence.BudgetStatus
BurnCause = ErrorBudgetBurnIntelligence.BurnCause
ErrorBudgetBurnRecord = ErrorBudgetBurnIntelligence.Record
ErrorBudgetBurnAnalysis = ErrorBudgetBurnIntelligence.Analysis
ErrorBudgetBurnReport = ErrorBudgetBurnIntelligence.Report
