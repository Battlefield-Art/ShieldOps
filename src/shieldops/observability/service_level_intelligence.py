"""ServiceLevelIntelligence — SLO intelligence."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ServiceLevelIntelligence = engine(
    "ServiceLevelIntelligence",
    description="Service Level Intelligence. Provides intelligence on SLOs, error budgets, a...",
    enums={
        "maturity": EnumDef(
            "SloMaturity",
            {
                "ADHOC": "adhoc",
                "DEFINED": "defined",
                "MEASURED": "measured",
                "OPTIMIZED": "optimized",
            },
        ),
        "budget_status": EnumDef(
            "ErrorBudgetStatus",
            {
                "HEALTHY": "healthy",
                "CONSUMING": "consuming",
                "CRITICAL": "critical",
                "EXHAUSTED": "exhausted",
            },
        ),
        "trend": EnumDef(
            "ReliabilityTrend",
            {
                "IMPROVING": "improving",
                "STABLE": "stable",
                "DECLINING": "declining",
                "VOLATILE": "volatile",
            },
        ),
    },
    record_fields=[
        FieldDef("error_budget_remaining", float, 100.0),
        FieldDef("burn_rate", float, 0.0),
    ],
)

# Backward-compatible re-exports
SloMaturity = ServiceLevelIntelligence.SloMaturity
ErrorBudgetStatus = ServiceLevelIntelligence.ErrorBudgetStatus
ReliabilityTrend = ServiceLevelIntelligence.ReliabilityTrend
SloRecord = ServiceLevelIntelligence.Record
SloAnalysis = ServiceLevelIntelligence.Analysis
SloReport = ServiceLevelIntelligence.Report
