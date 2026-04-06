"""Error Budget Tracker Engine — track SLO error budget consumption."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ErrorBudgetTrackerEngine = engine(
    "ErrorBudgetTrackerEngine",
    description="Track SLO error budget consumption and burn rates.",
    enums={
        "budget_state": EnumDef(
            "BudgetState",
            {
                "HEALTHY": "healthy",
                "WARNING": "warning",
                "CRITICAL": "critical",
                "EXHAUSTED": "exhausted",
                "EXCEEDED": "exceeded",
            },
        ),
        "burn_rate_category": EnumDef(
            "BurnRateCategory",
            {
                "NORMAL": "normal",
                "ELEVATED": "elevated",
                "HIGH": "high",
                "EXTREME": "extreme",
                "RECOVERED": "recovered",
            },
        ),
        "budget_action": EnumDef(
            "BudgetAction",
            {
                "NONE": "none",
                "SLOW_DEPLOY": "slow_deploy",
                "FREEZE_DEPLOY": "freeze_deploy",
                "INCIDENT_RESPONSE": "incident_response",
                "POSTMORTEM": "postmortem",
            },
        ),
    },
    record_fields=[
        FieldDef("slo_name", str, ""),
        FieldDef("budget_total_minutes", float, 0.0),
        FieldDef("budget_consumed_minutes", float, 0.0),
        FieldDef("budget_remaining_pct", float, 100.0),
        FieldDef("burn_rate_multiplier", float, 1.0),
        FieldDef("window_days", int, 30),
        FieldDef("description", str, ""),
    ],
    key_field="service_id",
)

# Backward-compatible re-exports
BudgetState = ErrorBudgetTrackerEngine.BudgetState
BurnRateCategory = ErrorBudgetTrackerEngine.BurnRateCategory
BudgetAction = ErrorBudgetTrackerEngine.BudgetAction
ErrorBudgetTrackerRecord = ErrorBudgetTrackerEngine.Record
ErrorBudgetTrackerAnalysis = ErrorBudgetTrackerEngine.Analysis
ErrorBudgetTrackerReport = ErrorBudgetTrackerEngine.Report
