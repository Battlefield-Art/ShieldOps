"""AutonomousExperimentEngine — Fully autonomous experiment lifecycle with budget enforcement."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AutonomousExperimentEngine = engine(
    "AutonomousExperimentEngine",
    description="Fully autonomous experiment lifecycle with budget enforcement.",
    enums={
        "experiment_phase": EnumDef(
            "ExperimentPhase",
            {
                "HYPOTHESIS": "hypothesis",
                "DESIGN": "design",
                "EXECUTE": "execute",
                "ANALYZE": "analyze",
                "DECIDE": "decide",
            },
        ),
        "budget_status": EnumDef(
            "BudgetStatus",
            {
                "UNDER_BUDGET": "under_budget",
                "AT_LIMIT": "at_limit",
                "OVER_BUDGET": "over_budget",
                "EXHAUSTED": "exhausted",
            },
        ),
        "decision_outcome": EnumDef(
            "DecisionOutcome",
            {
                "ACCEPT": "accept",
                "REJECT": "reject",
                "EXTEND": "extend",
                "PIVOT": "pivot",
            },
        ),
    },
    record_fields=[
        FieldDef("budget_spent", float, 0.0),
        FieldDef("budget_total", float, 0.0),
    ],
)

# Backward-compatible re-exports
ExperimentPhase = AutonomousExperimentEngine.ExperimentPhase
BudgetStatus = AutonomousExperimentEngine.BudgetStatus
DecisionOutcome = AutonomousExperimentEngine.DecisionOutcome
AutonomousExperimentRecord = AutonomousExperimentEngine.Record
AutonomousExperimentAnalysis = AutonomousExperimentEngine.Analysis
AutonomousExperimentReport = AutonomousExperimentEngine.Report
