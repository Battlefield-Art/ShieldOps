"""Experiment Lifecycle Engine — track autonomous experiment proposals, execution, results, an..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ExperimentLifecycleEngine = engine(
    "ExperimentLifecycleEngine",
    description="Track autonomous experiment lifecycle — propose, execute, evaluate, accept/...",
    enums={
        "experiment_phase": EnumDef(
            "ExperimentPhase",
            {
                "PROPOSED": "proposed",
                "RUNNING": "running",
                "COMPLETED": "completed",
                "ACCEPTED": "accepted",
                "REJECTED": "rejected",
            },
        ),
        "experiment_domain": EnumDef(
            "ExperimentDomain",
            {
                "ALERT_TUNING": "alert_tuning",
                "ROUTING": "routing",
                "RUNBOOK": "runbook",
                "POLICY": "policy",
                "THRESHOLD": "threshold",
            },
        ),
        "budget_status": EnumDef(
            "BudgetStatus",
            {
                "WITHIN_BUDGET": "within_budget",
                "APPROACHING_LIMIT": "approaching_limit",
                "EXCEEDED": "exceeded",
                "NOT_SET": "not_set",
            },
        ),
    },
    record_fields=[
        FieldDef("metric_before", float, 0.0),
        FieldDef("metric_after", float, 0.0),
        FieldDef("improvement_pct", float, 0.0),
        FieldDef("duration_seconds", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="experiment_id",
)

# Backward-compatible re-exports
ExperimentPhase = ExperimentLifecycleEngine.ExperimentPhase
ExperimentDomain = ExperimentLifecycleEngine.ExperimentDomain
BudgetStatus = ExperimentLifecycleEngine.BudgetStatus
ExperimentLifecycleRecord = ExperimentLifecycleEngine.Record
ExperimentLifecycleAnalysis = ExperimentLifecycleEngine.Analysis
ExperimentLifecycleReport = ExperimentLifecycleEngine.Report
