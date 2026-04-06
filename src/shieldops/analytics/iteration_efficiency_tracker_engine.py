"""Iteration Efficiency Tracker Engine — compute marginal improvement, detect diminishing retu..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

IterationEfficiencyTrackerEngine = engine(
    "IterationEfficiencyTrackerEngine",
    description="Compute marginal improvement, detect diminishing returns, and recommend ear...",
    enums={
        "efficiency_trend": EnumDef(
            "EfficiencyTrend",
            {
                "ACCELERATING": "accelerating",
                "STEADY": "steady",
                "DIMINISHING": "diminishing",
                "NEGATIVE": "negative",
            },
        ),
        "stopping_criteria": EnumDef(
            "StoppingCriteria",
            {
                "CONVERGENCE": "convergence",
                "BUDGET_EXHAUSTED": "budget_exhausted",
                "PLATEAU_DETECTED": "plateau_detected",
                "REGRESSION_DETECTED": "regression_detected",
            },
        ),
        "iteration_type": EnumDef(
            "IterationType",
            {
                "FULL_EVALUATION": "full_evaluation",
                "MINI_BATCH": "mini_batch",
                "CHECKPOINT": "checkpoint",
                "WARMUP": "warmup",
            },
        ),
    },
    record_fields=[
        FieldDef("iteration_number", int, 0),
        FieldDef("metric_value", float, 0.0),
        FieldDef("cost_per_iteration", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="experiment_id",
)

# Backward-compatible re-exports
EfficiencyTrend = IterationEfficiencyTrackerEngine.EfficiencyTrend
StoppingCriteria = IterationEfficiencyTrackerEngine.StoppingCriteria
IterationType = IterationEfficiencyTrackerEngine.IterationType
IterationEfficiencyRecord = IterationEfficiencyTrackerEngine.Record
IterationEfficiencyAnalysis = IterationEfficiencyTrackerEngine.Analysis
IterationEfficiencyReport = IterationEfficiencyTrackerEngine.Report
