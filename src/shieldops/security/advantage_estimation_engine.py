"""Advantage Estimation Engine — computes advantage estimates from group-level statistics, ana..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AdvantageEstimationEngine = engine(
    "AdvantageEstimationEngine",
    description="Computes advantage estimates from group-level statistics.",
    enums={
        "estimation_method": EnumDef(
            "EstimationMethod",
            {
                "GROUP_RELATIVE": "group_relative",
                "GLOBAL_RELATIVE": "global_relative",
                "GAE": "gae",
                "TEMPORAL_DIFFERENCE": "temporal_difference",
            },
        ),
        "advantage_sign": EnumDef(
            "AdvantageSign",
            {
                "POSITIVE": "positive",
                "NEAR_ZERO": "near_zero",
                "NEGATIVE": "negative",
                "HIGHLY_POSITIVE": "highly_positive",
            },
        ),
        "baseline_type": EnumDef(
            "BaselineType",
            {
                "GROUP_MEAN": "group_mean",
                "RUNNING_AVERAGE": "running_average",
                "EXPONENTIAL_MOVING": "exponential_moving",
                "MEDIAN": "median",
            },
        ),
    },
    record_fields=[
        FieldDef("group_id", str, ""),
        FieldDef("reward", float, 0.0),
        FieldDef("baseline_value", float, 0.0),
        FieldDef("advantage_value", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="task_id",
)

# Backward-compatible re-exports
EstimationMethod = AdvantageEstimationEngine.EstimationMethod
AdvantageSign = AdvantageEstimationEngine.AdvantageSign
BaselineType = AdvantageEstimationEngine.BaselineType
AdvantageRecord = AdvantageEstimationEngine.Record
AdvantageAnalysis = AdvantageEstimationEngine.Analysis
AdvantageReport = AdvantageEstimationEngine.Report
