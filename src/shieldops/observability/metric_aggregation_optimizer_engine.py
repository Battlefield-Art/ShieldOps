"""MetricAggregationOptimizerEngine — Optimize metric aggregation strategies."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

MetricAggregationOptimizerEngine = engine(
    "MetricAggregationOptimizerEngine",
    description="Optimize metric aggregation strategies (temporality, alignment, rollup).",
    enums={
        "temporality_type": EnumDef(
            "TemporalityType",
            {
                "CUMULATIVE": "cumulative",
                "DELTA": "delta",
            },
        ),
        "aggregation_method": EnumDef(
            "AggregationMethod",
            {
                "SUM": "sum",
                "AVERAGE": "average",
                "MIN": "min",
                "MAX": "max",
                "PERCENTILE": "percentile",
            },
        ),
        "optimization_outcome": EnumDef(
            "OptimizationOutcome",
            {
                "REDUCED_CARDINALITY": "reduced_cardinality",
                "IMPROVED_ACCURACY": "improved_accuracy",
                "LOWER_COST": "lower_cost",
            },
        ),
    },
    record_fields=[
        FieldDef("cardinality", int, 0),
        FieldDef("rollup_interval_sec", int, 60),
    ],
)

# Backward-compatible re-exports
TemporalityType = MetricAggregationOptimizerEngine.TemporalityType
AggregationMethod = MetricAggregationOptimizerEngine.AggregationMethod
OptimizationOutcome = MetricAggregationOptimizerEngine.OptimizationOutcome
MetricAggregationOptimizerRecord = MetricAggregationOptimizerEngine.Record
MetricAggregationOptimizerAnalysis = MetricAggregationOptimizerEngine.Analysis
MetricAggregationOptimizerReport = MetricAggregationOptimizerEngine.Report
