"""Metric Convergence Tracker Track metric convergence patterns, compute convergence rates, an..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

MetricConvergenceTracker = engine(
    "MetricConvergenceTracker",
    description="Track metric convergence, compute rates, and predict final metric values.",
    enums={
        "pattern": EnumDef(
            "ConvergencePattern",
            {
                "MONOTONIC": "monotonic",
                "OSCILLATING": "oscillating",
                "STEP_WISE": "step_wise",
                "ASYMPTOTIC": "asymptotic",
            },
        ),
        "stability": EnumDef(
            "StabilityLevel",
            {
                "STABLE": "stable",
                "UNSTABLE": "unstable",
                "TRANSITIONING": "transitioning",
                "CHAOTIC": "chaotic",
            },
        ),
        "metric_type": EnumDef(
            "MetricType",
            {
                "LOSS": "loss",
                "ACCURACY": "accuracy",
                "LATENCY": "latency",
                "THROUGHPUT": "throughput",
            },
        ),
    },
    record_fields=[
        FieldDef("metric_value", float, 0.0),
        FieldDef("iteration", int, 0),
    ],
    key_field="experiment_id",
)

# Backward-compatible re-exports
ConvergencePattern = MetricConvergenceTracker.ConvergencePattern
StabilityLevel = MetricConvergenceTracker.StabilityLevel
MetricType = MetricConvergenceTracker.MetricType
ConvergenceRecord = MetricConvergenceTracker.Record
ConvergenceAnalysis = MetricConvergenceTracker.Analysis
ConvergenceReport = MetricConvergenceTracker.Report
