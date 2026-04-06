"""Metric Baseline Engine — establish dynamic baselines for metrics, detect deviations, manage..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

MetricBaselineEngine = engine(
    "MetricBaselineEngine",
    description="Establish dynamic baselines for metrics, detect deviations, manage seasonal...",
    enums={
        "baseline_method": EnumDef(
            "BaselineMethod",
            {
                "MOVING_AVG": "moving_avg",
                "EXPONENTIAL": "exponential",
                "SEASONAL": "seasonal",
                "PERCENTILE": "percentile",
                "FIXED": "fixed",
            },
        ),
        "deviation_level": EnumDef(
            "DeviationLevel",
            {
                "EXTREME": "extreme",
                "HIGH": "high",
                "MODERATE": "moderate",
                "LOW": "low",
                "WITHIN_NORMAL": "within_normal",
            },
        ),
        "metric_type": EnumDef(
            "MetricType",
            {
                "COUNTER": "counter",
                "GAUGE": "gauge",
                "HISTOGRAM": "histogram",
                "SUMMARY": "summary",
                "RATE": "rate",
            },
        ),
    },
    record_fields=[
        FieldDef("service_name", str, ""),
        FieldDef("baseline_value", float, 0.0),
        FieldDef("current_value", float, 0.0),
        FieldDef("sigma_distance", float, 0.0),
        FieldDef("std_deviation", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="metric_name",
)

# Backward-compatible re-exports
BaselineMethod = MetricBaselineEngine.BaselineMethod
DeviationLevel = MetricBaselineEngine.DeviationLevel
MetricType = MetricBaselineEngine.MetricType
MetricBaselineRecord = MetricBaselineEngine.Record
MetricBaselineAnalysis = MetricBaselineEngine.Analysis
MetricBaselineReport = MetricBaselineEngine.Report
