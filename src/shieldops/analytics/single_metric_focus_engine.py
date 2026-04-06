"""Single Metric Focus Engine — track metric trajectory, detect distractions, and evaluate pla..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

SingleMetricFocusEngine = engine(
    "SingleMetricFocusEngine",
    description="Track metric trajectory, detect distractions, and evaluate plateau breakouts.",
    enums={
        "focus_metric": EnumDef(
            "FocusMetric",
            {
                "ACCURACY": "accuracy",
                "LATENCY": "latency",
                "THROUGHPUT": "throughput",
                "COST_EFFICIENCY": "cost_efficiency",
            },
        ),
        "trend": EnumDef(
            "MetricTrend",
            {
                "IMPROVING": "improving",
                "PLATEAU": "plateau",
                "DECLINING": "declining",
                "OSCILLATING": "oscillating",
            },
        ),
        "distraction_type": EnumDef(
            "DistractionType",
            {
                "SECONDARY_METRIC": "secondary_metric",
                "VANITY_METRIC": "vanity_metric",
                "CORRELATED_METRIC": "correlated_metric",
                "IRRELEVANT_METRIC": "irrelevant_metric",
            },
        ),
    },
    record_fields=[
        FieldDef("metric_value", float, 0.0),
        FieldDef("baseline_value", float, 0.0),
        FieldDef("is_primary", bool, True),
        FieldDef("description", str, ""),
    ],
    key_field="experiment_id",
)

# Backward-compatible re-exports
FocusMetric = SingleMetricFocusEngine.FocusMetric
MetricTrend = SingleMetricFocusEngine.MetricTrend
DistractionType = SingleMetricFocusEngine.DistractionType
SingleMetricRecord = SingleMetricFocusEngine.Record
SingleMetricAnalysis = SingleMetricFocusEngine.Analysis
SingleMetricReport = SingleMetricFocusEngine.Report
