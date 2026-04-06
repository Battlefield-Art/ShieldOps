"""PipelinePerformanceAnalytics — pipeline perf."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

PipelinePerformanceAnalytics = engine(
    "PipelinePerformanceAnalytics",
    description="Analyze pipeline performance.",
    enums={
        "pipeline_metric": EnumDef(
            "PipelineMetric",
            {
                "CYCLE_TIME": "cycle_time",
                "THROUGHPUT": "throughput",
                "ERROR_RATE": "error_rate",
                "FINDING_VELOCITY": "finding_velocity",
            },
        ),
        "cycle_trend": EnumDef(
            "CycleTrend",
            {
                "IMPROVING": "improving",
                "STABLE": "stable",
                "DEGRADING": "degrading",
            },
        ),
        "efficiency_score": EnumDef(
            "EfficiencyScore",
            {
                "EXCELLENT": "excellent",
                "GOOD": "good",
                "FAIR": "fair",
                "POOR": "poor",
            },
        ),
    },
    record_fields=[
        FieldDef("cycle_time_ms", float, 0.0),
        FieldDef("findings_per_cycle", int, 0),
        FieldDef("entity", str, ""),
    ],
)

# Backward-compatible re-exports
PipelineMetric = PipelinePerformanceAnalytics.PipelineMetric
CycleTrend = PipelinePerformanceAnalytics.CycleTrend
EfficiencyScore = PipelinePerformanceAnalytics.EfficiencyScore
PipelinePerformanceRecord = PipelinePerformanceAnalytics.Record
PipelinePerformanceAnalysis = PipelinePerformanceAnalytics.Analysis
PipelinePerformanceReport = PipelinePerformanceAnalytics.Report
