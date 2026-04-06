"""Latency Distribution Analyzer compute percentile shifts, detect tail latency spikes, rank e..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

LatencyDistributionAnalyzer = engine(
    "LatencyDistributionAnalyzer",
    description="Compute percentile shifts, detect tail latency spikes, rank endpoints by la...",
    enums={
        "percentile_bucket": EnumDef(
            "PercentileBucket",
            {
                "P50": "p50",
                "P95": "p95",
                "P99": "p99",
                "P999": "p999",
            },
        ),
        "latency_trend": EnumDef(
            "LatencyTrend",
            {
                "IMPROVING": "improving",
                "STABLE": "stable",
                "DEGRADING": "degrading",
                "VOLATILE": "volatile",
            },
        ),
        "analysis_window": EnumDef(
            "AnalysisWindow",
            {
                "MINUTE": "minute",
                "HOUR": "hour",
                "DAY": "day",
                "WEEK": "week",
            },
        ),
    },
    record_fields=[
        FieldDef("value_ms", float, 0.0),
        FieldDef("baseline_ms", float, 0.0),
        FieldDef("threshold_ms", float, 500.0),
        FieldDef("description", str, ""),
    ],
    key_field="endpoint_id",
)

# Backward-compatible re-exports
PercentileBucket = LatencyDistributionAnalyzer.PercentileBucket
LatencyTrend = LatencyDistributionAnalyzer.LatencyTrend
AnalysisWindow = LatencyDistributionAnalyzer.AnalysisWindow
LatencyDistributionRecord = LatencyDistributionAnalyzer.Record
LatencyDistributionAnalysis = LatencyDistributionAnalyzer.Analysis
LatencyDistributionReport = LatencyDistributionAnalyzer.Report
