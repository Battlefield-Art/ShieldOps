"""PerformancePredictionEngine — performance prediction engine."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

PerformancePredictionEngine = engine(
    "PerformancePredictionEngine",
    module="operations",  # uses record_item
    description="Performance Prediction Engine.",
    enums={
        "performance_metric": EnumDef(
            "PerformanceMetric",
            {
                "LATENCY_P50": "latency_p50",
                "LATENCY_P95": "latency_p95",
                "LATENCY_P99": "latency_p99",
                "THROUGHPUT": "throughput",
                "ERROR_RATE": "error_rate",
            },
        ),
        "prediction_window": EnumDef(
            "PredictionWindow",
            {
                "NEXT_HOUR": "next_hour",
                "NEXT_DAY": "next_day",
                "NEXT_WEEK": "next_week",
                "NEXT_MONTH": "next_month",
                "NEXT_QUARTER": "next_quarter",
            },
        ),
        "degradation_risk": EnumDef(
            "DegradationRisk",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MODERATE": "moderate",
                "LOW": "low",
                "NONE": "none",
            },
        ),
    },
)

# Backward-compatible re-exports
PerformanceMetric = PerformancePredictionEngine.PerformanceMetric
PredictionWindow = PerformancePredictionEngine.PredictionWindow
DegradationRisk = PerformancePredictionEngine.DegradationRisk
PerformancePredictionEngineRecord = PerformancePredictionEngine.Record
PerformancePredictionEngineAnalysis = PerformancePredictionEngine.Analysis
PerformancePredictionEngineReport = PerformancePredictionEngine.Report
