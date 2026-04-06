"""MeanTimeToContainOptimizer — optimize mean time to contain (mttc) for security incidents."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

MeanTimeToContainOptimizer = engine(
    "MeanTimeToContainOptimizer",
    description="Optimize mean time to contain (MTTC) for security incidents.",
    enums={
        "record_type": EnumDef(
            "MeanTimeToType",
            {
                "METRIC": "metric",
                "TREND": "trend",
                "FORECAST": "forecast",
                "ANOMALY": "anomaly",
                "BENCHMARK": "benchmark",
            },
        ),
        "source": EnumDef(
            "MeanTimeToSource",
            {
                "TELEMETRY": "telemetry",
                "LOG_ANALYSIS": "log_analysis",
                "APM": "apm",
                "CUSTOM": "custom",
                "SYNTHETIC": "synthetic",
            },
        ),
        "level": EnumDef(
            "MeanTimeToLevel",
            {
                "CRITICAL": "critical",
                "WARNING": "warning",
                "NORMAL": "normal",
                "OPTIMAL": "optimal",
                "UNKNOWN": "unknown",
            },
        ),
    },
)

# Backward-compatible re-exports
MeanTimeToType = MeanTimeToContainOptimizer.MeanTimeToType
MeanTimeToSource = MeanTimeToContainOptimizer.MeanTimeToSource
MeanTimeToLevel = MeanTimeToContainOptimizer.MeanTimeToLevel
MeanTimeToRecord = MeanTimeToContainOptimizer.Record
MeanTimeToAnalysis = MeanTimeToContainOptimizer.Analysis
MeanTimeToReport = MeanTimeToContainOptimizer.Report
