"""SecurityDataLakeOptimizer — optimize security data lake storage and query performance."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

SecurityDataLakeOptimizer = engine(
    "SecurityDataLakeOptimizer",
    description="Optimize security data lake storage and query performance.",
    enums={
        "record_type": EnumDef(
            "SecurityDataLakeType",
            {
                "METRIC": "metric",
                "TREND": "trend",
                "FORECAST": "forecast",
                "ANOMALY": "anomaly",
                "BENCHMARK": "benchmark",
            },
        ),
        "source": EnumDef(
            "SecurityDataLakeSource",
            {
                "TELEMETRY": "telemetry",
                "LOG_ANALYSIS": "log_analysis",
                "APM": "apm",
                "CUSTOM": "custom",
                "SYNTHETIC": "synthetic",
            },
        ),
        "level": EnumDef(
            "SecurityDataLakeLevel",
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
SecurityDataLakeType = SecurityDataLakeOptimizer.SecurityDataLakeType
SecurityDataLakeSource = SecurityDataLakeOptimizer.SecurityDataLakeSource
SecurityDataLakeLevel = SecurityDataLakeOptimizer.SecurityDataLakeLevel
SecurityDataLakeRecord = SecurityDataLakeOptimizer.Record
SecurityDataLakeAnalysis = SecurityDataLakeOptimizer.Analysis
SecurityDataLakeReport = SecurityDataLakeOptimizer.Report
