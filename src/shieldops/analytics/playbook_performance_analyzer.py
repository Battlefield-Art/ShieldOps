"""PlaybookPerformanceAnalyzer — analyze playbook execution performance and success rates."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

PlaybookPerformanceAnalyzer = engine(
    "PlaybookPerformanceAnalyzer",
    description="Analyze playbook execution performance and success rates.",
    enums={
        "record_type": EnumDef(
            "PlaybookType",
            {
                "METRIC": "metric",
                "TREND": "trend",
                "FORECAST": "forecast",
                "ANOMALY": "anomaly",
                "BENCHMARK": "benchmark",
            },
        ),
        "source": EnumDef(
            "PlaybookSource",
            {
                "TELEMETRY": "telemetry",
                "LOG_ANALYSIS": "log_analysis",
                "APM": "apm",
                "CUSTOM": "custom",
                "SYNTHETIC": "synthetic",
            },
        ),
        "level": EnumDef(
            "PlaybookLevel",
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
PlaybookType = PlaybookPerformanceAnalyzer.PlaybookType
PlaybookSource = PlaybookPerformanceAnalyzer.PlaybookSource
PlaybookLevel = PlaybookPerformanceAnalyzer.PlaybookLevel
PlaybookRecord = PlaybookPerformanceAnalyzer.Record
PlaybookAnalysis = PlaybookPerformanceAnalyzer.Analysis
PlaybookReport = PlaybookPerformanceAnalyzer.Report
