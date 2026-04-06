"""ThreatTrendForecaster — forecast threat trends based on historical data and intelligence."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

ThreatTrendForecaster = engine(
    "ThreatTrendForecaster",
    description="Forecast threat trends based on historical data and intelligence.",
    enums={
        "record_type": EnumDef(
            "ThreatTrendType",
            {
                "METRIC": "metric",
                "TREND": "trend",
                "FORECAST": "forecast",
                "ANOMALY": "anomaly",
                "BENCHMARK": "benchmark",
            },
        ),
        "source": EnumDef(
            "ThreatTrendSource",
            {
                "TELEMETRY": "telemetry",
                "LOG_ANALYSIS": "log_analysis",
                "APM": "apm",
                "CUSTOM": "custom",
                "SYNTHETIC": "synthetic",
            },
        ),
        "level": EnumDef(
            "ThreatTrendLevel",
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
ThreatTrendType = ThreatTrendForecaster.ThreatTrendType
ThreatTrendSource = ThreatTrendForecaster.ThreatTrendSource
ThreatTrendLevel = ThreatTrendForecaster.ThreatTrendLevel
ThreatTrendRecord = ThreatTrendForecaster.Record
ThreatTrendAnalysis = ThreatTrendForecaster.Analysis
ThreatTrendReport = ThreatTrendForecaster.Report
