"""SecurityInvestmentROIAnalyzer — analyze roi of security investments and tool purchases."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

SecurityInvestmentROIAnalyzer = engine(
    "SecurityInvestmentROIAnalyzer",
    description="Analyze ROI of security investments and tool purchases.",
    enums={
        "record_type": EnumDef(
            "SecurityType",
            {
                "METRIC": "metric",
                "TREND": "trend",
                "FORECAST": "forecast",
                "ANOMALY": "anomaly",
                "BENCHMARK": "benchmark",
            },
        ),
        "source": EnumDef(
            "SecuritySource",
            {
                "TELEMETRY": "telemetry",
                "LOG_ANALYSIS": "log_analysis",
                "APM": "apm",
                "CUSTOM": "custom",
                "SYNTHETIC": "synthetic",
            },
        ),
        "level": EnumDef(
            "SecurityLevel",
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
SecurityType = SecurityInvestmentROIAnalyzer.SecurityType
SecuritySource = SecurityInvestmentROIAnalyzer.SecuritySource
SecurityLevel = SecurityInvestmentROIAnalyzer.SecurityLevel
SecurityRecord = SecurityInvestmentROIAnalyzer.Record
SecurityAnalysis = SecurityInvestmentROIAnalyzer.Analysis
SecurityReport = SecurityInvestmentROIAnalyzer.Report
