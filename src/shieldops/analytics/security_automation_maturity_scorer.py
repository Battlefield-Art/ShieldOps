"""SecurityAutomationMaturityScorer — score security automation maturity across dimensions."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

SecurityAutomationMaturityScorer = engine(
    "SecurityAutomationMaturityScorer",
    description="Score security automation maturity across dimensions.",
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
SecurityType = SecurityAutomationMaturityScorer.SecurityType
SecuritySource = SecurityAutomationMaturityScorer.SecuritySource
SecurityLevel = SecurityAutomationMaturityScorer.SecurityLevel
SecurityRecord = SecurityAutomationMaturityScorer.Record
SecurityAnalysis = SecurityAutomationMaturityScorer.Analysis
SecurityReport = SecurityAutomationMaturityScorer.Report
