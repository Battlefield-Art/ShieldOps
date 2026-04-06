"""AutomationEffectivenessTracker — track security automation effectiveness and roi metrics."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AutomationEffectivenessTracker = engine(
    "AutomationEffectivenessTracker",
    description="Track security automation effectiveness and ROI metrics.",
    enums={
        "record_type": EnumDef(
            "AutomationType",
            {
                "METRIC": "metric",
                "TREND": "trend",
                "FORECAST": "forecast",
                "ANOMALY": "anomaly",
                "BENCHMARK": "benchmark",
            },
        ),
        "source": EnumDef(
            "AutomationSource",
            {
                "TELEMETRY": "telemetry",
                "LOG_ANALYSIS": "log_analysis",
                "APM": "apm",
                "CUSTOM": "custom",
                "SYNTHETIC": "synthetic",
            },
        ),
        "level": EnumDef(
            "AutomationLevel",
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
AutomationType = AutomationEffectivenessTracker.AutomationType
AutomationSource = AutomationEffectivenessTracker.AutomationSource
AutomationLevel = AutomationEffectivenessTracker.AutomationLevel
AutomationRecord = AutomationEffectivenessTracker.Record
AutomationAnalysis = AutomationEffectivenessTracker.Analysis
AutomationReport = AutomationEffectivenessTracker.Report
