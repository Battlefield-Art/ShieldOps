"""RemediationSuccessPredictor — predict remediation success probability before execution."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

RemediationSuccessPredictor = engine(
    "RemediationSuccessPredictor",
    description="Predict remediation success probability before execution.",
    enums={
        "record_type": EnumDef(
            "RemediationType",
            {
                "METRIC": "metric",
                "TREND": "trend",
                "FORECAST": "forecast",
                "ANOMALY": "anomaly",
                "BENCHMARK": "benchmark",
            },
        ),
        "source": EnumDef(
            "RemediationSource",
            {
                "TELEMETRY": "telemetry",
                "LOG_ANALYSIS": "log_analysis",
                "APM": "apm",
                "CUSTOM": "custom",
                "SYNTHETIC": "synthetic",
            },
        ),
        "level": EnumDef(
            "RemediationLevel",
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
RemediationType = RemediationSuccessPredictor.RemediationType
RemediationSource = RemediationSuccessPredictor.RemediationSource
RemediationLevel = RemediationSuccessPredictor.RemediationLevel
RemediationRecord = RemediationSuccessPredictor.Record
RemediationAnalysis = RemediationSuccessPredictor.Analysis
RemediationReport = RemediationSuccessPredictor.Report
