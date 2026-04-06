"""CloudSecurityPostureDashboard — generate cloud security posture dashboards and reports."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

CloudSecurityPostureDashboard = engine(
    "CloudSecurityPostureDashboard",
    description="Generate cloud security posture dashboards and reports.",
    enums={
        "record_type": EnumDef(
            "CloudSecurityType",
            {
                "METRIC": "metric",
                "TREND": "trend",
                "FORECAST": "forecast",
                "ANOMALY": "anomaly",
                "BENCHMARK": "benchmark",
            },
        ),
        "source": EnumDef(
            "CloudSecuritySource",
            {
                "TELEMETRY": "telemetry",
                "LOG_ANALYSIS": "log_analysis",
                "APM": "apm",
                "CUSTOM": "custom",
                "SYNTHETIC": "synthetic",
            },
        ),
        "level": EnumDef(
            "CloudSecurityLevel",
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
CloudSecurityType = CloudSecurityPostureDashboard.CloudSecurityType
CloudSecuritySource = CloudSecurityPostureDashboard.CloudSecuritySource
CloudSecurityLevel = CloudSecurityPostureDashboard.CloudSecurityLevel
CloudSecurityRecord = CloudSecurityPostureDashboard.Record
CloudSecurityAnalysis = CloudSecurityPostureDashboard.Analysis
CloudSecurityReport = CloudSecurityPostureDashboard.Report
