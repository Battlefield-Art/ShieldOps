"""IdentityRiskDashboard — generate identity risk dashboards and posture reports."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

IdentityRiskDashboard = engine(
    "IdentityRiskDashboard",
    description="Generate identity risk dashboards and posture reports.",
    enums={
        "record_type": EnumDef(
            "IdentityRiskType",
            {
                "METRIC": "metric",
                "TREND": "trend",
                "FORECAST": "forecast",
                "ANOMALY": "anomaly",
                "BENCHMARK": "benchmark",
            },
        ),
        "source": EnumDef(
            "IdentityRiskSource",
            {
                "TELEMETRY": "telemetry",
                "LOG_ANALYSIS": "log_analysis",
                "APM": "apm",
                "CUSTOM": "custom",
                "SYNTHETIC": "synthetic",
            },
        ),
        "level": EnumDef(
            "IdentityRiskLevel",
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
IdentityRiskType = IdentityRiskDashboard.IdentityRiskType
IdentityRiskSource = IdentityRiskDashboard.IdentityRiskSource
IdentityRiskLevel = IdentityRiskDashboard.IdentityRiskLevel
IdentityRiskRecord = IdentityRiskDashboard.Record
IdentityRiskAnalysis = IdentityRiskDashboard.Analysis
IdentityRiskReport = IdentityRiskDashboard.Report
