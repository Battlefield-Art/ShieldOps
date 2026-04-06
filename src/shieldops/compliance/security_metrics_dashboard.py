"""Security Metrics Dashboard — track and visualize security metrics."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

SecurityMetricsDashboard = engine(
    "SecurityMetricsDashboard",
    description="Track security metrics across categories, timeframes, identify metric gaps.",
    enums={
        "metric_category": EnumDef(
            "MetricCategory",
            {
                "VULNERABILITY": "vulnerability",
                "INCIDENT": "incident",
                "COMPLIANCE": "compliance",
                "ACCESS": "access",
                "THREAT": "threat",
            },
        ),
        "metric_timeframe": EnumDef(
            "MetricTimeframe",
            {
                "REALTIME": "realtime",
                "DAILY": "daily",
                "WEEKLY": "weekly",
                "MONTHLY": "monthly",
                "QUARTERLY": "quarterly",
            },
        ),
        "metric_status": EnumDef(
            "MetricStatus",
            {
                "ON_TARGET": "on_target",
                "AT_RISK": "at_risk",
                "OFF_TARGET": "off_target",
                "IMPROVING": "improving",
                "DEGRADING": "degrading",
            },
        ),
    },
    score_field="metric_score",
    key_field="metric_name",
)

# Backward-compatible re-exports
MetricCategory = SecurityMetricsDashboard.MetricCategory
MetricTimeframe = SecurityMetricsDashboard.MetricTimeframe
MetricStatus = SecurityMetricsDashboard.MetricStatus
MetricRecord = SecurityMetricsDashboard.Record
MetricAnalysis = SecurityMetricsDashboard.Analysis
SecurityMetricsReport = SecurityMetricsDashboard.Report
