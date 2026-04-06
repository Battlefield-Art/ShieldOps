"""OperationalAnalyticsHub — operational analytics hub."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

OperationalAnalyticsHub = engine(
    "OperationalAnalyticsHub",
    module="operations",  # uses record_item
    description="Operational Analytics Hub.",
    enums={
        "analytics_category": EnumDef(
            "AnalyticsCategory",
            {
                "RELIABILITY": "reliability",
                "PERFORMANCE": "performance",
                "COST": "cost",
                "SECURITY": "security",
                "PRODUCTIVITY": "productivity",
            },
        ),
        "time_horizon": EnumDef(
            "TimeHorizon",
            {
                "REAL_TIME": "real_time",
                "HOURLY": "hourly",
                "DAILY": "daily",
                "WEEKLY": "weekly",
                "MONTHLY": "monthly",
            },
        ),
        "insight_type": EnumDef(
            "InsightType",
            {
                "TREND": "trend",
                "ANOMALY": "anomaly",
                "CORRELATION": "correlation",
                "PREDICTION": "prediction",
                "RECOMMENDATION": "recommendation",
            },
        ),
    },
)

# Backward-compatible re-exports
AnalyticsCategory = OperationalAnalyticsHub.AnalyticsCategory
TimeHorizon = OperationalAnalyticsHub.TimeHorizon
InsightType = OperationalAnalyticsHub.InsightType
OperationalAnalyticsHubRecord = OperationalAnalyticsHub.Record
OperationalAnalyticsHubAnalysis = OperationalAnalyticsHub.Analysis
OperationalAnalyticsHubReport = OperationalAnalyticsHub.Report
