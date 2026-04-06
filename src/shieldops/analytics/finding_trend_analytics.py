"""FindingTrendAnalytics — finding trend analysis."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

FindingTrendAnalytics = engine(
    "FindingTrendAnalytics",
    description="Analyze security finding trends.",
    enums={
        "finding_category": EnumDef(
            "FindingCategory",
            {
                "VULNERABILITY": "vulnerability",
                "MISCONFIGURATION": "misconfiguration",
                "COMPLIANCE": "compliance",
                "IDENTITY": "identity",
                "DATA_EXPOSURE": "data_exposure",
            },
        ),
        "trend_period": EnumDef(
            "TrendPeriod",
            {
                "DAILY": "daily",
                "WEEKLY": "weekly",
                "MONTHLY": "monthly",
                "QUARTERLY": "quarterly",
            },
        ),
        "volume_change": EnumDef(
            "VolumeChange",
            {
                "INCREASING": "increasing",
                "STABLE": "stable",
                "DECREASING": "decreasing",
                "SPIKE": "spike",
            },
        ),
    },
    record_fields=[
        FieldDef("finding_count", int, 0),
        FieldDef("previous_count", int, 0),
        FieldDef("entity", str, ""),
    ],
)

# Backward-compatible re-exports
FindingCategory = FindingTrendAnalytics.FindingCategory
TrendPeriod = FindingTrendAnalytics.TrendPeriod
VolumeChange = FindingTrendAnalytics.VolumeChange
FindingTrendRecord = FindingTrendAnalytics.Record
FindingTrendAnalysis = FindingTrendAnalytics.Analysis
FindingTrendReport = FindingTrendAnalytics.Report
