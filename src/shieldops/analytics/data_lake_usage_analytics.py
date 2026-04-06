"""Data Lake Usage Analytics — query patterns and data growth."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

DataLakeUsageAnalytics = engine(
    "DataLakeUsageAnalytics",
    description="Analyze data lake query patterns and growth.",
    enums={
        "pattern": EnumDef(
            "QueryPattern",
            {
                "AD_HOC": "ad_hoc",
                "SCHEDULED": "scheduled",
                "STREAMING": "streaming",
                "BATCH": "batch",
                "INTERACTIVE": "interactive",
            },
        ),
        "volume": EnumDef(
            "DataVolume",
            {
                "SMALL": "small",
                "MEDIUM": "medium",
                "LARGE": "large",
                "VERY_LARGE": "very_large",
            },
        ),
        "frequency": EnumDef(
            "AccessFrequency",
            {
                "RARE": "rare",
                "OCCASIONAL": "occasional",
                "FREQUENT": "frequent",
                "CONTINUOUS": "continuous",
            },
        ),
    },
    key_field="dataset_name",
)

# Backward-compatible re-exports
QueryPattern = DataLakeUsageAnalytics.QueryPattern
DataVolume = DataLakeUsageAnalytics.DataVolume
AccessFrequency = DataLakeUsageAnalytics.AccessFrequency
UsageRecord = DataLakeUsageAnalytics.Record
UsageAnalysis = DataLakeUsageAnalytics.Analysis
UsageReport = DataLakeUsageAnalytics.Report
