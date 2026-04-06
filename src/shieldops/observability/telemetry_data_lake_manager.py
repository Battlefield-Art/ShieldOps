"""TelemetryDataLakeManager — telemetry data lake manager."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

TelemetryDataLakeManager = engine(
    "TelemetryDataLakeManager",
    module="operations",  # uses record_item
    description="Telemetry Data Lake Manager.",
    enums={
        "data_lake_partition": EnumDef(
            "DataLakePartition",
            {
                "HOURLY": "hourly",
                "DAILY": "daily",
                "WEEKLY": "weekly",
                "MONTHLY": "monthly",
                "YEARLY": "yearly",
            },
        ),
        "data_lake_format": EnumDef(
            "DataLakeFormat",
            {
                "PARQUET": "parquet",
                "ORC": "orc",
                "AVRO": "avro",
                "JSON": "json",
                "CSV": "csv",
            },
        ),
        "data_lake_tier": EnumDef(
            "DataLakeTier",
            {
                "HOT": "hot",
                "WARM": "warm",
                "COLD": "cold",
                "ARCHIVE": "archive",
                "FROZEN": "frozen",
            },
        ),
    },
)

# Backward-compatible re-exports
DataLakePartition = TelemetryDataLakeManager.DataLakePartition
DataLakeFormat = TelemetryDataLakeManager.DataLakeFormat
DataLakeTier = TelemetryDataLakeManager.DataLakeTier
TelemetryDataLakeManagerRecord = TelemetryDataLakeManager.Record
TelemetryDataLakeManagerAnalysis = TelemetryDataLakeManager.Analysis
TelemetryDataLakeManagerReport = TelemetryDataLakeManager.Report
