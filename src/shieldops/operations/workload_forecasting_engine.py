"""WorkloadForecastingEngine — workload forecasting engine."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

WorkloadForecastingEngine = engine(
    "WorkloadForecastingEngine",
    module="operations",  # uses record_item
    description="Workload Forecasting Engine.",
    enums={
        "workload_type": EnumDef(
            "WorkloadType",
            {
                "WEB_TRAFFIC": "web_traffic",
                "BATCH_PROCESSING": "batch_processing",
                "STREAMING": "streaming",
                "ML_INFERENCE": "ml_inference",
                "DATABASE": "database",
            },
        ),
        "forecast_granularity": EnumDef(
            "ForecastGranularity",
            {
                "MINUTE": "minute",
                "HOURLY": "hourly",
                "DAILY": "daily",
                "WEEKLY": "weekly",
                "MONTHLY": "monthly",
            },
        ),
        "seasonal_pattern": EnumDef(
            "SeasonalPattern",
            {
                "DAILY": "daily",
                "WEEKLY": "weekly",
                "MONTHLY": "monthly",
                "QUARTERLY": "quarterly",
                "ANNUAL": "annual",
            },
        ),
    },
)

# Backward-compatible re-exports
WorkloadType = WorkloadForecastingEngine.WorkloadType
ForecastGranularity = WorkloadForecastingEngine.ForecastGranularity
SeasonalPattern = WorkloadForecastingEngine.SeasonalPattern
WorkloadForecastingEngineRecord = WorkloadForecastingEngine.Record
WorkloadForecastingEngineAnalysis = WorkloadForecastingEngine.Analysis
WorkloadForecastingEngineReport = WorkloadForecastingEngine.Report
