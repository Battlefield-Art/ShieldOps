"""Capacity Demand Forecaster compute demand forecasts, detect capacity exhaustion risk, rank..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

CapacityDemandForecaster = engine(
    "CapacityDemandForecaster",
    description="Compute demand forecasts, detect capacity exhaustion risk, rank resources b...",
    enums={
        "forecast_horizon": EnumDef(
            "ForecastHorizon",
            {
                "SHORT_TERM": "short_term",
                "MEDIUM_TERM": "medium_term",
                "LONG_TERM": "long_term",
                "SEASONAL": "seasonal",
            },
        ),
        "resource_type": EnumDef(
            "ResourceType",
            {
                "CPU": "cpu",
                "MEMORY": "memory",
                "STORAGE": "storage",
                "NETWORK": "network",
            },
        ),
        "demand_trend": EnumDef(
            "DemandTrend",
            {
                "GROWING": "growing",
                "STABLE": "stable",
                "DECLINING": "declining",
                "VOLATILE": "volatile",
            },
        ),
    },
    record_fields=[
        FieldDef("current_usage", float, 0.0),
        FieldDef("capacity_limit", float, 100.0),
        FieldDef("forecast_value", float, 0.0),
        FieldDef("region", str, ""),
        FieldDef("description", str, ""),
    ],
    key_field="resource_id",
)

# Backward-compatible re-exports
ForecastHorizon = CapacityDemandForecaster.ForecastHorizon
ResourceType = CapacityDemandForecaster.ResourceType
DemandTrend = CapacityDemandForecaster.DemandTrend
CapacityDemandRecord = CapacityDemandForecaster.Record
CapacityDemandAnalysis = CapacityDemandForecaster.Analysis
CapacityDemandReport = CapacityDemandForecaster.Report
