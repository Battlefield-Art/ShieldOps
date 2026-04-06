"""Cloud Spend Forecaster forecast spend horizons, detect spend seasonality, simulate growth s..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

CloudSpendForecaster = engine(
    "CloudSpendForecaster",
    description="Forecast spend horizons, detect seasonality, simulate growth scenarios.",
    enums={
        "forecast_horizon": EnumDef(
            "ForecastHorizon",
            {
                "MONTHLY": "monthly",
                "QUARTERLY": "quarterly",
                "ANNUAL": "annual",
                "MULTI_YEAR": "multi_year",
            },
        ),
        "seasonality_type": EnumDef(
            "SeasonalityType",
            {
                "WEEKLY": "weekly",
                "MONTHLY": "monthly",
                "QUARTERLY": "quarterly",
                "EVENT_DRIVEN": "event_driven",
            },
        ),
        "growth_model": EnumDef(
            "GrowthModel",
            {
                "LINEAR": "linear",
                "EXPONENTIAL": "exponential",
                "STEPWISE": "stepwise",
                "CUSTOM": "custom",
            },
        ),
    },
    record_fields=[
        FieldDef("service_name", str, ""),
        FieldDef("current_spend", float, 0.0),
        FieldDef("projected_spend", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="account_id",
)

# Backward-compatible re-exports
ForecastHorizon = CloudSpendForecaster.ForecastHorizon
SeasonalityType = CloudSpendForecaster.SeasonalityType
GrowthModel = CloudSpendForecaster.GrowthModel
CloudSpendRecord = CloudSpendForecaster.Record
CloudSpendAnalysis = CloudSpendForecaster.Analysis
CloudSpendReport = CloudSpendForecaster.Report
