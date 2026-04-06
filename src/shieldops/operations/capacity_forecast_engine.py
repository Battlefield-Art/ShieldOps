"""Capacity Forecast Engine — track resource capacity forecasting accuracy."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

CapacityForecastEngine = engine(
    "CapacityForecastEngine",
    description="Track resource capacity forecasting accuracy across services.",
    enums={
        "forecast_method": EnumDef(
            "ForecastMethod",
            {
                "STATISTICAL": "statistical",
                "ML_MODEL": "ml_model",
                "HEURISTIC": "heuristic",
                "MANUAL": "manual",
                "HYBRID": "hybrid",
            },
        ),
        "resource_category": EnumDef(
            "ResourceCategory",
            {
                "COMPUTE": "compute",
                "MEMORY": "memory",
                "STORAGE": "storage",
                "NETWORK": "network",
                "DATABASE": "database",
            },
        ),
        "forecast_accuracy": EnumDef(
            "ForecastAccuracy",
            {
                "EXACT": "exact",
                "CLOSE": "close",
                "OVERESTIMATED": "overestimated",
                "UNDERESTIMATED": "underestimated",
                "MISSED": "missed",
            },
        ),
    },
    record_fields=[
        FieldDef("predicted_value", float, 0.0),
        FieldDef("actual_value", float, 0.0),
        FieldDef("deviation_pct", float, 0.0),
        FieldDef("horizon_days", int, 30),
        FieldDef("description", str, ""),
    ],
    score_field="confidence_score",
    key_field="service_id",
)

# Backward-compatible re-exports
ForecastMethod = CapacityForecastEngine.ForecastMethod
ResourceCategory = CapacityForecastEngine.ResourceCategory
ForecastAccuracy = CapacityForecastEngine.ForecastAccuracy
CapacityForecastRecord = CapacityForecastEngine.Record
CapacityForecastAnalysis = CapacityForecastEngine.Analysis
CapacityForecastReport = CapacityForecastEngine.Report
