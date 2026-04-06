"""Operational Forecasting Engine Time-series forecasting for operational metrics with multi-h..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

OperationalForecastingEngine = engine(
    "OperationalForecastingEngine",
    description="Operational Forecasting Engine Time-series forecasting for operational metr...",
    enums={
        "horizon": EnumDef(
            "ForecastHorizon",
            {
                "ONE_HOUR": "one_hour",
                "SIX_HOURS": "six_hours",
                "ONE_DAY": "one_day",
                "SEVEN_DAYS": "seven_days",
                "THIRTY_DAYS": "thirty_days",
            },
        ),
        "method": EnumDef(
            "ForecastMethod",
            {
                "ARIMA": "arima",
                "EXPONENTIAL_SMOOTHING": "exponential_smoothing",
                "PROPHET": "prophet",
                "LINEAR": "linear",
                "ENSEMBLE": "ensemble",
            },
        ),
        "forecast_accuracy": EnumDef(
            "ForecastAccuracy",
            {
                "EXCELLENT": "excellent",
                "GOOD": "good",
                "FAIR": "fair",
                "POOR": "poor",
                "INSUFFICIENT_DATA": "insufficient_data",
            },
        ),
    },
    record_fields=[
        FieldDef("predicted_value", float, 0.0),
        FieldDef("actual_value", float, 0.0),
        FieldDef("confidence_interval_pct", float, 0.0),
        FieldDef("breach_predicted", bool, False),
    ],
    score_field="accuracy_score",
    key_field="metric_name",
)

# Backward-compatible re-exports
ForecastHorizon = OperationalForecastingEngine.ForecastHorizon
ForecastMethod = OperationalForecastingEngine.ForecastMethod
ForecastAccuracy = OperationalForecastingEngine.ForecastAccuracy
ForecastRecord = OperationalForecastingEngine.Record
ForecastAnalysis = OperationalForecastingEngine.Analysis
ForecastReport = OperationalForecastingEngine.Report
