"""Cost Trend Anomaly Correlator correlate cost with deployments, attribute trends to business..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

CostTrendAnomalyCorrelator = engine(
    "CostTrendAnomalyCorrelator",
    description="Correlate cost with deployments, attribute trends, forecast continuation.",
    enums={
        "trend_direction": EnumDef(
            "TrendDirection",
            {
                "INCREASING": "increasing",
                "STABLE": "stable",
                "DECREASING": "decreasing",
                "VOLATILE": "volatile",
            },
        ),
        "correlation_type": EnumDef(
            "CorrelationType",
            {
                "DEPLOYMENT": "deployment",
                "TRAFFIC": "traffic",
                "SEASONAL": "seasonal",
                "CONFIG": "config",
            },
        ),
        "forecast_confidence": EnumDef(
            "ForecastConfidence",
            {
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "UNCERTAIN": "uncertain",
            },
        ),
    },
    record_fields=[
        FieldDef("current_cost", float, 0.0),
        FieldDef("previous_cost", float, 0.0),
        FieldDef("event_id", str, ""),
        FieldDef("description", str, ""),
    ],
    key_field="service_name",
)

# Backward-compatible re-exports
TrendDirection = CostTrendAnomalyCorrelator.TrendDirection
CorrelationType = CostTrendAnomalyCorrelator.CorrelationType
ForecastConfidence = CostTrendAnomalyCorrelator.ForecastConfidence
CostTrendRecord = CostTrendAnomalyCorrelator.Record
CostTrendAnalysis = CostTrendAnomalyCorrelator.Analysis
CostTrendReport = CostTrendAnomalyCorrelator.Report
