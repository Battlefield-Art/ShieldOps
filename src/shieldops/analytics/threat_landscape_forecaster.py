"""Threat Landscape Forecaster — forecast emerging threats and landscape evolution."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

ThreatLandscapeForecaster = engine(
    "ThreatLandscapeForecaster",
    description="Forecast emerging threats and landscape evolution across horizons.",
    enums={
        "forecast_horizon": EnumDef(
            "ForecastHorizon",
            {
                "SHORT_TERM": "short_term",
                "MEDIUM_TERM": "medium_term",
                "LONG_TERM": "long_term",
                "STRATEGIC": "strategic",
                "TACTICAL": "tactical",
            },
        ),
        "forecast_confidence": EnumDef(
            "ForecastConfidence",
            {
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "SPECULATIVE": "speculative",
                "UNCERTAIN": "uncertain",
            },
        ),
        "threat_trend": EnumDef(
            "ThreatTrend",
            {
                "ESCALATING": "escalating",
                "STABLE": "stable",
                "DECLINING": "declining",
                "EMERGING": "emerging",
                "CYCLICAL": "cyclical",
            },
        ),
    },
    score_field="forecast_score",
    key_field="forecast_name",
)

# Backward-compatible re-exports
ForecastHorizon = ThreatLandscapeForecaster.ForecastHorizon
ForecastConfidence = ThreatLandscapeForecaster.ForecastConfidence
ThreatTrend = ThreatLandscapeForecaster.ThreatTrend
ForecastRecord = ThreatLandscapeForecaster.Record
ForecastAnalysis = ThreatLandscapeForecaster.Analysis
ForecastReport = ThreatLandscapeForecaster.Report
