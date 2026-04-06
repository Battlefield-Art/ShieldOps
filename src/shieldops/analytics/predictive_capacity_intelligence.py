"""Predictive Capacity Intelligence predictive capacity intelligence with ML-driven forecasting."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

PredictiveCapacityIntelligence = engine(
    "PredictiveCapacityIntelligence",
    description="Predictive Capacity Intelligence predictive capacity intelligence with ML-d...",
    enums={
        "capacity_domain": EnumDef(
            "CapacityDomain",
            {
                "COMPUTE": "compute",
                "MEMORY": "memory",
                "STORAGE": "storage",
                "NETWORK": "network",
                "DATABASE": "database",
            },
        ),
        "forecast_method": EnumDef(
            "ForecastMethod",
            {
                "LINEAR": "linear",
                "EXPONENTIAL": "exponential",
                "SEASONAL": "seasonal",
                "ML_ENSEMBLE": "ml_ensemble",
                "HYBRID": "hybrid",
            },
        ),
        "capacity_risk": EnumDef(
            "CapacityRisk",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "ADEQUATE": "adequate",
            },
        ),
    },
)

# Backward-compatible re-exports
CapacityDomain = PredictiveCapacityIntelligence.CapacityDomain
ForecastMethod = PredictiveCapacityIntelligence.ForecastMethod
CapacityRisk = PredictiveCapacityIntelligence.CapacityRisk
CapacityIntelRecord = PredictiveCapacityIntelligence.Record
CapacityIntelAnalysis = PredictiveCapacityIntelligence.Analysis
PredictiveCapacityReport = PredictiveCapacityIntelligence.Report
