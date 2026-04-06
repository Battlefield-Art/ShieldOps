"""PredictiveIncidentEngine — predictive incident engine."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

PredictiveIncidentEngine = engine(
    "PredictiveIncidentEngine",
    module="operations",  # uses record_item
    description="Predictive Incident Engine.",
    enums={
        "prediction_type": EnumDef(
            "PredictionType",
            {
                "OUTAGE": "outage",
                "DEGRADATION": "degradation",
                "CAPACITY": "capacity",
                "SECURITY": "security",
                "COMPLIANCE": "compliance",
            },
        ),
        "prediction_confidence": EnumDef(
            "PredictionConfidence",
            {
                "VERY_HIGH": "very_high",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "SPECULATIVE": "speculative",
            },
        ),
        "time_to_impact": EnumDef(
            "TimeToImpact",
            {
                "IMMINENT": "imminent",
                "HOURS": "hours",
                "DAYS": "days",
                "WEEKS": "weeks",
                "MONTHS": "months",
            },
        ),
    },
)

# Backward-compatible re-exports
PredictionType = PredictiveIncidentEngine.PredictionType
PredictionConfidence = PredictiveIncidentEngine.PredictionConfidence
TimeToImpact = PredictiveIncidentEngine.TimeToImpact
PredictiveIncidentEngineRecord = PredictiveIncidentEngine.Record
PredictiveIncidentEngineAnalysis = PredictiveIncidentEngine.Analysis
PredictiveIncidentEngineReport = PredictiveIncidentEngine.Report
