"""PredictiveSlaEngine — predictive sla engine."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

PredictiveSlaEngine = engine(
    "PredictiveSlaEngine",
    module="operations",  # uses record_item
    description="Predictive Sla Engine.",
    enums={
        "sla_metric": EnumDef(
            "SlaMetric",
            {
                "AVAILABILITY": "availability",
                "LATENCY": "latency",
                "THROUGHPUT": "throughput",
                "ERROR_RATE": "error_rate",
                "RESPONSE_TIME": "response_time",
            },
        ),
        "breach_risk": EnumDef(
            "BreachRisk",
            {
                "IMMINENT": "imminent",
                "HIGH": "high",
                "MODERATE": "moderate",
                "LOW": "low",
                "MINIMAL": "minimal",
            },
        ),
        "mitigation_priority": EnumDef(
            "MitigationPriority",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "DEFERRED": "deferred",
            },
        ),
    },
)

# Backward-compatible re-exports
SlaMetric = PredictiveSlaEngine.SlaMetric
BreachRisk = PredictiveSlaEngine.BreachRisk
MitigationPriority = PredictiveSlaEngine.MitigationPriority
PredictiveSlaEngineRecord = PredictiveSlaEngine.Record
PredictiveSlaEngineAnalysis = PredictiveSlaEngine.Analysis
PredictiveSlaEngineReport = PredictiveSlaEngine.Report
