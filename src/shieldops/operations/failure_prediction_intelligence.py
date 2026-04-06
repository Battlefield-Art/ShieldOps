"""FailurePredictionIntelligence — failure prediction intelligence."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

FailurePredictionIntelligence = engine(
    "FailurePredictionIntelligence",
    module="operations",  # uses record_item
    description="Failure Prediction Intelligence.",
    enums={
        "failure_type": EnumDef(
            "FailureType",
            {
                "HARDWARE": "hardware",
                "SOFTWARE": "software",
                "NETWORK": "network",
                "CAPACITY": "capacity",
                "DEPENDENCY": "dependency",
            },
        ),
        "failure_likelihood": EnumDef(
            "FailureLikelihood",
            {
                "IMMINENT": "imminent",
                "LIKELY": "likely",
                "POSSIBLE": "possible",
                "UNLIKELY": "unlikely",
                "RARE": "rare",
            },
        ),
        "mitigation_strategy": EnumDef(
            "MitigationStrategy",
            {
                "PREEMPTIVE": "preemptive",
                "REACTIVE": "reactive",
                "REDUNDANCY": "redundancy",
                "GRACEFUL_DEGRADATION": "graceful_degradation",
                "MANUAL": "manual",
            },
        ),
    },
)

# Backward-compatible re-exports
FailureType = FailurePredictionIntelligence.FailureType
FailureLikelihood = FailurePredictionIntelligence.FailureLikelihood
MitigationStrategy = FailurePredictionIntelligence.MitigationStrategy
FailurePredictionIntelligenceRecord = FailurePredictionIntelligence.Record
FailurePredictionIntelligenceAnalysis = FailurePredictionIntelligence.Analysis
FailurePredictionIntelligenceReport = FailurePredictionIntelligence.Report
