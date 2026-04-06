"""IntelligentSamplingCoordinator — sampling coord."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

IntelligentSamplingCoordinator = engine(
    "IntelligentSamplingCoordinator",
    description="Intelligent Sampling Coordinator. Coordinates sampling decisions across ser...",
    enums={
        "strategy": EnumDef(
            "SamplingStrategy",
            {
                "HEAD": "head",
                "TAIL": "tail",
                "PRIORITY": "priority",
                "ADAPTIVE": "adaptive",
            },
        ),
        "importance": EnumDef(
            "TraceImportance",
            {
                "CRITICAL": "critical",
                "IMPORTANT": "important",
                "ROUTINE": "routine",
                "NOISE": "noise",
            },
        ),
        "outcome": EnumDef(
            "SamplingOutcome",
            {
                "SAMPLED": "sampled",
                "DROPPED": "dropped",
                "DEFERRED": "deferred",
            },
        ),
    },
    record_fields=[
        FieldDef("sample_rate", float, 1.0),
        FieldDef("accuracy", float, 0.0),
    ],
)

# Backward-compatible re-exports
SamplingStrategy = IntelligentSamplingCoordinator.SamplingStrategy
TraceImportance = IntelligentSamplingCoordinator.TraceImportance
SamplingOutcome = IntelligentSamplingCoordinator.SamplingOutcome
SamplingRecord = IntelligentSamplingCoordinator.Record
SamplingAnalysis = IntelligentSamplingCoordinator.Analysis
SamplingReport = IntelligentSamplingCoordinator.Report
