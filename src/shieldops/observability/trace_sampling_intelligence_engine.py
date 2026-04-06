"""Trace Sampling Intelligence Engine — evaluate intelligent trace sampling decisions, detect..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

TraceSamplingIntelligenceEngine = engine(
    "TraceSamplingIntelligenceEngine",
    description="Evaluate intelligent trace sampling decisions, detect sampling bias, optimi...",
    enums={
        "sampling_strategy": EnumDef(
            "SamplingStrategy",
            {
                "HEAD_BASED": "head_based",
                "TAIL_BASED": "tail_based",
                "PRIORITY": "priority",
                "ADAPTIVE": "adaptive",
            },
        ),
        "sample_decision": EnumDef(
            "SampleDecision",
            {
                "KEEP": "keep",
                "DROP": "drop",
                "DEFER": "defer",
                "ESCALATE": "escalate",
            },
        ),
        "sampling_quality": EnumDef(
            "SamplingQuality",
            {
                "REPRESENTATIVE": "representative",
                "BIASED": "biased",
                "SPARSE": "sparse",
                "COMPREHENSIVE": "comprehensive",
            },
        ),
    },
    record_fields=[
        FieldDef("trace_id", str, ""),
        FieldDef("sampling_rate", float, 0.0),
        FieldDef("trace_volume", int, 0),
        FieldDef("kept_traces", int, 0),
        FieldDef("description", str, ""),
    ],
    score_field="bias_score",
    key_field="service_name",
)

# Backward-compatible re-exports
SamplingStrategy = TraceSamplingIntelligenceEngine.SamplingStrategy
SampleDecision = TraceSamplingIntelligenceEngine.SampleDecision
SamplingQuality = TraceSamplingIntelligenceEngine.SamplingQuality
TraceSamplingRecord = TraceSamplingIntelligenceEngine.Record
TraceSamplingAnalysis = TraceSamplingIntelligenceEngine.Analysis
TraceSamplingReport = TraceSamplingIntelligenceEngine.Report
