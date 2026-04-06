"""Span Criticality Scoring Engine — score span criticality in trace trees, identify critical..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

SpanCriticalityScoringEngine = engine(
    "SpanCriticalityScoringEngine",
    description="Score span criticality in trace trees, identify critical paths, rank spans...",
    enums={
        "span_role": EnumDef(
            "SpanRole",
            {
                "ENTRY": "entry",
                "INTERNAL": "internal",
                "LEAF": "leaf",
                "ERROR": "error",
            },
        ),
        "criticality_factor": EnumDef(
            "CriticalityFactor",
            {
                "LATENCY_CONTRIBUTION": "latency_contribution",
                "ERROR_RATE": "error_rate",
                "DEPENDENCY_COUNT": "dependency_count",
                "CALL_FREQUENCY": "call_frequency",
            },
        ),
        "score_confidence": EnumDef(
            "ScoreConfidence",
            {
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "UNCERTAIN": "uncertain",
            },
        ),
    },
    record_fields=[
        FieldDef("trace_id", str, ""),
        FieldDef("service_name", str, ""),
        FieldDef("operation_name", str, ""),
        FieldDef("latency_ms", float, 0.0),
        FieldDef("dependency_count", int, 0),
        FieldDef("call_count", int, 0),
        FieldDef("description", str, ""),
    ],
    score_field="criticality_score",
    key_field="span_id",
)

# Backward-compatible re-exports
SpanRole = SpanCriticalityScoringEngine.SpanRole
CriticalityFactor = SpanCriticalityScoringEngine.CriticalityFactor
ScoreConfidence = SpanCriticalityScoringEngine.ScoreConfidence
SpanCriticalityRecord = SpanCriticalityScoringEngine.Record
SpanCriticalityAnalysis = SpanCriticalityScoringEngine.Analysis
SpanCriticalityReport = SpanCriticalityScoringEngine.Report
