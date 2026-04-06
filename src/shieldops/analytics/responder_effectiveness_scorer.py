"""Responder Effectiveness Scorer score responder performance, benchmark against peers, identi..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ResponderEffectivenessScorer = engine(
    "ResponderEffectivenessScorer",
    description="Score responder performance, benchmark against peers, identify skill develo...",
    enums={
        "performance_tier": EnumDef(
            "PerformanceTier",
            {
                "EXCEPTIONAL": "exceptional",
                "PROFICIENT": "proficient",
                "DEVELOPING": "developing",
                "NOVICE": "novice",
            },
        ),
        "metric_category": EnumDef(
            "MetricCategory",
            {
                "SPEED": "speed",
                "ACCURACY": "accuracy",
                "QUALITY": "quality",
                "COMMUNICATION": "communication",
            },
        ),
        "benchmark_scope": EnumDef(
            "BenchmarkScope",
            {
                "TEAM": "team",
                "DEPARTMENT": "department",
                "ORGANIZATION": "organization",
                "INDUSTRY": "industry",
            },
        ),
    },
    record_fields=[
        FieldDef("incidents_resolved", int, 0),
        FieldDef("avg_resolution_min", float, 0.0),
    ],
    key_field="responder_id",
)

# Backward-compatible re-exports
PerformanceTier = ResponderEffectivenessScorer.PerformanceTier
MetricCategory = ResponderEffectivenessScorer.MetricCategory
BenchmarkScope = ResponderEffectivenessScorer.BenchmarkScope
ResponderEffectivenessRecord = ResponderEffectivenessScorer.Record
ResponderEffectivenessAnalysis = ResponderEffectivenessScorer.Analysis
ResponderEffectivenessReport = ResponderEffectivenessScorer.Report
