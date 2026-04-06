"""API Health Composite Scorer. Compute composite health scores for APIs, identify degraded en..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ApiHealthCompositeScorer = engine(
    "ApiHealthCompositeScorer",
    module="operations",  # uses record_item
    description="Compute composite health scores, identify degraded endpoints, and benchmark...",
    enums={
        "health_grade": EnumDef(
            "HealthGrade",
            {
                "EXCELLENT": "excellent",
                "GOOD": "good",
                "FAIR": "fair",
                "POOR": "poor",
            },
        ),
        "signal_type": EnumDef(
            "SignalType",
            {
                "LATENCY": "latency",
                "ERROR_RATE": "error_rate",
                "THROUGHPUT": "throughput",
                "SATURATION": "saturation",
            },
        ),
        "benchmark_scope": EnumDef(
            "BenchmarkScope",
            {
                "SERVICE": "service",
                "TEAM": "team",
                "ORGANIZATION": "organization",
                "INDUSTRY": "industry",
            },
        ),
    },
    record_fields=[
        FieldDef("latency_ms", float, 0.0),
        FieldDef("error_rate", float, 0.0),
        FieldDef("throughput_rps", float, 0.0),
    ],
    key_field="endpoint",
)

# Backward-compatible re-exports
HealthGrade = ApiHealthCompositeScorer.HealthGrade
SignalType = ApiHealthCompositeScorer.SignalType
BenchmarkScope = ApiHealthCompositeScorer.BenchmarkScope
ApiHealthRecord = ApiHealthCompositeScorer.Record
ApiHealthAnalysis = ApiHealthCompositeScorer.Analysis
ApiHealthReport = ApiHealthCompositeScorer.Report
