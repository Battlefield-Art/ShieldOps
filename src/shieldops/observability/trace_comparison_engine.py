"""Trace Comparison Engine — compare traces across time periods or versions, detect behavioral..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

TraceComparisonEngine = engine(
    "TraceComparisonEngine",
    description="Compare traces across time periods or versions, detect behavioral changes,...",
    enums={
        "comparison_type": EnumDef(
            "ComparisonType",
            {
                "TEMPORAL": "temporal",
                "VERSION": "version",
                "CANARY": "canary",
                "BASELINE": "baseline",
            },
        ),
        "difference_type": EnumDef(
            "DifferenceType",
            {
                "STRUCTURAL": "structural",
                "PERFORMANCE": "performance",
                "ERROR_RATE": "error_rate",
                "VOLUME": "volume",
            },
        ),
        "comparison_result": EnumDef(
            "ComparisonResult",
            {
                "IMPROVED": "improved",
                "UNCHANGED": "unchanged",
                "DEGRADED": "degraded",
                "INCOMPARABLE": "incomparable",
            },
        ),
    },
    record_fields=[
        FieldDef("baseline_trace_id", str, ""),
        FieldDef("candidate_trace_id", str, ""),
        FieldDef("baseline_latency_ms", float, 0.0),
        FieldDef("candidate_latency_ms", float, 0.0),
        FieldDef("baseline_error_rate", float, 0.0),
        FieldDef("candidate_error_rate", float, 0.0),
        FieldDef("description", str, ""),
    ],
    score_field="difference_score",
    key_field="service_name",
)

# Backward-compatible re-exports
ComparisonType = TraceComparisonEngine.ComparisonType
DifferenceType = TraceComparisonEngine.DifferenceType
ComparisonResult = TraceComparisonEngine.ComparisonResult
TraceComparisonRecord = TraceComparisonEngine.Record
TraceComparisonAnalysis = TraceComparisonEngine.Analysis
TraceComparisonReport = TraceComparisonEngine.Report
