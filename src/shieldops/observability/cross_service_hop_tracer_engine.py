"""Cross-Service Hop Tracer Engine — trace investigation hops across service boundaries, ident..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

CrossServiceHopTracerEngine = engine(
    "CrossServiceHopTracerEngine",
    description="Trace investigation hops across service boundaries, identify hop blockers,...",
    enums={
        "hop_type": EnumDef(
            "HopType",
            {
                "DEPENDENCY": "dependency",
                "SHARED_RESOURCE": "shared_resource",
                "CASCADE": "cascade",
                "CONFIGURATION": "configuration",
            },
        ),
        "service_boundary": EnumDef(
            "ServiceBoundary",
            {
                "SAME_SERVICE": "same_service",
                "SAME_TEAM": "same_team",
                "CROSS_TEAM": "cross_team",
                "CROSS_ORG": "cross_org",
            },
        ),
        "tracing_completeness": EnumDef(
            "TracingCompleteness",
            {
                "FULL_TRACE": "full_trace",
                "PARTIAL_TRACE": "partial_trace",
                "BLOCKED_TRACE": "blocked_trace",
                "ESTIMATED_TRACE": "estimated_trace",
            },
        ),
    },
    record_fields=[
        FieldDef("latency_ms", float, 0.0),
        FieldDef("hop_index", int, 0),
        FieldDef("source_service", str, ""),
        FieldDef("target_service", str, ""),
        FieldDef("description", str, ""),
    ],
    key_field="trace_id",
)

# Backward-compatible re-exports
HopType = CrossServiceHopTracerEngine.HopType
ServiceBoundary = CrossServiceHopTracerEngine.ServiceBoundary
TracingCompleteness = CrossServiceHopTracerEngine.TracingCompleteness
CrossServiceHopRecord = CrossServiceHopTracerEngine.Record
CrossServiceHopAnalysis = CrossServiceHopTracerEngine.Analysis
CrossServiceHopReport = CrossServiceHopTracerEngine.Report
