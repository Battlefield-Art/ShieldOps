"""Distributed Context Tracker Cross-service context propagation tracking, baggage validation,..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

DistributedContextTracker = engine(
    "DistributedContextTracker",
    description="Distributed Context Tracker Cross-service context propagation tracking, bag...",
    enums={
        "propagation_format": EnumDef(
            "PropagationFormat",
            {
                "W3C_TRACEPARENT": "w3c_traceparent",
                "W3C_TRACESTATE": "w3c_tracestate",
                "B3_SINGLE": "b3_single",
                "B3_MULTI": "b3_multi",
                "JAEGER": "jaeger",
                "XRAY": "xray",
                "CUSTOM": "custom",
            },
        ),
        "context_health": EnumDef(
            "ContextHealth",
            {
                "VALID": "valid",
                "MISSING": "missing",
                "CORRUPTED": "corrupted",
                "TRUNCATED": "truncated",
                "LEAKED": "leaked",
                "EXPIRED": "expired",
            },
        ),
        "compliance_level": EnumDef(
            "ComplianceLevel",
            {
                "COMPLIANT": "compliant",
                "PARTIAL": "partial",
                "NON_COMPLIANT": "non_compliant",
                "UNKNOWN": "unknown",
            },
        ),
    },
    record_fields=[
        FieldDef("span_id", str, ""),
        FieldDef("parent_span_id", str, ""),
        FieldDef("source_service", str, ""),
        FieldDef("target_service", str, ""),
        FieldDef("baggage_items", dict, ""),
        FieldDef("baggage_size_bytes", int, 0),
        FieldDef("hop_count", int, 0),
        FieldDef("context_age_ms", float, 0.0),
    ],
    key_field="trace_id",
)

# Backward-compatible re-exports
PropagationFormat = DistributedContextTracker.PropagationFormat
ContextHealth = DistributedContextTracker.ContextHealth
ComplianceLevel = DistributedContextTracker.ComplianceLevel
ContextRecord = DistributedContextTracker.Record
ContextAnalysis = DistributedContextTracker.Analysis
ContextPropagationReport = DistributedContextTracker.Report
