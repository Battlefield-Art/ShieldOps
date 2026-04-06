"""DistributedContextEngine — track and analyze distributed context propagation."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

DistributedContextEngine = engine(
    "DistributedContextEngine",
    description="Distributed Context Engine — track context propagation across services.",
    enums={
        "context_type": EnumDef(
            "ContextType",
            {
                "W3C_TRACEPARENT": "w3c_traceparent",
                "B3_PROPAGATION": "b3_propagation",
                "BAGGAGE": "baggage",
                "CUSTOM_HEADER": "custom_header",
            },
        ),
        "propagation_status": EnumDef(
            "PropagationStatus",
            {
                "COMPLETE": "complete",
                "PARTIAL": "partial",
                "BROKEN": "broken",
                "MISSING": "missing",
            },
        ),
        "context_issue": EnumDef(
            "ContextIssue",
            {
                "MISSING_PARENT": "missing_parent",
                "ORPHAN_SPAN": "orphan_span",
                "CONTEXT_LEAK": "context_leak",
                "HEADER_CORRUPTION": "header_corruption",
            },
        ),
    },
    record_fields=[
        FieldDef("baggage_item_count", int, 0),
    ],
)

# Backward-compatible re-exports
ContextType = DistributedContextEngine.ContextType
PropagationStatus = DistributedContextEngine.PropagationStatus
ContextIssue = DistributedContextEngine.ContextIssue
DistributedContextRecord = DistributedContextEngine.Record
DistributedContextAnalysis = DistributedContextEngine.Analysis
DistributedContextReport = DistributedContextEngine.Report
