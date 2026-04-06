"""TraceContextPropagation — trace context propagation."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

TraceContextPropagation = engine(
    "TraceContextPropagation",
    description="Trace context propagation engine.",
    enums={
        "propagation_format": EnumDef(
            "PropagationFormat",
            {
                "W3C": "w3c",
                "B3": "b3",
                "JAEGER": "jaeger",
                "XRAY": "xray",
            },
        ),
        "propagation_issue": EnumDef(
            "PropagationIssue",
            {
                "MISSING_HEADER": "missing_header",
                "FORMAT_MISMATCH": "format_mismatch",
                "CONTEXT_LOST": "context_lost",
                "ID_COLLISION": "id_collision",
            },
        ),
        "service_boundary": EnumDef(
            "ServiceBoundary",
            {
                "INTERNAL": "internal",
                "EXTERNAL": "external",
                "THIRD_PARTY": "third_party",
                "LEGACY": "legacy",
            },
        ),
    },
)

# Backward-compatible re-exports
PropagationFormat = TraceContextPropagation.PropagationFormat
PropagationIssue = TraceContextPropagation.PropagationIssue
ServiceBoundary = TraceContextPropagation.ServiceBoundary
TraceContextPropagationRecord = TraceContextPropagation.Record
TraceContextPropagationAnalysis = TraceContextPropagation.Analysis
TraceContextPropagationReport = TraceContextPropagation.Report
