"""TraceLogCorrelationQualityEngine — Measure trace-to-log correlation quality."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

TraceLogCorrelationQualityEngine = engine(
    "TraceLogCorrelationQualityEngine",
    description="Measure quality of trace-to-log correlation.",
    enums={
        "method": EnumDef(
            "CorrelationMethod",
            {
                "TRACE_ID_INJECTION": "trace_id_injection",
                "W3C_TRACEPARENT": "w3c_traceparent",
                "B3_PROPAGATION": "b3_propagation",
            },
        ),
        "gap": EnumDef(
            "CorrelationGap",
            {
                "NO_TRACE_ID": "no_trace_id",
                "NO_SPAN_ID": "no_span_id",
                "MISMATCHED_SERVICE": "mismatched_service",
            },
        ),
        "status": EnumDef(
            "InstrumentationStatus",
            {
                "AUTO": "auto",
                "MANUAL": "manual",
                "MISSING": "missing",
            },
        ),
    },
    record_fields=[
        FieldDef("correlation_pct", float, 0.0),
        FieldDef("log_volume", int, 0),
    ],
)

# Backward-compatible re-exports
CorrelationMethod = TraceLogCorrelationQualityEngine.CorrelationMethod
CorrelationGap = TraceLogCorrelationQualityEngine.CorrelationGap
InstrumentationStatus = TraceLogCorrelationQualityEngine.InstrumentationStatus
TraceLogCorrelationQualityRecord = TraceLogCorrelationQualityEngine.Record
TraceLogCorrelationQualityAnalysis = TraceLogCorrelationQualityEngine.Analysis
TraceLogCorrelationQualityReport = TraceLogCorrelationQualityEngine.Report
