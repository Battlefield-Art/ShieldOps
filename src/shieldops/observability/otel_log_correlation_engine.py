"""OtelLogCorrelationEngine — Correlate logs with traces via trace_id and span_id."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

OtelLogCorrelationEngine = engine(
    "OtelLogCorrelationEngine",
    description="Correlate logs with traces via trace_id and span_id.",
    enums={
        "correlation_status": EnumDef(
            "CorrelationStatus",
            {
                "CORRELATED": "correlated",
                "ORPHANED": "orphaned",
                "MISSING_CONTEXT": "missing_context",
            },
        ),
        "log_level": EnumDef(
            "LogLevel",
            {
                "TRACE": "trace",
                "DEBUG": "debug",
                "INFO": "info",
                "WARN": "warn",
                "ERROR": "error",
                "FATAL": "fatal",
            },
        ),
        "correlation_quality": EnumDef(
            "CorrelationQuality",
            {
                "EXCELLENT": "excellent",
                "GOOD": "good",
                "FAIR": "fair",
                "POOR": "poor",
            },
        ),
    },
    record_fields=[
        FieldDef("log_count", int, 0),
        FieldDef("trace_id", str, ""),
    ],
)

# Backward-compatible re-exports
CorrelationStatus = OtelLogCorrelationEngine.CorrelationStatus
LogLevel = OtelLogCorrelationEngine.LogLevel
CorrelationQuality = OtelLogCorrelationEngine.CorrelationQuality
OtelLogCorrelationRecord = OtelLogCorrelationEngine.Record
OtelLogCorrelationAnalysis = OtelLogCorrelationEngine.Analysis
OtelLogCorrelationReport = OtelLogCorrelationEngine.Report
