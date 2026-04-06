"""CrossSignalCorrelationEngine — Correlate traces, metrics, and logs for root cause analysis."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

CrossSignalCorrelationEngine = engine(
    "CrossSignalCorrelationEngine",
    description="Correlate traces + metrics + logs for unified root cause analysis.",
    enums={
        "signal_type": EnumDef(
            "SignalType",
            {
                "TRACE": "trace",
                "METRIC": "metric",
                "LOG": "log",
            },
        ),
        "correlation_strength": EnumDef(
            "CorrelationStrength",
            {
                "STRONG": "strong",
                "MODERATE": "moderate",
                "WEAK": "weak",
                "NONE": "none",
            },
        ),
        "root_cause_confidence": EnumDef(
            "RootCauseConfidence",
            {
                "CONFIRMED": "confirmed",
                "PROBABLE": "probable",
                "POSSIBLE": "possible",
                "UNLIKELY": "unlikely",
            },
        ),
    },
    record_fields=[
        FieldDef("signal_count", int, 0),
        FieldDef("correlation_id", str, ""),
    ],
)

# Backward-compatible re-exports
SignalType = CrossSignalCorrelationEngine.SignalType
CorrelationStrength = CrossSignalCorrelationEngine.CorrelationStrength
RootCauseConfidence = CrossSignalCorrelationEngine.RootCauseConfidence
CrossSignalCorrelationRecord = CrossSignalCorrelationEngine.Record
CrossSignalCorrelationAnalysis = CrossSignalCorrelationEngine.Analysis
CrossSignalCorrelationReport = CrossSignalCorrelationEngine.Report
