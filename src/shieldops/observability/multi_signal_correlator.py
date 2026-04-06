"""Multi Signal Correlator — multi-signal correlation across metrics, logs, and traces."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

MultiSignalCorrelator = engine(
    "MultiSignalCorrelator",
    description="Multi Signal Correlator — multi-signal correlation across metrics, logs, an...",
    enums={
        "correlation_type": EnumDef(
            "CorrelationType",
            {
                "TEMPORAL": "temporal",
                "CAUSAL": "causal",
                "TOPOLOGICAL": "topological",
                "STATISTICAL": "statistical",
                "PATTERN": "pattern",
            },
        ),
        "signal_source": EnumDef(
            "SignalSource",
            {
                "METRIC_STREAM": "metric_stream",
                "LOG_PIPELINE": "log_pipeline",
                "TRACE_BACKEND": "trace_backend",
                "EVENT_BUS": "event_bus",
                "ALERT_SYSTEM": "alert_system",
            },
        ),
        "correlation_strength": EnumDef(
            "CorrelationStrength",
            {
                "STRONG": "strong",
                "MODERATE": "moderate",
                "WEAK": "weak",
                "TENTATIVE": "tentative",
                "NONE": "none",
            },
        ),
    },
)

# Backward-compatible re-exports
CorrelationType = MultiSignalCorrelator.CorrelationType
SignalSource = MultiSignalCorrelator.SignalSource
CorrelationStrength = MultiSignalCorrelator.CorrelationStrength
CorrelationRecord = MultiSignalCorrelator.Record
CorrelationAnalysis = MultiSignalCorrelator.Analysis
MultiSignalReport = MultiSignalCorrelator.Report
