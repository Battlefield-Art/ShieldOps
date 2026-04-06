"""ChaosObservabilityEngine — chaos observability engine."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

ChaosObservabilityEngine = engine(
    "ChaosObservabilityEngine",
    description="Chaos Observability Engine.",
    enums={
        "signal_type": EnumDef(
            "SignalType",
            {
                "METRIC": "metric",
                "LOG": "log",
                "TRACE": "trace",
                "EVENT": "event",
                "ALERT": "alert",
            },
        ),
        "coverage_level": EnumDef(
            "CoverageLevel",
            {
                "FULL": "full",
                "PARTIAL": "partial",
                "MINIMAL": "minimal",
                "NONE": "none",
                "UNKNOWN": "unknown",
            },
        ),
        "observability_gap": EnumDef(
            "ObservabilityGap",
            {
                "MISSING_METRIC": "missing_metric",
                "NO_ALERTING": "no_alerting",
                "BLIND_SPOT": "blind_spot",
                "STALE_DASHBOARD": "stale_dashboard",
                "INCOMPLETE_TRACE": "incomplete_trace",
            },
        ),
    },
)

# Backward-compatible re-exports
SignalType = ChaosObservabilityEngine.SignalType
CoverageLevel = ChaosObservabilityEngine.CoverageLevel
ObservabilityGap = ChaosObservabilityEngine.ObservabilityGap
ChaosObservabilityRecord = ChaosObservabilityEngine.Record
ChaosObservabilityAnalysis = ChaosObservabilityEngine.Analysis
ChaosObservabilityReport = ChaosObservabilityEngine.Report
