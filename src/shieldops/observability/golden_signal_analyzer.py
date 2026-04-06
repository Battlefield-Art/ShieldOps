"""Golden Signal Analyzer — golden signals analysis (latency, traffic, errors, saturation)."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

GoldenSignalAnalyzer = engine(
    "GoldenSignalAnalyzer",
    description="Golden Signal Analyzer — golden signals analysis (latency, traffic, errors,...",
    enums={
        "golden_signal": EnumDef(
            "GoldenSignal",
            {
                "LATENCY": "latency",
                "TRAFFIC": "traffic",
                "ERRORS": "errors",
                "SATURATION": "saturation",
                "AVAILABILITY": "availability",
            },
        ),
        "signal_scope": EnumDef(
            "SignalScope",
            {
                "SERVICE": "service",
                "ENDPOINT": "endpoint",
                "CLUSTER": "cluster",
                "REGION": "region",
                "GLOBAL": "global",
            },
        ),
        "signal_health": EnumDef(
            "SignalHealth",
            {
                "HEALTHY": "healthy",
                "WARNING": "warning",
                "CRITICAL": "critical",
                "UNKNOWN": "unknown",
                "MAINTENANCE": "maintenance",
            },
        ),
    },
)

# Backward-compatible re-exports
GoldenSignal = GoldenSignalAnalyzer.GoldenSignal
SignalScope = GoldenSignalAnalyzer.SignalScope
SignalHealth = GoldenSignalAnalyzer.SignalHealth
GoldenSignalRecord = GoldenSignalAnalyzer.Record
GoldenSignalAnalysis = GoldenSignalAnalyzer.Analysis
GoldenSignalReport = GoldenSignalAnalyzer.Report
