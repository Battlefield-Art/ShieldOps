"""SignalRoutingEngine — telemetry signal routing."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

SignalRoutingEngine = engine(
    "SignalRoutingEngine",
    description="Telemetry signal routing engine.",
    enums={
        "signal_type": EnumDef(
            "SignalType",
            {
                "METRIC": "metric",
                "TRACE": "trace",
                "LOG": "log",
                "EVENT": "event",
            },
        ),
        "routing_rule": EnumDef(
            "RoutingRule",
            {
                "DROP": "drop",
                "SAMPLE": "sample",
                "TRANSFORM": "transform",
                "FORWARD": "forward",
            },
        ),
        "routing_priority": EnumDef(
            "RoutingPriority",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            },
        ),
    },
)

# Backward-compatible re-exports
SignalType = SignalRoutingEngine.SignalType
RoutingRule = SignalRoutingEngine.RoutingRule
RoutingPriority = SignalRoutingEngine.RoutingPriority
SignalRoutingEngineRecord = SignalRoutingEngine.Record
SignalRoutingEngineAnalysis = SignalRoutingEngine.Analysis
SignalRoutingEngineReport = SignalRoutingEngine.Report
