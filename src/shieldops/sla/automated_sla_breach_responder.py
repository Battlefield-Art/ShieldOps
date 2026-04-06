"""Automated Sla Breach Responder — automated SLA breach response and recovery."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AutomatedSlaBreachResponder = engine(
    "AutomatedSlaBreachResponder",
    description="Automated Sla Breach Responder — automated SLA breach response and recovery.",
    enums={
        "breach_type": EnumDef(
            "BreachType",
            {
                "AVAILABILITY": "availability",
                "LATENCY": "latency",
                "ERROR_RATE": "error_rate",
                "THROUGHPUT": "throughput",
                "RESPONSE_TIME": "response_time",
            },
        ),
        "response_strategy": EnumDef(
            "ResponseStrategy",
            {
                "SCALING": "scaling",
                "FAILOVER": "failover",
                "TRAFFIC_SHIFT": "traffic_shift",
                "DEGRADATION": "degradation",
                "NOTIFICATION": "notification",
            },
        ),
        "breach_severity": EnumDef(
            "BreachSeverity",
            {
                "CRITICAL": "critical",
                "MAJOR": "major",
                "MINOR": "minor",
                "WARNING": "warning",
                "INFORMATIONAL": "informational",
            },
        ),
    },
)

# Backward-compatible re-exports
BreachType = AutomatedSlaBreachResponder.BreachType
ResponseStrategy = AutomatedSlaBreachResponder.ResponseStrategy
BreachSeverity = AutomatedSlaBreachResponder.BreachSeverity
BreachRecord = AutomatedSlaBreachResponder.Record
BreachAnalysis = AutomatedSlaBreachResponder.Analysis
AutomatedSlaBreachReport = AutomatedSlaBreachResponder.Report
