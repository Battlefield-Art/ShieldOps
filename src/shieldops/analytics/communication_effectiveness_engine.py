"""Communication Effectiveness Engine — measure comm channel metrics."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

CommunicationEffectivenessEngine = engine(
    "CommunicationEffectivenessEngine",
    description="Measure communication channel effectiveness.",
    enums={
        "metric": EnumDef(
            "CommMetric",
            {
                "ACK_RATE": "ack_rate",
                "RESPONSE_TIME": "response_time",
                "ESCALATION_RATE": "escalation_rate",
                "READ_RATE": "read_rate",
                "ACTION_RATE": "action_rate",
            },
        ),
        "rate": EnumDef(
            "ResponseRate",
            {
                "IMMEDIATE": "immediate",
                "FAST": "fast",
                "NORMAL": "normal",
                "SLOW": "slow",
                "NO_RESPONSE": "no_response",
            },
        ),
        "efficiency": EnumDef(
            "ChannelEfficiency",
            {
                "EXCELLENT": "excellent",
                "GOOD": "good",
                "ADEQUATE": "adequate",
                "POOR": "poor",
                "FAILING": "failing",
            },
        ),
    },
    record_fields=[
        FieldDef("value", float, 0.0),
        FieldDef("target", float, 0.0),
        FieldDef("incident_id", str, ""),
    ],
    key_field="channel",
)

# Backward-compatible re-exports
CommMetric = CommunicationEffectivenessEngine.CommMetric
ResponseRate = CommunicationEffectivenessEngine.ResponseRate
ChannelEfficiency = CommunicationEffectivenessEngine.ChannelEfficiency
CommRecord = CommunicationEffectivenessEngine.Record
CommAnalysis = CommunicationEffectivenessEngine.Analysis
CommReport = CommunicationEffectivenessEngine.Report
