"""AgentEscalationEngine — manages escalation chains for AI agent governance decisions."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AgentEscalationEngine = engine(
    "AgentEscalationEngine",
    description="Manages escalation chains for AI agent governance decisions.",
    enums={
        "priority": EnumDef(
            "EscalationPriority",
            {
                "P0": "p0",
                "P1": "p1",
                "P2": "p2",
                "P3": "p3",
                "P4": "p4",
            },
        ),
        "outcome": EnumDef(
            "EscalationOutcome",
            {
                "APPROVED": "approved",
                "DENIED": "denied",
                "DEFERRED": "deferred",
                "AUTO_RESOLVED": "auto_resolved",
            },
        ),
        "channel": EnumDef(
            "EscalationChannel",
            {
                "SLACK": "slack",
                "PAGERDUTY": "pagerduty",
                "EMAIL": "email",
                "IN_APP": "in_app",
            },
        ),
    },
    record_fields=[
        FieldDef("reason", str, ""),
        FieldDef("responder", str, ""),
        FieldDef("escalated_at", float, ""),
        FieldDef("resolved_at", float, 0.0),
        FieldDef("response_time_sec", float, 0.0),
        FieldDef("context", dict, ""),
    ],
    key_field="agent_id",
)

# Backward-compatible re-exports
EscalationPriority = AgentEscalationEngine.EscalationPriority
EscalationOutcome = AgentEscalationEngine.EscalationOutcome
EscalationChannel = AgentEscalationEngine.EscalationChannel
EscalationRecord = AgentEscalationEngine.Record
EscalationAnalysis = AgentEscalationEngine.Analysis
EscalationReport = AgentEscalationEngine.Report
