"""Autonomous Incident Commander — autonomous incident command and response coordination."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AutonomousIncidentCommander = engine(
    "AutonomousIncidentCommander",
    module="operations",  # uses record_item
    description="Autonomous Incident Commander for incident command and response coordination.",
    enums={
        "command_mode": EnumDef(
            "CommandMode",
            {
                "FULLY_AUTONOMOUS": "fully_autonomous",
                "SEMI_AUTONOMOUS": "semi_autonomous",
                "ADVISORY": "advisory",
                "MANUAL": "manual",
            },
        ),
        "incident_severity": EnumDef(
            "IncidentSeverity",
            {
                "SEV1": "sev1",
                "SEV2": "sev2",
                "SEV3": "sev3",
                "SEV4": "sev4",
            },
        ),
        "escalation_trigger": EnumDef(
            "EscalationTrigger",
            {
                "TIMEOUT": "timeout",
                "THRESHOLD": "threshold",
                "COMPLEXITY": "complexity",
                "POLICY": "policy",
            },
        ),
    },
)

# Backward-compatible re-exports
CommandMode = AutonomousIncidentCommander.CommandMode
IncidentSeverity = AutonomousIncidentCommander.IncidentSeverity
EscalationTrigger = AutonomousIncidentCommander.EscalationTrigger
CommandRecord = AutonomousIncidentCommander.Record
CommandAnalysis = AutonomousIncidentCommander.Analysis
AutonomousIncidentCommanderReport = AutonomousIncidentCommander.Report
