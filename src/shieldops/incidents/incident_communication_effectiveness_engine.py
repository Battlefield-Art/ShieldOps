"""Incident Communication Effectiveness Engine — compute communication scores, detect gaps, ra..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

IncidentCommunicationEffectivenessEngine = engine(
    "IncidentCommunicationEffectivenessEngine",
    description="Compute communication scores, detect communication gaps, rank incidents by...",
    enums={
        "channel": EnumDef(
            "CommunicationChannel",
            {
                "SLACK": "slack",
                "EMAIL": "email",
                "PAGERDUTY": "pagerduty",
                "STATUSPAGE": "statuspage",
            },
        ),
        "quality": EnumDef(
            "CommunicationQuality",
            {
                "EXCELLENT": "excellent",
                "GOOD": "good",
                "FAIR": "fair",
                "POOR": "poor",
            },
        ),
        "stakeholder_type": EnumDef(
            "StakeholderType",
            {
                "ENGINEERING": "engineering",
                "MANAGEMENT": "management",
                "CUSTOMER": "customer",
                "EXTERNAL": "external",
            },
        ),
    },
    record_fields=[
        FieldDef("response_time_seconds", float, 0.0),
        FieldDef("update_count", int, 0),
        FieldDef("description", str, ""),
    ],
    score_field="comms_score",
    key_field="incident_id",
)

# Backward-compatible re-exports
CommunicationChannel = IncidentCommunicationEffectivenessEngine.CommunicationChannel
CommunicationQuality = IncidentCommunicationEffectivenessEngine.CommunicationQuality
StakeholderType = IncidentCommunicationEffectivenessEngine.StakeholderType
CommunicationEffectivenessRecord = IncidentCommunicationEffectivenessEngine.Record
CommunicationEffectivenessAnalysis = IncidentCommunicationEffectivenessEngine.Analysis
CommunicationEffectivenessReport = IncidentCommunicationEffectivenessEngine.Report
