"""AgentCommunicationAuditor — Audits agent-to-agent communication channels."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AgentCommunicationAuditor = engine(
    "AgentCommunicationAuditor",
    description="Audits agent-to-agent communication channels.",
    enums={
        "channel_type": EnumDef(
            "ChannelType",
            {
                "DIRECT": "direct",
                "BROADCAST": "broadcast",
                "DELEGATED": "delegated",
                "PROXIED": "proxied",
            },
        ),
        "audit_verdict": EnumDef(
            "AuditVerdict",
            {
                "CLEAN": "clean",
                "SUSPICIOUS": "suspicious",
                "TAMPERED": "tampered",
                "BLOCKED": "blocked",
            },
        ),
        "data_sensitivity": EnumDef(
            "DataSensitivity",
            {
                "PUBLIC": "public",
                "INTERNAL": "internal",
                "CONFIDENTIAL": "confidential",
                "RESTRICTED": "restricted",
            },
        ),
    },
    record_fields=[
        FieldDef("destination", str, ""),
        FieldDef("payload_size_bytes", int, 0),
        FieldDef("message_count", int, 0),
    ],
    key_field="source",
)

# Backward-compatible re-exports
ChannelType = AgentCommunicationAuditor.ChannelType
AuditVerdict = AgentCommunicationAuditor.AuditVerdict
DataSensitivity = AgentCommunicationAuditor.DataSensitivity
CommunicationRecord = AgentCommunicationAuditor.Record
CommunicationAnalysis = AgentCommunicationAuditor.Analysis
CommunicationReport = AgentCommunicationAuditor.Report
