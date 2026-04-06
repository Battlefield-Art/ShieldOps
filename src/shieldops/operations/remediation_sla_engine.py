"""Remediation SLA Engine — track SLA compliance."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

RemediationSLAEngine = engine(
    "RemediationSLAEngine",
    description="Track remediation SLA compliance.",
    enums={
        "tier": EnumDef(
            "SLATier",
            {
                "P1_CRITICAL": "p1_critical",
                "P2_HIGH": "p2_high",
                "P3_MEDIUM": "p3_medium",
                "P4_LOW": "p4_low",
                "P5_INFORMATIONAL": "p5_informational",
            },
        ),
        "status": EnumDef(
            "ComplianceStatus",
            {
                "COMPLIANT": "compliant",
                "AT_RISK": "at_risk",
                "BREACHED": "breached",
                "WAIVED": "waived",
                "PENDING": "pending",
            },
        ),
        "escalation": EnumDef(
            "EscalationLevel",
            {
                "NONE": "none",
                "TEAM_LEAD": "team_lead",
                "MANAGER": "manager",
                "DIRECTOR": "director",
                "VP": "vp",
            },
        ),
    },
    record_fields=[
        FieldDef("target_hours", float, 72.0),
        FieldDef("elapsed_hours", float, 0.0),
        FieldDef("owner", str, ""),
    ],
    key_field="remediation_id",
)

# Backward-compatible re-exports
SLATier = RemediationSLAEngine.SLATier
ComplianceStatus = RemediationSLAEngine.ComplianceStatus
EscalationLevel = RemediationSLAEngine.EscalationLevel
RemediationSLARecord = RemediationSLAEngine.Record
RemediationSLAAnalysis = RemediationSLAEngine.Analysis
RemediationSLAReport = RemediationSLAEngine.Report
