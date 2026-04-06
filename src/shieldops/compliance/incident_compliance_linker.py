"""Incident Compliance Linker — link incidents to compliance requirements."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

IncidentComplianceLinker = engine(
    "IncidentComplianceLinker",
    description="Link incidents to compliance requirements, track impact, identify notificat...",
    enums={
        "incident_category": EnumDef(
            "IncidentCategory",
            {
                "DATA_BREACH": "data_breach",
                "UNAUTHORIZED_ACCESS": "unauthorized_access",
                "SERVICE_DISRUPTION": "service_disruption",
                "POLICY_VIOLATION": "policy_violation",
                "REGULATORY_FAILURE": "regulatory_failure",
            },
        ),
        "compliance_impact": EnumDef(
            "ComplianceImpact",
            {
                "CRITICAL": "critical",
                "MAJOR": "major",
                "MODERATE": "moderate",
                "MINOR": "minor",
                "NONE": "none",
            },
        ),
        "notification_requirement": EnumDef(
            "NotificationRequirement",
            {
                "MANDATORY": "mandatory",
                "CONDITIONAL": "conditional",
                "RECOMMENDED": "recommended",
                "NONE_REQUIRED": "none_required",
                "TBD": "tbd",
            },
        ),
    },
    score_field="link_score",
    key_field="incident_name",
)

# Backward-compatible re-exports
IncidentCategory = IncidentComplianceLinker.IncidentCategory
ComplianceImpact = IncidentComplianceLinker.ComplianceImpact
NotificationRequirement = IncidentComplianceLinker.NotificationRequirement
LinkRecord = IncidentComplianceLinker.Record
LinkAnalysis = IncidentComplianceLinker.Analysis
IncidentComplianceReport = IncidentComplianceLinker.Report
