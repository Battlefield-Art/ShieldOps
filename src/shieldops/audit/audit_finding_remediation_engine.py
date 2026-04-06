"""Audit Finding Remediation Engine compute remediation velocity, detect overdue findings, ran..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AuditFindingRemediationEngine = engine(
    "AuditFindingRemediationEngine",
    description="Compute remediation velocity, detect overdue findings, rank findings by ris...",
    enums={
        "finding_severity": EnumDef(
            "FindingSeverity",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            },
        ),
        "remediation_status": EnumDef(
            "RemediationStatus",
            {
                "OPEN": "open",
                "IN_PROGRESS": "in_progress",
                "REMEDIATED": "remediated",
                "ACCEPTED_RISK": "accepted_risk",
            },
        ),
        "finding_category": EnumDef(
            "FindingCategory",
            {
                "CONTROL_GAP": "control_gap",
                "PROCESS_DEFICIENCY": "process_deficiency",
                "TECHNICAL_DEBT": "technical_debt",
                "POLICY_VIOLATION": "policy_violation",
            },
        ),
    },
    record_fields=[
        FieldDef("days_open", float, 0.0),
        FieldDef("due_date_days", float, 30.0),
        FieldDef("owner", str, ""),
        FieldDef("description", str, ""),
    ],
    score_field="risk_score",
    key_field="finding_id",
)

# Backward-compatible re-exports
FindingSeverity = AuditFindingRemediationEngine.FindingSeverity
RemediationStatus = AuditFindingRemediationEngine.RemediationStatus
FindingCategory = AuditFindingRemediationEngine.FindingCategory
AuditFindingRecord = AuditFindingRemediationEngine.Record
AuditFindingAnalysis = AuditFindingRemediationEngine.Analysis
AuditFindingReport = AuditFindingRemediationEngine.Report
