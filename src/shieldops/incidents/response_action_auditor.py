"""Response Action Auditor — audit and track all incident response actions."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

ResponseActionAuditor = engine(
    "ResponseActionAuditor",
    description="Audit incident response actions — containment, eradication, recovery, commu...",
    enums={
        "action_type": EnumDef(
            "ActionType",
            {
                "CONTAINMENT": "containment",
                "ERADICATION": "eradication",
                "RECOVERY": "recovery",
                "COMMUNICATION": "communication",
                "APPROVAL": "approval",
            },
        ),
        "action_result": EnumDef(
            "ActionResult",
            {
                "SUCCESS": "success",
                "FAILURE": "failure",
                "PARTIAL": "partial",
                "TIMEOUT": "timeout",
                "CANCELLED": "cancelled",
            },
        ),
        "audit_severity": EnumDef(
            "AuditSeverity",
            {
                "CRITICAL": "critical",
                "MAJOR": "major",
                "MINOR": "minor",
                "INFO": "info",
                "NONE": "none",
            },
        ),
    },
)

# Backward-compatible re-exports
ActionType = ResponseActionAuditor.ActionType
ActionResult = ResponseActionAuditor.ActionResult
AuditSeverity = ResponseActionAuditor.AuditSeverity
ActionAuditRecord = ResponseActionAuditor.Record
ActionAuditAnalysis = ResponseActionAuditor.Analysis
ActionAuditReport = ResponseActionAuditor.Report
