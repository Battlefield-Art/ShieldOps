"""Exception Management Engine — manage policy exceptions and risk acceptances."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

ExceptionManagementEngine = engine(
    "ExceptionManagementEngine",
    description="Manage policy exceptions, risk acceptances, waivers, and exemption lifecycle.",
    enums={
        "exception_type": EnumDef(
            "ExceptionType",
            {
                "RISK_ACCEPTANCE": "risk_acceptance",
                "COMPENSATING_CONTROL": "compensating_control",
                "TEMPORARY_WAIVER": "temporary_waiver",
                "PERMANENT_EXEMPTION": "permanent_exemption",
                "DEFERRED_REMEDIATION": "deferred_remediation",
            },
        ),
        "exception_status": EnumDef(
            "ExceptionStatus",
            {
                "REQUESTED": "requested",
                "APPROVED": "approved",
                "ACTIVE": "active",
                "EXPIRED": "expired",
                "REVOKED": "revoked",
            },
        ),
        "approval_level": EnumDef(
            "ApprovalLevel",
            {
                "CISO": "ciso",
                "SECURITY_LEAD": "security_lead",
                "MANAGER": "manager",
                "AUTOMATED": "automated",
                "COMMITTEE": "committee",
            },
        ),
    },
    score_field="risk_score",
    key_field="exception_name",
)

# Backward-compatible re-exports
ExceptionType = ExceptionManagementEngine.ExceptionType
ExceptionStatus = ExceptionManagementEngine.ExceptionStatus
ApprovalLevel = ExceptionManagementEngine.ApprovalLevel
ExceptionRecord = ExceptionManagementEngine.Record
ExceptionAnalysis = ExceptionManagementEngine.Analysis
ExceptionManagementReport = ExceptionManagementEngine.Report
