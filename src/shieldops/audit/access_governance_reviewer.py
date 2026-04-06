"""Access Governance Reviewer — review and govern access rights and permissions."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AccessGovernanceReviewer = engine(
    "AccessGovernanceReviewer",
    description="Review access governance, track outcomes, identify access review gaps.",
    enums={
        "review_type": EnumDef(
            "ReviewType",
            {
                "PERIODIC": "periodic",
                "TRIGGERED": "triggered",
                "CERTIFICATION": "certification",
                "PRIVILEGED_ACCESS": "privileged_access",
                "SERVICE_ACCOUNT": "service_account",
            },
        ),
        "review_outcome": EnumDef(
            "ReviewOutcome",
            {
                "APPROVED": "approved",
                "REVOKED": "revoked",
                "MODIFIED": "modified",
                "ESCALATED": "escalated",
                "DEFERRED": "deferred",
            },
        ),
        "access_risk": EnumDef(
            "AccessRisk",
            {
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "MINIMAL": "minimal",
                "NONE": "none",
            },
        ),
    },
    score_field="review_score",
    key_field="review_name",
)

# Backward-compatible re-exports
ReviewType = AccessGovernanceReviewer.ReviewType
ReviewOutcome = AccessGovernanceReviewer.ReviewOutcome
AccessRisk = AccessGovernanceReviewer.AccessRisk
ReviewRecord = AccessGovernanceReviewer.Record
ReviewAnalysis = AccessGovernanceReviewer.Analysis
AccessGovernanceReport = AccessGovernanceReviewer.Report
