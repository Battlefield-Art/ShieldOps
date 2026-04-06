"""Third Party Security Scorer — assess and score third-party vendor security."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

ThirdPartySecurityScorer = engine(
    "ThirdPartySecurityScorer",
    description="Assess third-party vendor security posture, track ratings, identify vendor...",
    enums={
        "vendor_tier": EnumDef(
            "VendorTier",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "MINIMAL": "minimal",
            },
        ),
        "assessment_type": EnumDef(
            "AssessmentType",
            {
                "QUESTIONNAIRE": "questionnaire",
                "AUDIT": "audit",
                "CONTINUOUS_MONITORING": "continuous_monitoring",
                "PENETRATION_TEST": "penetration_test",
                "CERTIFICATION": "certification",
            },
        ),
        "security_rating": EnumDef(
            "SecurityRating",
            {
                "EXCELLENT": "excellent",
                "GOOD": "good",
                "ACCEPTABLE": "acceptable",
                "POOR": "poor",
                "CRITICAL": "critical",
            },
        ),
    },
    score_field="vendor_score",
    key_field="vendor_name",
)

# Backward-compatible re-exports
VendorTier = ThirdPartySecurityScorer.VendorTier
AssessmentType = ThirdPartySecurityScorer.AssessmentType
SecurityRating = ThirdPartySecurityScorer.SecurityRating
VendorRecord = ThirdPartySecurityScorer.Record
VendorAnalysis = ThirdPartySecurityScorer.Analysis
VendorSecurityReport = ThirdPartySecurityScorer.Report
