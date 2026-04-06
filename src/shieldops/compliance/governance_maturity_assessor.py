"""Governance Maturity Assessor — assess and track governance maturity levels."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

GovernanceMaturityAssessor = engine(
    "GovernanceMaturityAssessor",
    description="Assess governance maturity across domains, track levels, identify maturity...",
    enums={
        "maturity_level": EnumDef(
            "MaturityLevel",
            {
                "OPTIMIZED": "optimized",
                "MANAGED": "managed",
                "DEFINED": "defined",
                "REPEATABLE": "repeatable",
                "INITIAL": "initial",
            },
        ),
        "governance_domain": EnumDef(
            "GovernanceDomain",
            {
                "RISK_MANAGEMENT": "risk_management",
                "POLICY_MANAGEMENT": "policy_management",
                "COMPLIANCE": "compliance",
                "AUDIT": "audit",
                "SECURITY_OPERATIONS": "security_operations",
            },
        ),
        "assessment_frequency": EnumDef(
            "AssessmentFrequency",
            {
                "CONTINUOUS": "continuous",
                "QUARTERLY": "quarterly",
                "SEMI_ANNUAL": "semi_annual",
                "ANNUAL": "annual",
                "AD_HOC": "ad_hoc",
            },
        ),
    },
    score_field="maturity_score",
    key_field="domain_name",
)

# Backward-compatible re-exports
MaturityLevel = GovernanceMaturityAssessor.MaturityLevel
GovernanceDomain = GovernanceMaturityAssessor.GovernanceDomain
AssessmentFrequency = GovernanceMaturityAssessor.AssessmentFrequency
MaturityRecord = GovernanceMaturityAssessor.Record
MaturityAnalysis = GovernanceMaturityAssessor.Analysis
GovernanceMaturityReport = GovernanceMaturityAssessor.Report
