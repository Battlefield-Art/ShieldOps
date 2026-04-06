"""AIActComplianceEngine — EU AI Act compliance tracking and assessment."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AIActComplianceEngine = engine(
    "AIActComplianceEngine",
    description="EU AI Act compliance tracking and assessment.",
    enums={
        "risk_tier": EnumDef(
            "AIActRiskTier",
            {
                "UNACCEPTABLE": "unacceptable",
                "HIGH_RISK": "high_risk",
                "LIMITED_RISK": "limited_risk",
                "MINIMAL_RISK": "minimal_risk",
            },
        ),
        "article": EnumDef(
            "ComplianceArticle",
            {
                "ART6_CLASSIFICATION": "art6_classification",
                "ART9_RISK_MGMT": "art9_risk_mgmt",
                "ART10_DATA_GOVERNANCE": "art10_data_governance",
                "ART13_TRANSPARENCY": "art13_transparency",
                "ART14_HUMAN_OVERSIGHT": "art14_human_oversight",
                "ART15_ACCURACY": "art15_accuracy",
            },
        ),
        "assessment_status": EnumDef(
            "AssessmentStatus",
            {
                "COMPLIANT": "compliant",
                "PARTIAL": "partial",
                "NON_COMPLIANT": "non_compliant",
                "EXEMPT": "exempt",
            },
        ),
    },
    record_fields=[
        FieldDef("evidence_ref", str, ""),
        FieldDef("assessor", str, ""),
    ],
    key_field="system_id",
)

# Backward-compatible re-exports
AIActRiskTier = AIActComplianceEngine.AIActRiskTier
ComplianceArticle = AIActComplianceEngine.ComplianceArticle
AssessmentStatus = AIActComplianceEngine.AssessmentStatus
ComplianceRecord = AIActComplianceEngine.Record
ComplianceAnalysis = AIActComplianceEngine.Analysis
ComplianceReport = AIActComplianceEngine.Report
