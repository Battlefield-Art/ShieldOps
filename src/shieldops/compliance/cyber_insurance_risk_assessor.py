"""CyberInsuranceRiskAssessor — assess cyber insurance risk and coverage requirements."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

CyberInsuranceRiskAssessor = engine(
    "CyberInsuranceRiskAssessor",
    description="Assess cyber insurance risk and coverage requirements.",
    enums={
        "record_type": EnumDef(
            "CyberInsuranceType",
            {
                "CONTROL": "control",
                "POLICY": "policy",
                "REGULATION": "regulation",
                "STANDARD": "standard",
                "FRAMEWORK": "framework",
            },
        ),
        "source": EnumDef(
            "CyberInsuranceSource",
            {
                "AUDIT": "audit",
                "AUTOMATED_SCAN": "automated_scan",
                "MANUAL_REVIEW": "manual_review",
                "CONTINUOUS_MONITOR": "continuous_monitor",
                "THIRD_PARTY": "third_party",
            },
        ),
        "level": EnumDef(
            "CyberInsuranceLevel",
            {
                "COMPLIANT": "compliant",
                "PARTIAL": "partial",
                "NON_COMPLIANT": "non_compliant",
                "NOT_ASSESSED": "not_assessed",
                "EXEMPT": "exempt",
            },
        ),
    },
)

# Backward-compatible re-exports
CyberInsuranceType = CyberInsuranceRiskAssessor.CyberInsuranceType
CyberInsuranceSource = CyberInsuranceRiskAssessor.CyberInsuranceSource
CyberInsuranceLevel = CyberInsuranceRiskAssessor.CyberInsuranceLevel
CyberInsuranceRecord = CyberInsuranceRiskAssessor.Record
CyberInsuranceAnalysis = CyberInsuranceRiskAssessor.Analysis
CyberInsuranceReport = CyberInsuranceRiskAssessor.Report
