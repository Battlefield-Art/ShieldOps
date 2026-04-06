"""UnifiedComplianceEngine — unified compliance engine."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

UnifiedComplianceEngine = engine(
    "UnifiedComplianceEngine",
    module="operations",  # uses record_item
    description="Unified Compliance Engine.",
    enums={
        "compliance_domain": EnumDef(
            "ComplianceDomain",
            {
                "SECURITY": "security",
                "PRIVACY": "privacy",
                "FINANCIAL": "financial",
                "OPERATIONAL": "operational",
                "REGULATORY": "regulatory",
            },
        ),
        "assessment_type": EnumDef(
            "AssessmentType",
            {
                "AUTOMATED": "automated",
                "MANUAL": "manual",
                "HYBRID": "hybrid",
                "CONTINUOUS": "continuous",
                "PERIODIC": "periodic",
            },
        ),
        "compliance_score": EnumDef(
            "ComplianceScore",
            {
                "EXCELLENT": "excellent",
                "GOOD": "good",
                "FAIR": "fair",
                "POOR": "poor",
                "FAILING": "failing",
            },
        ),
    },
)

# Backward-compatible re-exports
ComplianceDomain = UnifiedComplianceEngine.ComplianceDomain
AssessmentType = UnifiedComplianceEngine.AssessmentType
ComplianceScore = UnifiedComplianceEngine.ComplianceScore
UnifiedComplianceEngineRecord = UnifiedComplianceEngine.Record
UnifiedComplianceEngineAnalysis = UnifiedComplianceEngine.Analysis
UnifiedComplianceEngineReport = UnifiedComplianceEngine.Report
