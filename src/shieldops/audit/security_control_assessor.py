"""Security Control Assessor — assess effectiveness of security controls."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

SecurityControlAssessor = engine(
    "SecurityControlAssessor",
    description="Assess security control effectiveness, track domains, identify assessment g...",
    enums={
        "control_domain": EnumDef(
            "ControlDomain",
            {
                "ACCESS_MANAGEMENT": "access_management",
                "DATA_SECURITY": "data_security",
                "NETWORK_SECURITY": "network_security",
                "APPLICATION_SECURITY": "application_security",
                "OPERATIONAL_SECURITY": "operational_security",
            },
        ),
        "assessment_result": EnumDef(
            "AssessmentResult",
            {
                "EFFECTIVE": "effective",
                "PARTIALLY_EFFECTIVE": "partially_effective",
                "INEFFECTIVE": "ineffective",
                "NOT_TESTED": "not_tested",
                "NOT_APPLICABLE": "not_applicable",
            },
        ),
        "assessment_method": EnumDef(
            "AssessmentMethod",
            {
                "AUTOMATED": "automated",
                "MANUAL": "manual",
                "HYBRID": "hybrid",
                "CONTINUOUS": "continuous",
                "SAMPLING": "sampling",
            },
        ),
    },
    score_field="effectiveness_score",
    key_field="control_name",
)

# Backward-compatible re-exports
ControlDomain = SecurityControlAssessor.ControlDomain
AssessmentResult = SecurityControlAssessor.AssessmentResult
AssessmentMethod = SecurityControlAssessor.AssessmentMethod
ControlRecord = SecurityControlAssessor.Record
ControlAnalysis = SecurityControlAssessor.Analysis
ControlAssessmentReport = SecurityControlAssessor.Report
