"""Backup Validator Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class GapAnalysisResult(BaseModel):
    """Structured output from LLM-assisted backup gap analysis."""

    summary: str = Field(description="Summary of backup gap analysis")
    critical_gaps: list[str] = Field(
        description="Critical gaps in backup coverage"
    )
    compliance_risks: list[str] = Field(
        description="Compliance risks from backup gaps"
    )
    recommendations: list[str] = Field(
        description="Prioritized recommendations to close gaps"
    )


class RecoveryAnalysisResult(BaseModel):
    """Structured output for recovery test analysis."""

    summary: str = Field(description="Summary of recovery test results")
    rto_assessment: str = Field(
        description="Assessment of Recovery Time Objective adherence"
    )
    rpo_assessment: str = Field(
        description="Assessment of Recovery Point Objective adherence"
    )
    improvements: list[str] = Field(
        description="Improvements to recovery procedures"
    )


class BackupReportResult(BaseModel):
    """Structured output for backup validation report."""

    executive_summary: str = Field(description="Executive summary")
    compliance_status: str = Field(
        description="Compliance status of backup program"
    )
    risk_areas: list[str] = Field(
        description="Areas of risk in backup infrastructure"
    )
    action_items: list[str] = Field(
        description="Action items for infrastructure team"
    )


SYSTEM_GAP_ANALYSIS = (
    "You are a disaster recovery expert analyzing backup coverage gaps.\n"
    "For the backup inventory:\n"
    "1. Identify services without adequate backup coverage\n"
    "2. Assess compliance risks (SOC 2, HIPAA, PCI-DSS requirements)\n"
    "3. Evaluate retention policy adequacy for each service tier\n"
    "4. Recommend specific actions to close backup gaps"
)

SYSTEM_RECOVERY_ANALYSIS = (
    "You are a DR engineer analyzing backup recovery test results.\n"
    "For the recovery tests:\n"
    "1. Assess RTO adherence — are recovery times within SLA?\n"
    "2. Assess RPO adherence — is data loss within acceptable limits?\n"
    "3. Identify bottlenecks in recovery procedures\n"
    "4. Recommend improvements to reduce recovery time and data loss"
)

SYSTEM_REPORT = (
    "You are a backup compliance officer generating a validation report.\n"
    "Generate a comprehensive backup validation report:\n"
    "1. Executive summary of backup health and coverage\n"
    "2. Compliance status against regulatory requirements\n"
    "3. Risk areas requiring immediate attention\n"
    "4. Prioritized action items for the infrastructure team"
)
