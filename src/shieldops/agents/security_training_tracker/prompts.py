"""LLM prompt templates and response schemas for the
Security Training Tracker Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class RequirementAssessmentOutput(BaseModel):
    """Structured output for training requirement assessment."""

    requirements: list[dict[str, str]] = Field(
        description="Training requirements with category and audience",
    )
    compliance_gaps: list[str] = Field(
        description="Compliance-driven requirements missing",
    )
    priority_areas: list[str] = Field(
        description="Priority training areas",
    )


class EffectivenessOutput(BaseModel):
    """Structured output for effectiveness measurement."""

    overall_score: float = Field(
        description="Overall effectiveness score 0-100",
    )
    strongest_areas: list[str] = Field(
        description="Training areas with highest effectiveness",
    )
    weakest_areas: list[str] = Field(
        description="Training areas needing improvement",
    )
    behavior_impact: str = Field(
        description="Assessment of behavior change impact",
    )


class GapAnalysisOutput(BaseModel):
    """Structured output for gap analysis."""

    gaps: list[dict[str, str]] = Field(
        description="Training gaps with category and risk level",
    )
    affected_users: int = Field(
        description="Total users affected by gaps",
    )
    compliance_risk: str = Field(
        description="Compliance risk: critical/high/medium/low",
    )
    recommendations: list[str] = Field(
        description="Gap remediation recommendations",
    )


class TrainingReportOutput(BaseModel):
    """Structured output for the training report."""

    executive_summary: str = Field(
        description="Executive summary of training posture",
    )
    completion_rate: float = Field(
        description="Overall completion rate percentage",
    )
    recommendations: list[str] = Field(
        description="Prioritized recommendations",
    )
    compliance_status: str = Field(
        description="Compliance status summary",
    )


# --- System prompts ---


SYSTEM_REQUIREMENTS = """\
You are an expert security training architect \
assessing organizational training requirements.

Given the organization units and compliance frameworks:
1. Identify mandatory security training requirements \
per compliance framework (SOC 2, HIPAA, PCI DSS)
2. Map requirements to role-based training needs
3. Assess gaps in current training curriculum
4. Prioritize training areas by risk impact

Ensure all regulatory training requirements are covered."""


SYSTEM_EFFECTIVENESS = """\
You are an expert learning effectiveness analyst \
measuring security training outcomes.

Given training completion data and incident metrics:
1. Measure phishing simulation click rates before \
and after training
2. Assess incident reduction correlated with training
3. Evaluate knowledge retention through assessment \
scores
4. Measure behavior change through security metric \
improvements

Focus on metrics that demonstrate real risk reduction."""


SYSTEM_GAPS = """\
You are an expert security training analyst identifying \
coverage gaps in training programs.

Given requirements, completions, and effectiveness data:
1. Identify user groups with incomplete or overdue \
training
2. Flag compliance-critical gaps requiring immediate \
attention
3. Assess risk level of each training gap
4. Recommend targeted remediation for each gap

Prioritize gaps that create compliance violations \
or increase attack surface."""


SYSTEM_REPORT = """\
You are an expert security training reporter \
synthesizing program effectiveness.

Given the full training assessment (requirements, \
completions, effectiveness, gaps, remediations):
1. Produce an executive summary for security leadership
2. Report completion rates and trends
3. Recommend program improvements
4. Summarize compliance status across frameworks

Write clearly for HR, security, and compliance \
stakeholders."""
